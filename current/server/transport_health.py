"""Authenticate the reverse data path, not merely the HTTPS heartbeat.

Three independent failed health exchanges open a bounded quiet period. No new
forward channels are created during it, allowing SSH keepalives to expire a
half-open session even while public clients keep retrying. No root watchdog,
destination traffic, key rotation, node state mutation, or direct fallback.
"""
import asyncio
import collections
import math
import threading
import time


async def exchange(c, node):
    writer = None
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', 22000+node['slot'])
        writer.write(b'\x05\x01\x02')
        await writer.drain()
        if await reader.readexactly(2) != b'\x05\x02':
            raise ConnectionError('Reverse SOCKS method')
        user = b'home'
        password = c.derive('home', node['slot']).encode('ascii')
        writer.write(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password)
        await writer.drain()
        if await reader.readexactly(2) != b'\x01\x00':
            raise ConnectionError('Reverse SOCKS authentication')
    finally:
        if writer:
            writer.close()


class Manager:
    TIMEOUT = 6
    INTERVAL = 30
    RETRY = 10
    QUIET = 60
    FAILURES = 3

    def __init__(self, clock=time.monotonic, probe=exchange):
        self.clock = clock
        self.probe = probe
        self.lock = threading.RLock()
        self.states = {}
        self.jobs = {}
        self.slots = asyncio.Semaphore(4)
        self.metrics = collections.Counter()

    def _state(self, nid):
        return self.states.setdefault(nid, {'failed': 0, 'until': 0, 'due': 0, 'success': False})

    def remaining(self, nid):
        with self.lock:
            state = self.states.get(nid)
            return max(0, state['until']-self.clock()) if state else 0

    def blocked(self, nid):
        return self.remaining(nid) > 0

    def view(self, nid):
        with self.lock:
            state = self.states.get(nid)
            remaining = self.remaining(nid)
            return {'status': 'recovering' if remaining else 'ready' if state and state['success'] else 'checking',
                    'retry_after': math.ceil(remaining), 'consecutive_failures': state['failed'] if state else 0}

    def outcome(self, nid, success):
        """Only serialized scheduled probes feed the breaker, not client floods."""
        with self.lock:
            now = self.clock()
            state = self._state(nid)
            if state['until'] > now:
                return False
            if success:
                state.update(failed=0, due=now+self.INTERVAL, success=True)
                self.metrics['probe_ok'] += 1
                return False
            state['success'] = False
            state['failed'] += 1
            state['due'] = now+self.RETRY
            self.metrics['probe_failed'] += 1
            if state['failed'] < self.FAILURES:
                return False
            state.update(failed=0, until=now+self.QUIET, due=now+self.QUIET)
            self.metrics['recovery_started'] += 1
            return True

    async def check(self, c, node):
        nid = node['id']
        async with self.slots:
            if self.blocked(nid):
                return
            try:
                # Queue is bounded by registered nodes. Timeout includes the
                # whole greeting + authentication, not a timeout per byte.
                await asyncio.wait_for(self.probe(c, node), self.TIMEOUT)
                success = True
            except (OSError, ConnectionError, TimeoutError, asyncio.IncompleteReadError):
                success = False
            if self.outcome(nid, success):
                # Close only this node's data flows; authorization stays intact.
                await c.close_node(nid)

    def tick(self, c, rows):
        now = self.clock()
        for row in rows:
            if row['state'] != 'enabled' or time.time()-row['seen'] >= 45:
                continue
            nid = row['id']
            with self.lock:
                state = self._state(nid)
                if state['until'] > now or state['due'] > now or nid in self.jobs:
                    continue
                state['due'] = now+self.INTERVAL
            task = asyncio.create_task(self.check(c, dict(row)))
            self.jobs[nid] = task
            def done(future, nid=nid):
                self.jobs.pop(nid, None)
                if not future.cancelled() and future.exception() is not None:
                    self.metrics['probe_internal_error'] += 1
            task.add_done_callback(done)
