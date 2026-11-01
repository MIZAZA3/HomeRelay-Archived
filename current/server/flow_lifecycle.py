"""Bounded gate lifecycle. Only completed DNS-only UDP flows are reclaimable.

No destination/payload logging. DNS transaction IDs exist only in bounded RAM
sets until a reply is forwarded. TCP half-close and non-DNS UDP are preserved.
"""
import asyncio
import collections
import hmac
import json
import os
import pathlib
import struct
import time

import target_policy
import transport_health


class Flow:
    def __init__(self, nid, writer):
        self.nid = nid
        self.writer = writer
        self.peer = None
        self.udp = None
        self.dns_only = True
        self.dns_reason = 'unseen'
        self.up_packets = 0
        self.down_packets = 0
        self.created = time.monotonic()
        self.stage = 'opening'
        self.pending = set()
        self.completed = False
        self.busy = 0
        self.updated = time.monotonic()
        self.retiring = False
        self.done = asyncio.Event()

    def dns(self, frame, response=False):
        """Track headers only; never decode/store question names or answers."""
        self.updated = time.monotonic()
        if response:self.down_packets += 1
        else:self.up_packets += 1
        if not self.dns_only:
            return
        addr, port, payload = target_policy.frame_parts(frame)
        if port != 53 or len(payload) < 12:
            self.dns_only = False
            self.dns_reason = 'non_dns_port' if port != 53 else 'short_dns'
        else:
            tx, flags, questions = struct.unpack('!HHH', payload[:6])
            if bool(flags & 0x8000) != response or flags & 0x7800 or questions != 1:
                self.dns_only = False
                self.dns_reason = 'dns_header'
            else:
                key = (addr, tx)
                if response:
                    if key not in self.pending:
                        self.dns_only = False
                        self.dns_reason = 'unmatched_dns_response'
                    else:
                        self.pending.remove(key)
                        self.completed = True
                        self.dns_reason = 'matched_dns'
                else:
                    self.pending.add(key)
                    self.dns_reason = 'pending_dns'
                    if len(self.pending) > 64:
                        self.dns_only = False
                        self.dns_reason = 'dns_pending_bound'
        if not self.dns_only:
            self.pending.clear()

    def reclaimable(self):
        return (self.udp is True and self.dns_only and self.completed
                and not self.pending and not self.busy and not self.retiring)


class Registry:
    def __init__(self):
        self.flows = set()
        self.metrics = collections.Counter()
        self.last_snapshot = 0
        self.transport = transport_health.Manager()

    async def admit(self, c, nid, writer):
        # No semaphore/waiter queue grows beyond the bounded active-flow set.
        # Two bounded reclaim attempts, THREE capacity checks: an intervening
        # arrival can win the first slot, but the last released slot must still
        # be checked before deciding rejection.
        for attempt in range(3):
            node_full = c.ACTIVE[nid] >= c.GATE_NODE_LIMIT
            global_full = c.ACTIVE['all'] >= c.GATE_GLOBAL_LIMIT
            if not node_full and not global_full:
                flow = Flow(nid, writer)
                self.flows.add(flow)
                c.ACTIVE['all'] += 1
                c.ACTIVE[nid] += 1
                c.LIVE[nid].add(writer)
                self.metrics['accepted'] += 1
                return flow
            if attempt == 2:
                break
            candidates = [f for f in self.flows if f.reclaimable() and (not node_full or f.nid == nid)]
            candidates.sort(key=lambda f: (f.nid != nid, f.updated))
            if not candidates:
                break
            victim = candidates[0]
            victim.retiring = True
            victim.writer.close()
            if victim.peer:
                victim.peer.close()
            self.metrics['reclaimed_dns'] += 1
            try:
                await asyncio.wait_for(victim.done.wait(), 1)
            except TimeoutError:
                break
            # Only the old handler's finally may decrement counters. Recheck
            # capacity atomically after awaiting; concurrent arrivals may win.
        key = 'rejected_node_capacity' if c.ACTIVE[nid] >= c.GATE_NODE_LIMIT else 'rejected_global_capacity'
        self.metrics[key] += 1
        return None

    def release(self, c, flow):
        self.flows.discard(flow)
        c.LIVE[flow.nid].discard(flow.writer)
        c.LIVE[flow.nid].discard(flow.peer)
        c.ACTIVE['all'] -= 1
        c.ACTIVE[flow.nid] -= 1
        flow.pending.clear()
        flow.done.set()
        self.metrics['closed'] += 1

    def snapshot(self, c):
        now = time.monotonic()
        if now - self.last_snapshot < 6:
            return
        self.last_snapshot = now
        try:
            types = collections.Counter('udp' if f.udp else 'tcp' if f.udp is False else 'negotiating' for f in self.flows)
            result = {'time': time.time(), 'metrics': dict(self.metrics), 'active': dict(types),
                      'active_total': len(self.flows), 'completed_dns': sum(f.reclaimable() for f in self.flows),
                      'node_limit': c.GATE_NODE_LIMIT, 'global_limit': c.GATE_GLOBAL_LIMIT,
                      'open_fds': len(list(pathlib.Path('/proc/self/fd').iterdir()))}
            # Diagnostic headers/counters only: no addresses, IDs or payloads.
            result['udp_states'] = [
                {'kind': f.dns_reason, 'stage': f.stage, 'pending': len(f.pending),
                 'age_seconds': round(now-f.created,1), 'idle_seconds': round(now-f.updated,1),
                 'busy': f.busy, 'up_packets': f.up_packets, 'down_packets': f.down_packets}
                for f in self.flows if f.udp]
            result['transport_metrics'] = dict(self.transport.metrics)
            result['recovering_nodes'] = sum(self.transport.blocked(nid) for nid in self.transport.states)
            tmp = c.STATE/'diagnostics.json.tmp'
            # Private state directory is 0700. Explicit mode also handles umask.
            fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(result, stream)
            os.chmod(tmp, 0o600)
            tmp.replace(c.STATE/'diagnostics.json')
        except OSError:
            self.metrics['snapshot_failed'] += 1


async def gate(c, reader, writer, slot):
    flow = None
    peer = None
    registry = c.FLOW_REGISTRY
    stage = 'negotiation'

    async def exact(r, n):
        return await asyncio.wait_for(r.readexactly(n), 8)

    def permitted(n, user, password):
        if not n or n['state'] != 'enabled' or time.time()-n['seen'] > 45 or registry.transport.blocked(n['id']):
            return False
        if user == f'probe{slot+1:03}':
            return hmac.compare_digest(password, c.derive('probe', slot))
        a = c.access(n['id'])
        return bool(user == f'direct{slot+1:03}' and a and a['mode'] == 'password'
                    and slot in c.CFG.get('direct_open_slots', [])
                    and hmac.compare_digest(password, c.direct_proxy.gate_password(c.derive, n, a)))

    try:
        with c.db() as db:
            n = db.execute('SELECT * FROM nodes WHERE slot=?', (slot,)).fetchone()
        if not n or n['state'] != 'enabled' or time.time()-n['seen'] > 45:
            registry.metrics['rejected_offline_state'] += 1
            return
        nid = n['id']
        if registry.transport.blocked(nid):
            registry.metrics['rejected_transport_recovery'] += 1
            return
        flow = await registry.admit(c, nid, writer)
        if flow is None:
            return
        ver, count = await exact(reader, 2)
        if ver != 5 or not 1 <= count <= 8:
            return
        if 2 not in await exact(reader, count):
            return
        writer.write(b'\x05\x02')
        await writer.drain()
        ver, length = await exact(reader, 2)
        if ver != 1 or not length:
            return
        user = (await exact(reader, length)).decode('ascii')
        length = (await exact(reader, 1))[0]
        password = (await exact(reader, length)).decode('ascii')
        if not permitted(c.node(nid), user, password):
            registry.metrics['rejected_auth'] += 1
            return
        stage = 'upstream_connect'
        r2, peer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', 22000+slot), 5)
        flow.peer = peer
        c.LIVE[nid].add(peer)
        stage = 'upstream_auth'
        peer.write(b'\x05\x01\x02')
        await peer.drain()
        if await exact(r2, 2) != b'\x05\x02':
            raise ConnectionError('Upstream method')
        home = b'home'
        pw = c.derive('home', slot).encode()
        peer.write(b'\x01'+bytes([len(home)])+home+bytes([len(pw)])+pw)
        await peer.drain()
        if await exact(r2, 2) != b'\x01\x00' or not permitted(c.node(nid), user, password):
            raise ConnectionError('Upstream auth')
        writer.write(b'\x01\x00')
        await writer.drain()
        stage = 'target_policy'
        flow.udp, request = await c.TARGETS.request(reader, nid)
        allowed = lambda: permitted(c.node(nid), user, password)
        await c.LIMITER.write(peer, request, nid, 'upload', allowed)
        stage = 'upstream_reply'
        reply = await exact(r2, 3)
        if reply[0] != 5 or reply[2] != 0:
            raise ConnectionError('Upstream reply')
        # The SOCKS control reply is NOT a UDP frame. Forward it separately.
        reply += await target_policy.raw_address(r2)
        await c.LIMITER.write(writer, reply, nid, 'download', allowed)
        if reply[1] != 0:
            registry.metrics['upstream_target_rejected'] += 1
            return
        stage = 'transfer'
        flow.stage = 'transfer'

        async def pump(r, w, direction):
            while True:
                started = False
                def start_packet():
                    nonlocal started
                    started = True
                    flow.busy += 1
                try:
                    if flow.udp:
                        if direction == 'upload':
                            b = await c.TARGETS.datagram(r, nid, start_packet)
                        else:
                            b = await target_policy.read_udp_frame(r, c.TARGETS.UDP_IDLE_TIMEOUT, start_packet)
                    else:
                        b = await asyncio.wait_for(r.read(16384), 180)
                    if not b or not allowed():
                        break
                    if flow.udp and direction == 'upload':
                        flow.dns(b)
                    await c.LIMITER.write(w, b, nid, direction, allowed)
                    if flow.udp and direction == 'download':
                        # Only reclaim after the entire response has drained.
                        flow.dns(b, response=True)
                finally:
                    if started:
                        flow.busy -= 1
                flow.updated = time.monotonic()
            # Preserve real TCP half-close: uploads may end before a response.
            try:
                w.write_eof()
            except (OSError, RuntimeError, NotImplementedError):
                pass

        jobs = [asyncio.create_task(pump(reader, peer, 'upload')),
                asyncio.create_task(pump(r2, writer, 'download'))]
        try:
            await asyncio.gather(*jobs)
        finally:
            for job in jobs:
                job.cancel()
            await asyncio.gather(*jobs, return_exceptions=True)
    except target_policy.Denied:
        registry.metrics['policy_denied'] += 1
    except TimeoutError:
        registry.metrics[stage+'_timeout'] += 1
    except asyncio.IncompleteReadError:
        registry.metrics[stage+'_eof'] += 1
    except (ConnectionError, OSError, ValueError):
        registry.metrics[stage+'_closed'] += 1
    except Exception:
        registry.metrics['unexpected_error'] += 1
    finally:
        writer.close()
        if peer:
            peer.close()
        if flow:
            registry.release(c, flow)
