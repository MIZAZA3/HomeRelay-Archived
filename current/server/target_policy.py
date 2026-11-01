"""Resolve, validate and PIN proxy targets before the residential tunnel.

Static hostname blacklists alone cannot stop domains resolving to private IPs.
This policy rewrites SOCKS5 CONNECT and GOST UDP-over-TCP destination fields to a
validated numeric IP. No application payload is sent before target validation.
"""
import asyncio
import collections
import concurrent.futures
import ipaddress
import re
import socket
import struct
import threading
import time


class Denied(ConnectionError):
    pass


async def exact(reader, size):
    return await asyncio.wait_for(reader.readexactly(size), 15)


async def raw_address(reader):
    kind = (await exact(reader, 1))[0]
    if kind == 1:
        value = await exact(reader, 4)
    elif kind == 4:
        value = await exact(reader, 16)
    elif kind == 3:
        length = (await exact(reader, 1))[0]
        if not 1 <= length <= 253:
            raise Denied('Invalid target hostname length')
        value = bytes([length]) + await exact(reader, length)
    else:
        raise Denied('Unsupported target address type')
    return bytes([kind]) + value + await exact(reader, 2)


def decode_address(raw):
    if raw[0] == 1:
        host = socket.inet_ntop(socket.AF_INET, raw[1:5])
    elif raw[0] == 4:
        host = socket.inet_ntop(socket.AF_INET6, raw[1:17])
    else:
        host = raw[2:2+raw[1]].decode('utf-8')
    return host, struct.unpack('!H', raw[-2:])[0]


async def address(reader):
    return decode_address(await raw_address(reader))


def frame_parts(frame):
    kind = frame[3]
    length = 7 if kind == 1 else 19 if kind == 4 else 4+frame[4]
    addr = frame[3:3+length]
    return addr, struct.unpack('!H', addr[-2:])[0], frame[3+length:]


async def read_udp_frame(reader, idle_timeout=180, on_start=None):
    first = await asyncio.wait_for(reader.readexactly(1), idle_timeout)
    if on_start:
        on_start()
    header = first + await exact(reader, 2)
    size = struct.unpack('!H', header[:2])[0]
    if not size or header[2] not in (0, 0xff):
        raise Denied('Unsupported empty or fragmented UDP-over-TCP frame')
    addr = await raw_address(reader)
    if not int.from_bytes(addr[-2:], 'big'):
        raise Denied('Invalid target port')
    return header + addr + await exact(reader, size)


def encode(ip, port):
    value = ipaddress.ip_address(ip)
    return bytes([1 if value.version == 4 else 4]) + value.packed + struct.pack('!H', port)


class Policy:
    DNS_TIMEOUT = 8
    MAX_PENDING = 64
    UDP_IDLE_TIMEOUT = 180

    def __init__(self, blocked_ips=(), resolver=None, test_addresses=()):
        self.blocked = set(blocked_ips)
        # Explicit constructor injection is only used by isolated tests. The
        # production constructor never passes a test allowance or fake resolver.
        self.test_addresses = set(test_addresses)
        self.resolver = resolver or socket.getaddrinfo
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='relay-dns')
        self.slots = threading.BoundedSemaphore(4)
        self.workers = asyncio.Semaphore(4)
        self.pending = {}
        self.cache = collections.OrderedDict()
        # Explicit conservative special-use ranges also cover classification
        # differences between system Python versions. In particular preserve
        # the existing full 192.0.0/24 denial after a hostname has been resolved.
        self.transition = [ipaddress.ip_network(n) for n in (
            '192.0.0.0/24', '192.88.99.0/24', '64:ff9b::/96', '64:ff9b:1::/48',
            '2002::/16', '2001::/23', '3fff::/20', '5f00::/16')]

    def safe_ip(self, text):
        ip = ipaddress.ip_address(text)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        value = str(ip)
        if value in self.test_addresses:
            return value
        if not ip.is_global or ip.is_multicast or ip.is_reserved or value in self.blocked or any(ip.version == n.version and ip in n for n in self.transition):
            raise Denied('Non-public destination denied')
        return value

    async def resolve(self, host, scope=None):
        if '%' in host or any(ord(x) <= 32 or ord(x) == 127 for x in host):
            raise Denied('Invalid target address')
        try:
            return self.safe_ip(host)
        except ValueError:
            pass
        try:
            name = host.rstrip('.').encode('idna').decode('ascii').lower()
        except UnicodeError:
            raise Denied('Invalid target hostname') from None
        if not name or len(name) > 253 or not re.fullmatch(r'[a-z0-9_.-]+', name) or name == 'localhost' or name.endswith(('.localhost', '.local')):
            raise Denied('Invalid or local target hostname')
        key = (scope, name)
        now = time.monotonic();cached = self.cache.get(key)
        if cached and cached[0] > now:
            self.cache.move_to_end(key)
            return cached[1]
        task = self.pending.get(key)
        if task is None:
            if len(self.pending) >= self.MAX_PENDING:
                raise Denied('DNS waiting queue full')
            task = asyncio.create_task(self._lookup(name, scope, key))
            self.pending[key] = task
            def done(future):
                if self.pending.get(key) is future:
                    self.pending.pop(key, None)
                if not future.cancelled():
                    future.exception()
            task.add_done_callback(done)
        # One cancelled browser request must not cancel a lookup shared by
        # other requests. Both distinct-name work and executor queues are bounded.
        return await asyncio.shield(task)

    async def _native(self, name, deadline):
        while not self.slots.acquire(False):
            if time.monotonic() >= deadline:
                raise Denied('DNS worker wait timed out')
            await asyncio.sleep(.01)
        def lookup():
            try:
                return self.resolver(name, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
            finally:
                self.slots.release()
        try:
            try:
                future = asyncio.get_running_loop().run_in_executor(self.pool, lookup)
            except Exception:
                self.slots.release()
                raise
            # A timed-out lookup cannot be killed, but it still occupies one of
            # four fixed slots. Consume a later exception without logging target
            # names or growing an unbounded executor queue.
            future.add_done_callback(lambda f: None if f.cancelled() else f.exception())
            result = await asyncio.wait_for(asyncio.shield(future), max(.001, deadline-time.monotonic()))
        except (OSError, TimeoutError):
            raise Denied('Target resolution unavailable') from None
        return [row[4][0] for row in result]

    async def _lookup(self, name, scope, key):
        deadline = time.monotonic() + self.DNS_TIMEOUT
        acquired = False
        try:
            await asyncio.wait_for(self.workers.acquire(), self.DNS_TIMEOUT)
            acquired = True
            addresses = await self._native(name, deadline)
            # Validate ALL returned candidates before selecting one. Preserve
            # resolver preference instead of sorting IP strings lexicographically.
            addresses = list(dict.fromkeys(self.safe_ip(ip) for ip in addresses))
            if not addresses:
                raise Denied('No permitted destination')
            selected = next((ip for ip in addresses if ipaddress.ip_address(ip).version == 4), addresses[0])
            self.cache[key] = (time.monotonic()+30, selected)
            self.cache.move_to_end(key)
            while len(self.cache) > 256:
                self.cache.popitem(last=False)
            return selected
        except TimeoutError:
            raise Denied('Target resolution wait timed out') from None
        finally:
            if acquired:
                self.workers.release()

    async def request(self, reader, scope=None):
        version, command, reserved = await exact(reader, 3)
        if version != 5 or reserved != 0:
            raise Denied('Invalid SOCKS request')
        host, port = await address(reader)
        if command == 1:
            if not port:
                raise Denied('Invalid target port')
            return False, b'\x05\x01\x00' + encode(await self.resolve(host, scope), port)
        # GOST CmdUDPTun=0xf3: the address in this control request is NOT an
        # application target. Each subsequent datagram has its own destination.
        if command == 0xf3 and host in ('0.0.0.0', '::') and port == 0:
            return True, b'\x05\xf3\x00\x01\x00\x00\x00\x00\x00\x00'
        raise Denied('Unsupported SOCKS command')

    async def datagram(self, reader, scope=None, on_start=None):
        # Idle is not a partial packet. Allow the same idle budget as the
        # reverse pump, while still bounding a slow/incomplete frame to 15 sec.
        frame = await read_udp_frame(reader, self.UDP_IDLE_TIMEOUT, on_start)
        addr, port, payload = frame_parts(frame)
        host, _ = decode_address(addr)
        target = await self.resolve(host, scope)
        return frame[:3] + encode(target, port) + payload
