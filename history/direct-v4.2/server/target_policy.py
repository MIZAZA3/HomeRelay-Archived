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


async def address(reader):
    kind = (await exact(reader, 1))[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, await exact(reader, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, await exact(reader, 16))
    elif kind == 3:
        length = (await exact(reader, 1))[0]
        if not 1 <= length <= 253:
            raise Denied('Invalid target hostname length')
        host = (await exact(reader, length)).decode('utf-8')
    else:
        raise Denied('Unsupported target address type')
    port = struct.unpack('!H', await exact(reader, 2))[0]
    return host, port


def encode(ip, port):
    value = ipaddress.ip_address(ip)
    return bytes([1 if value.version == 4 else 4]) + value.packed + struct.pack('!H', port)


class Policy:
    def __init__(self, blocked_ips=(), resolver=None, test_addresses=()):
        self.blocked = set(blocked_ips)
        # Explicit constructor injection is only used by isolated tests. The
        # production constructor never passes a test allowance or fake resolver.
        self.test_addresses = set(test_addresses)
        self.resolver = resolver or socket.getaddrinfo
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='relay-dns')
        self.slots = threading.BoundedSemaphore(4)
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

    async def resolve(self, host):
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
        now = time.monotonic();cached = self.cache.get(name)
        if cached and cached[0] > now:
            self.cache.move_to_end(name)
            return cached[1]
        if not self.slots.acquire(False):
            raise Denied('DNS capacity temporarily busy')
        def lookup():
            try:
                return self.resolver(name, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
            finally:
                self.slots.release()
        try:
            future = asyncio.get_running_loop().run_in_executor(self.pool, lookup)
            # A timed-out lookup cannot be killed, but it still occupies one of
            # four fixed slots. Consume a later exception without logging target
            # names or growing an unbounded executor queue.
            future.add_done_callback(lambda f: None if f.cancelled() else f.exception())
            result = await asyncio.wait_for(asyncio.shield(future), 4)
        except (OSError, TimeoutError):
            raise Denied('Target resolution unavailable') from None
        # Reject mixed public/private answers as well; never let a later DNS
        # resolution select a different address. Prefer IPv4 for existing agents.
        addresses = {self.safe_ip(row[4][0]) for row in result}
        if not addresses:
            raise Denied('No permitted destination')
        selected = sorted(addresses, key=lambda x: (ipaddress.ip_address(x).version, x))[0]
        self.cache[name] = (now + 30, selected);self.cache.move_to_end(name)
        while len(self.cache) > 256:
            self.cache.popitem(last=False)
        return selected

    async def request(self, reader):
        version, command, reserved = await exact(reader, 3)
        if version != 5 or reserved != 0:
            raise Denied('Invalid SOCKS request')
        host, port = await address(reader)
        if command == 1:
            if not port:
                raise Denied('Invalid target port')
            return False, b'\x05\x01\x00' + encode(await self.resolve(host), port)
        # GOST CmdUDPTun=0xf3: the address in this control request is NOT an
        # application target. Each subsequent datagram has its own destination.
        if command == 0xf3 and host in ('0.0.0.0', '::') and port == 0:
            return True, b'\x05\xf3\x00\x01\x00\x00\x00\x00\x00\x00'
        raise Denied('Unsupported SOCKS command')

    async def datagram(self, reader):
        header = await exact(reader, 3)
        size = struct.unpack('!H', header[:2])[0]
        # GOST marks UDP-over-stream with FRAG=0xff (not an IP fragment).
        # Accept its flag and the unfragmented 0 value, reject actual fragments.
        if not size or header[2] not in (0, 0xff):
            raise Denied('Unsupported empty or fragmented UDP-over-TCP frame')
        host, port = await address(reader)
        if not port:
            raise Denied('Invalid target port')
        target = await self.resolve(host)
        payload = await exact(reader, size)
        return header + encode(target, port) + payload
