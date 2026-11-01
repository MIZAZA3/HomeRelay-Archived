"""Real TCP/UDP and timing tests, called only in the isolated fixture namespace."""
import asyncio
import socket
import struct
import time


async def run(c, nodes, api, cookie, csrf, launch, client_config, waitport, connect, check):
    target = nodes[0]

    async def change(up, down, revision=None, token=csrf, extra=None):
        cfg = c.LIMITER.view(target)
        body = {'upload_kib': up, 'download_kib': down,
                'expected_revision': cfg['revision'] if revision is None else revision}
        body.update(extra or {})
        return await asyncio.to_thread(api, 'POST', '/api/nodes/' + target + '/limits', body, cookie, token)

    revision = c.LIMITER.view(target)['revision']
    code, _, _ = await change(8, 16, token='')
    check('limits API rejects missing CSRF', code == 403 and c.LIMITER.view(target)['revision'] == revision)
    code, _, _ = await asyncio.to_thread(api, 'POST', '/api/nodes/' + target + '/limits',
                                        {'upload_kib': 8, 'download_kib': 16, 'expected_revision': revision})
    check('limits API rejects anonymous writes', code == 401)
    for value in [-1, 257, True, 1.5, '8', None]:
        code, _, _ = await change(value, 16)
        check('limits API rejects invalid value ' + repr(value), code == 400 and c.LIMITER.view(target)['revision'] == revision)
    code, _, _ = await change(8, 16, extra={'total_rate_kib': 99999})
    check('limits API cannot mass-assign the global cap', code == 400)
    code, _, _ = await change(8, 16, revision=True)
    check('limits API rejects boolean revision', code == 400)
    access_before = dict(c.access(target))
    process_before = c.ENGINE.process.pid
    code, result, _ = await change(8, 16)
    check('independent upload/download limits saved and applied', code == 200 and result['limits']['effective_upload_kib'] == 8 and result['limits']['effective_download_kib'] == 16)
    code, _, _ = await change(1, 1, revision=revision)
    check('stale limits settings cannot overwrite newer limits', code == 409)
    check('speed update does not rotate credentials or restart GOST', dict(c.access(target)) == access_before and c.ENGINE.process.pid == process_before)

    for slot, local in [(0, 31140), (1, 31150)]:
        n = c.node(nodes[slot]);cred = c.direct_proxy.credential(c.CFG, c.derive, n, c.access(n['id']))
        client=client_config(cred['password'], 24443 + slot, local)
        launch('speed-client-' + str(slot), client)
        await waitport(local)
    def small_udp():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.settimeout(4);udp.sendto(b'speed-preflight',('127.0.0.1',31141));return udp.recv(256)==b'speed-preflight'
    check('new current credential UDP works before timed speed tests',await asyncio.to_thread(small_udp))

    async def transfer_server(reader, writer):
        try:
            mode, size = (await reader.readline()).decode().strip().split(':')
            size = int(size)
            if not 0 < size <= 1024 * 1024:
                return
            if mode == 'u':
                received = 0
                while received < size:
                    block = await reader.read(min(16384, size - received))
                    if not block:
                        return
                    received += len(block)
                writer.write(struct.pack('!I', received));await writer.drain()
            elif mode == 'd':
                writer.write(b'x' * size);await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(transfer_server, '203.0.113.10', 18002)
    async def fixture_heartbeat():
        while True:
            with c.db() as db:
                for nid in nodes:db.execute('UPDATE nodes SET seen=? WHERE id=?',(time.time(),nid))
            await asyncio.sleep(3)
    heartbeat=asyncio.create_task(fixture_heartbeat())

    async def transfer(mode, size, local=31140):
        reader, writer = await connect(local, '203.0.113.10', 18002)
        start = time.monotonic()
        try:
            writer.write(f'{mode}:{size}\n'.encode())
            if mode == 'u':
                writer.write(b'x' * size)
            await writer.drain()
            if mode == 'u':
                assert struct.unpack('!I', await asyncio.wait_for(reader.readexactly(4), 25))[0] == size
            else:
                data = await asyncio.wait_for(reader.readexactly(size), 25)
                assert len(data) == size
            return time.monotonic() - start
        finally:
            writer.close()

    try:
        upload_seconds = await transfer('u', 32 * 1024)
        print('TIMING upload',round(upload_seconds,3),flush=True)
        check('real SS upload obeys 8 KiB/s node cap', upload_seconds >= 3.4)
        download_seconds = await transfer('d', 32 * 1024)
        print('TIMING download',round(download_seconds,3),flush=True)
        check('real SS download independently obeys 16 KiB/s cap', download_seconds >= 1.7)
        start = time.monotonic()
        await asyncio.gather(transfer('u', 16 * 1024), transfer('u', 16 * 1024))
        shared_seconds = time.monotonic() - start
        print('TIMING parallel',round(shared_seconds,3),flush=True)
        check('parallel TCP connections cannot multiply the node quota', shared_seconds >= 3.4)
        fast_seconds = await transfer('d', 32 * 1024, 31150)
        check('node-specific slow limit does not leak into another node', fast_seconds < 1.5)

        await change(8, 8)
        start = time.monotonic();pending = asyncio.create_task(transfer('d', 128 * 1024))
        await asyncio.sleep(.4)
        check('existing slow download is still active before hot update', not pending.done())
        code, _, _ = await change(8, 128)
        await pending
        check('raising limit takes effect on the existing stream without reconnect', code == 200 and time.monotonic() - start < 4)
        start = time.monotonic();pending = asyncio.create_task(transfer('d', 64 * 1024))
        await asyncio.sleep(.1)
        await change(8, 8)
        await pending
        check('lowering limit constrains an existing stream without a stale-rate burst', time.monotonic() - start >= 4.5)
        print('TIMING lowered',round(time.monotonic()-start,3),flush=True)

        # A GOST SSU client sends actual encrypted UDP, sharing the very same gate.
        await change(8, 16)
        check('UDP remains usable after TCP-only and hot-rate updates',await asyncio.to_thread(small_udp))
        def udp_batch():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(12)
                for index in range(16):
                    udp.sendto(b'u' * 1024, ('127.0.0.1', 31141))
                    try:response=udp.recv(2048)
                    except TimeoutError:
                        raise RuntimeError('UDP batch timeout at packet '+str(index)) from None
                    assert response == b'u' * 1024
        start = time.monotonic()
        await asyncio.gather(transfer('u', 16 * 1024), asyncio.to_thread(udp_batch))
        mixed_seconds = time.monotonic() - start
        check('TCP and standard SS UDP share one aggregate upload quota', mixed_seconds >= 3.4)

        code, inherited, _ = await change(0, 0)
        check('zero means inherit 256 KiB/s, never unlimited', code == 200 and inherited['limits']['effective_upload_kib'] == 256 and c.LIMITER.pair(target)['upload'].rate == 256 * 1024)
        start = time.monotonic()
        await asyncio.gather(transfer('d', 128 * 1024), transfer('d', 128 * 1024, 31150))
        aggregate_seconds = time.monotonic() - start
        check('multiple inherited nodes remain below shared global cap', aggregate_seconds >= .8)
        check('limits remain independent of node password revisions', dict(c.access(target)) == access_before)
        print('SPEED_MEASUREMENTS', {'upload_seconds': round(upload_seconds, 3), 'download_seconds': round(download_seconds, 3),
                                     'parallel_seconds': round(shared_seconds, 3), 'other_node_seconds': round(fast_seconds, 3),
                                     'mixed_tcp_udp_seconds': round(mixed_seconds, 3), 'global_seconds': round(aggregate_seconds, 3)})
    finally:
        heartbeat.cancel();await asyncio.gather(heartbeat,return_exceptions=True)
        server.close();await server.wait_closed()
