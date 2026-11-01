"""Actual GOST/standard-SS browser-style concurrency and idle UDP regression."""
import asyncio,socket,time

async def run(c,nodes,connect,roundtrip,check):
    async def keep_seen():
        while True:
            with c.db() as db:db.execute('UPDATE nodes SET seen=?',(time.time(),))
            await asyncio.sleep(5)
    heartbeat=asyncio.create_task(keep_seen())
    try:
        # Only fixture nodes, never production. Release prior test associations.
        for nid in nodes:await c.close_node(nid)
        await asyncio.sleep(.2)
        sockets=await asyncio.gather(*(connect(31140) for _ in range(20)))
        check('20 simultaneous standard SS TCP streams survive beyond old 16-node cap',len(sockets)==20)
        for reader,writer in sockets:
            writer.write(b'parallel-stability');await writer.drain()
        check('all 20 parallel standard SS streams carry data',all(x==b'parallel-stability' for x in await asyncio.gather(*(reader.readexactly(18) for reader,writer in sockets))))
        for reader,writer in sockets:writer.close()
        await asyncio.sleep(.2)
        check('global 64 and per-node 32 connection bounds remain explicit',c.GATE_GLOBAL_LIMIT==64 and c.GATE_NODE_LIMIT==32)

        previous=c.TARGETS
        def slow_resolver(name,*args):
            time.sleep(.1)
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('203.0.113.10',0))]
        c.TARGETS=c.target_policy.Policy(resolver=slow_resolver,test_addresses=['203.0.113.10'])
        try:
            results=await asyncio.gather(*(roundtrip(31140,host='burst%d.fixture'%i) for i in range(12)),return_exceptions=True)
            check('12 distinct DNS requests succeed through real standard SS gate queue',all(value is True for value in results))
        finally:
            c.TARGETS.pool.shutdown(wait=True);c.TARGETS=previous

        # Real standard SS UDP, same source socket and association after >15 sec.
        def idle_udp():
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                udp.settimeout(4);udp.sendto(b'before-idle',('127.0.0.1',31141));first=udp.recv(128)
                time.sleep(17)
                udp.sendto(b'after-idle',('127.0.0.1',31141));second=udp.recv(128)
                return first==b'before-idle' and second==b'after-idle'
        check('same standard SS UDP association works after 17 seconds idle',await asyncio.to_thread(idle_udp))
        check('node passwords remain usable after concurrency and UDP-idle tests',await roundtrip(31140))
    finally:
        heartbeat.cancel();await asyncio.gather(heartbeat,return_exceptions=True)
