"""Completed DNS-session starvation and SQLite handle lifetime, fixture only."""
import asyncio,gc,json,os,pathlib,socket,struct,time

async def run(c,nodes,launch,client_config,waitport,roundtrip,check):
    class DNS(asyncio.DatagramProtocol):
        def connection_made(self,t):self.t=t
        def datagram_received(self,data,addr):
            self.t.sendto(data[:2]+b'\x81\x80'+data[4:],addr)
    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(DNS,local_addr=('203.0.113.10',53))
    target=nodes[0]
    await c.close_node(target);await asyncio.sleep(.2)
    n=c.node(target);cred=c.direct_proxy.credential(c.CFG,c.derive,n,c.access(target))
    cfg=client_config(cred['password'],24443,31300)
    cfg['services'][1]['forwarder']['nodes'][0]['addr']='203.0.113.10:53'
    launch('dns-pressure-client',cfg);await waitport(31300)
    sockets=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(36)]
    def dns_query(index):
        udp=sockets[index%36]
        udp.settimeout(.7);tx=index.to_bytes(2,'big')
        packet=tx+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x01x\x00\x00\x01\x00\x01'
        udp.sendto(packet,('127.0.0.1',31301))
        try:reply=udp.recv(512);return reply[:2]==tx and bool(reply[2]&128)
        except TimeoutError:return False
    results=[]
    for index in range(36):results.append(await asyncio.to_thread(dns_query,index))
    active=c.ACTIVE[target]
    try:tcp=await roundtrip(31300)
    except Exception:tcp=False
    fixed=hasattr(c,'FLOW_REGISTRY')
    finding={'dns_success':sum(results),'dns_queries':36,'active_after_dns':active,'tcp_after_dns':tcp,'fixed_lifecycle':fixed}
    print('DNS_SESSION_PRESSURE',json.dumps(finding))
    if fixed:
        check('36 short-lived DNS sessions do not starve later TCP traffic',all(results) and tcp)
        check('completed DNS sessions are reclaimed instead of increasing the connection cap',c.FLOW_REGISTRY.metrics['reclaimed_dns']>0 and c.GATE_NODE_LIMIT==32 and c.GATE_GLOBAL_LIMIT==64)
        reused=[]
        for index in range(36,72):reused.append(await asyncio.to_thread(dns_query,index))
        check('reclaimed standard SS UDP sessions recreate successfully on the same source sockets',all(reused))
    else:
        check('old completed-DNS capacity starvation reproduced in isolation',sum(results)<36 and not tcp and active>=32)
    for udp in sockets:udp.close()
    await c.close_node(target);await asyncio.sleep(.2);transport.close()
    if fixed:
        async def respond_after_eof(reader,writer):
            data=await reader.read();await asyncio.sleep(.03)
            writer.write(data+b'-reply');await writer.drain();writer.close()
        server=await asyncio.start_server(respond_after_eof,'203.0.113.10',18002)
        try:
            r,w=await asyncio.open_connection('127.0.0.1',23000)
            w.write(b'\x05\x01\x02');await w.drain();assert await r.readexactly(2)==b'\x05\x02'
            u=b'probe001';pw=c.derive('probe',0).encode()
            w.write(b'\x01'+bytes([len(u)])+u+bytes([len(pw)])+pw);await w.drain()
            assert await r.readexactly(2)==b'\x01\x00'
            w.write(b'\x05\x01\x00'+c.target_policy.encode('203.0.113.10',18002));await w.drain()
            response=await r.readexactly(3);await c.target_policy.raw_address(r);assert response==b'\x05\x00\x00'
            w.write(b'half-close');await w.drain();w.write_eof()
            check('TCP upload half-close does not truncate a later downstream response',await asyncio.wait_for(r.read(),3)==b'half-close-reply')
            w.close()
        finally:server.close();await server.wait_closed()
        with c.db() as db:db.execute('CREATE TABLE lifecycle_fixture_tx(value TEXT)')
        try:
            with c.db() as db:
                db.execute('INSERT INTO lifecycle_fixture_tx VALUES("rollback")')
                raise ValueError('fixture rollback')
        except ValueError:pass
        with c.db() as db:count=db.execute('SELECT count(*) FROM lifecycle_fixture_tx').fetchone()[0]
        check('explicit DB close retains exception rollback semantics',count==0)
    def handles():
        count=0
        for path in pathlib.Path('/proc/self/fd').iterdir():
            try:value=str(path.readlink())
            except OSError:continue
            if 'nodes.sqlite3' in value:count+=1
        return count
    gc.collect();before=handles();enabled=gc.isenabled();gc.disable()
    try:
        for _ in range(250):
            with c.db() as db:db.execute('SELECT id FROM nodes LIMIT 1').fetchone()
        growth=handles()-before
    finally:
        if enabled:gc.enable()
        gc.collect()
    print('SQLITE_HANDLE_GROWTH',json.dumps({'iterations':250,'growth_with_gc_disabled':growth,'fixed_lifecycle':fixed}))
    if fixed:check('250 SQLite reads close handles without relying on garbage collection',growth<=3)
    else:check('old SQLite descriptor retention reproduced in isolation',growth>100)
