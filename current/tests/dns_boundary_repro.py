"""Reproduce the old guard gap on a private marker in an isolated netns only."""
import asyncio,json

async def run(launch,waitport,connect,check):
    hits=[]
    async def marker(reader,writer):
        hits.append(True);writer.write(b'isolated-private-marker');await writer.drain();writer.close()
    server=await asyncio.start_server(marker,'127.0.0.1',18003)
    launch('dns-boundary-model',{'log':{'level':'fatal'},'services':[{
        'name':'old-boundary','addr':'127.0.0.1:31200','handler':{'type':'socks5','metadata':{'notls':True}},
        'listener':{'type':'tcp'},'bypasses':['private'],'hosts':'fixture-dns'}],
        'bypasses':[{'name':'private','matchers':['127.0.0.0/8','10.0.0.0/8','169.254.0.0/16']}],
        'hosts':[{'name':'fixture-dns','mappings':[{'ip':'127.0.0.1','hostname':'dns-boundary.fixture'}]}]})
    await waitport(31200)
    try:
        try:r,w=await connect(31200,'127.0.0.1',18003);w.close();literal_blocked=False
        except Exception:literal_blocked=True
        try:
            r,w=await connect(31200,'dns-boundary.fixture',18003)
            data=await asyncio.wait_for(r.read(64),3);w.close();domain_reached=data==b'isolated-private-marker'
        except Exception:domain_reached=False
        print('OLD_DNS_BOUNDARY_FINDING',json.dumps({'literal_private_blocked':literal_blocked,'domain_resolving_to_private_reached_marker':domain_reached,'production_lan_probed':False}))
        check('old pre-resolution blacklist gap reproduced only against isolated marker',literal_blocked and domain_reached)
    finally:server.close();await server.wait_closed()
