"""Real gate authentication across a simulated reverse-path recovery window."""
import asyncio
import json
from transport_health import Manager,exchange

async def run(c,nodes,check):
    nid=nodes[0];other=nodes[1]
    before=(dict(c.access(nid)),dict(c.LIMITER.config(nid)),c.node(nid)['state'])
    async def authenticate(slot,target):
        r,w=await asyncio.open_connection('127.0.0.1',23000+slot)
        try:
            w.write(b'\x05\x01\x02');await w.drain()
            if await asyncio.wait_for(r.read(2),2)!=b'\x05\x02':return False
            user=('direct%03d'%(slot+1)).encode();pw=c.direct_proxy.gate_password(c.derive,c.node(target),c.access(target)).encode()
            w.write(b'\x01'+bytes([len(user)])+user+bytes([len(pw)])+pw);await w.drain()
            return await asyncio.wait_for(r.readexactly(2),2)==b'\x01\x00'
        except (ConnectionError,asyncio.IncompleteReadError):return False
        finally:w.close()
    check('actual gate is usable before reverse-path recovery',await authenticate(0,nid))
    clock=[100.0]
    async def fail(c,node):raise TimeoutError('fixture dead reverse link')
    manager=Manager(clock=lambda:clock[0],probe=fail)
    previous=c.FLOW_REGISTRY.transport;c.FLOW_REGISTRY.transport=manager
    try:
        for _ in range(3):await manager.check(c,dict(c.node(nid)))
        check('actual gate fails closed throughout transport quiet time',not await authenticate(0,nid))
        check('another actual node gate survives targeted recovery',await authenticate(1,other))
        viewrow=dict(c.node(nid));viewrow.update(tunnel=1,seen=__import__('time').time())
        info=c.public_info(viewrow);agent=c.agent_info(viewrow)
        check('online heartbeat is not advertised as tunnel-ready during recovery',info['online'] and not info['tunnel_ready'] and info['transport_health']['status']=='recovering')
        check('legacy agent response preserves enabled state and its existing SSH parameters',agent['state']=='enabled' and agent['remote_port']==22000 and agent['home_password']==c.derive('home',0))
        clock[0]+=manager.QUIET;manager.probe=exchange
        await manager.check(c,dict(c.node(nid)))
        check('real reverse SOCKS authentication restores healthy runtime state',manager.view(nid)['status']=='ready' and await authenticate(0,nid))
        after=(dict(c.access(nid)),dict(c.LIMITER.config(nid)),c.node(nid)['state'])
        check('recovery never changes node authorization password or speed settings',before==after)
    finally:c.FLOW_REGISTRY.transport=previous
