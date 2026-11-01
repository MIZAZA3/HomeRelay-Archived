"""Actual SS TCP and authenticated GOST UDP-tunnel target-policy regression."""
import asyncio
import contextlib
import socket
import struct


async def run(c, roundtrip, blocked, check):
    check('standard SS TCP domain is resolved and pinned before friend tunnel', await roundtrip(host='public.fixture'))
    check('standard SS TCP private DNS answer is denied', await blocked(host='private.fixture'))
    check('standard SS TCP mixed public/private DNS answers are denied', await blocked(host='mixed.fixture'))
    check('standard SS TCP public answer stays pinned across DNS rebinding', await roundtrip(host='pin.fixture'))
    old_resolver = c.TARGETS.resolver
    def rebound(host,*args):
        if host=='pin.fixture':return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',0))]
        return old_resolver(host,*args)
    c.TARGETS.resolver=rebound
    check('cached pinned numeric target cannot re-resolve at friend side',await roundtrip(host='pin.fixture'))
    c.TARGETS.cache.pop('pin.fixture',None)
    check('expired DNS pin rejects a subsequently private answer',await blocked(host='pin.fixture'))
    c.TARGETS.resolver=old_resolver

    # Exercise the exact UDP-over-TCP path used after standard SS UDP is decoded
    # by GOST. Only fixture node's derived internal credential is used.
    async def udp_tunnel():
        r,w=await asyncio.open_connection('127.0.0.1',23000)
        w.write(b'\x05\x01\x02');await w.drain();assert await r.readexactly(2)==b'\x05\x02'
        with c.db() as db:n=db.execute('SELECT * FROM nodes WHERE slot=0').fetchone()
        a=c.access(n['id']);user=b'direct001';pw=c.direct_proxy.gate_password(c.derive,n,a).encode()
        w.write(b'\x01'+bytes([len(user)])+user+bytes([len(pw)])+pw);await w.drain()
        assert await r.readexactly(2)==b'\x01\x00'
        w.write(b'\x05\xf3\x00\x01\x00\x00\x00\x00\x00\x00');await w.drain()
        h=await r.readexactly(4);assert h[1]==0
        await r.readexactly((4 if h[3]==1 else 16)+2)
        return r,w

    def frame(host,port,payload=b'policy-udp'):
        b=host.encode()
        return struct.pack('!H',len(payload))+b'\x00\x03'+bytes([len(b)])+b+struct.pack('!H',port)+payload

    r,w=await udp_tunnel()
    try:
        w.write(frame('public.fixture',18001));await w.drain()
        header=await asyncio.wait_for(r.readexactly(4),3)
        size=struct.unpack('!H',header[:2])[0]
        await r.readexactly((4 if header[3]==1 else 16)+2)
        check('GOST UDP-over-TCP domain is resolved and pinned before friend tunnel',await r.readexactly(size)==b'policy-udp')
    finally:w.close()
    for host,label in [('private.fixture','private DNS'),('mixed.fixture','mixed DNS')]:
        r,w=await udp_tunnel()
        try:
            w.write(frame(host,18001));await w.drain()
            try:result=await asyncio.wait_for(r.read(1),3)
            except (ConnectionError,TimeoutError):result=b''
            check('GOST UDP-over-TCP '+label+' target is denied',result==b'')
        finally:w.close()
