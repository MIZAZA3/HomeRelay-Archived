"""Reverse-path recovery without production keys, DB, root, or SSH settings."""
import asyncio,json,pathlib,sys,time,types
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'server'))
import transport_health as t

RESULTS=[]
def check(name,ok):assert ok,name;RESULTS.append(name)

async def run():
    clock=[100.0];m=t.Manager(clock=lambda:clock[0])
    check('unknown status reads allocate no per-client state',m.view('unknown')['status']=='checking' and not m.states)
    check('one failed probe does not restart a tunnel',not m.outcome('a',False) and not m.blocked('a'))
    check('two failed probes do not restart a tunnel',not m.outcome('a',False) and not m.blocked('a'))
    check('success resets consecutive failures',not m.outcome('a',True) and m.view('a')['consecutive_failures']==0)
    m.outcome('a',False);m.outcome('a',False)
    check('three independent failed probes start one quiet period',m.outcome('a',False) and m.view('a')['retry_after']==60)
    check('late successes do not cancel an already started recovery',not m.outcome('a',True) and m.blocked('a'))
    check('another node is not blocked by a failed node',not m.blocked('b'))
    clock[0]+=59
    check('no early reopening before the quiet deadline',m.blocked('a'))
    clock[0]+=1
    check('recovery reopens without changing credentials after 60 seconds',not m.blocked('a'))
    m.outcome('a',True)
    check('a subsequent successful probe restores ready status',m.view('a')['status']=='ready')
    check('public health metadata has no credential or destination field',set(m.view('a'))=={'status','retry_after','consecutive_failures'})

    wire=[]
    async def home(reader,writer):
        try:
            wire.append(await reader.readexactly(3));writer.write(b'\x05\x02');await writer.drain()
            head=await reader.readexactly(2);user=await reader.readexactly(head[1]);size=(await reader.readexactly(1))[0];password=await reader.readexactly(size)
            wire.append((head,user,password));writer.write(b'\x01\x00');await writer.drain()
            wire.append(await reader.read())
        finally:writer.close()
    server=await asyncio.start_server(home,'127.0.0.1',0)
    port=server.sockets[0].getsockname()[1]
    original=t.asyncio.open_connection
    async def redirected(host,p):
        assert (host,p)==('127.0.0.1',22000)
        return await original('127.0.0.1',port)
    t.asyncio.open_connection=redirected
    try:
        await t.exchange(types.SimpleNamespace(derive=lambda label,slot:'fixture-key'),{'slot':0})
        await asyncio.sleep(.01)
        check('real SOCKS health exchange authenticates but sends no application request',wire[0]==b'\x05\x01\x02' and wire[1][1:]==(b'home',b'fixture-key') and wire[2]==b'')
    finally:t.asyncio.open_connection=original;server.close();await server.wait_closed()

    closed=[];c=types.SimpleNamespace(close_node=None)
    async def close_node(nid):closed.append(nid)
    c.close_node=close_node
    async def stall(c,node):await asyncio.sleep(10)
    m=t.Manager(probe=stall);m.TIMEOUT=.015
    for _ in range(3):await m.check(c,{'id':'a','slot':0})
    check('a non-responsive reverse tunnel has a bounded whole-exchange timeout',m.metrics['probe_failed']==3)
    check('failure closes only the affected node and no persistent state is needed',closed==['a'] and m.blocked('a'))
    await m.check(c,{'id':'a','slot':0})
    check('recovery probes are suppressed during the quiet period',m.metrics['probe_failed']==3 and closed==['a'])

    active=[0];peak=[0];calls=[]
    async def bounded(c,node):
        active[0]+=1;peak[0]=max(peak[0],active[0]);calls.append(node['id'])
        try:await asyncio.sleep(.01)
        finally:active[0]-=1
    m=t.Manager(probe=bounded)
    rows=[{'id':str(i),'slot':i,'state':'enabled','seen':time.time()} for i in range(16)]
    m.tick(c,rows);m.tick(c,rows)
    await asyncio.gather(*list(m.jobs.values()));await asyncio.sleep(0)
    check('health exchanges have a separate hard four-probe bound',peak[0]<=4 and len(calls)==16)
    check('repeated ticks cannot enqueue duplicate probes per node',len(set(calls))==16 and not m.jobs)
    before=len(calls);m.tick(c,rows);await asyncio.sleep(.01)
    check('healthy nodes are not polled continuously',len(calls)==before)
    stale=[dict(rows[0],id='stale',seen=time.time()-50),dict(rows[0],id='idle',state='idle'),dict(rows[0],id='rejected',state='rejected')]
    m.tick(c,stale)
    check('offline idle and rejected nodes do not create health connections',not m.jobs)
    print(json.dumps({'transport_health_unit_passed':RESULTS,'count':len(RESULTS)}))

if __name__=='__main__':asyncio.run(run())
