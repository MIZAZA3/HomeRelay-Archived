"""Bounded DNS scheduling, sharing, cancellation and frame-idle regression."""
import asyncio,collections,json,pathlib,socket,struct,sys,threading,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'server'))
import target_policy
from target_policy import Policy,Denied

RESULTS=[]
def check(name,ok):assert ok,name;RESULTS.append(name)

async def run():
    calls=collections.Counter();active=0;peak=0;lock=threading.Lock()
    def resolver(name,*_):
        nonlocal active,peak
        with lock:active+=1;peak=max(peak,active);calls[name]+=1
        try:
            time.sleep(.05)
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',0))]
        finally:
            with lock:active-=1
    p=Policy(resolver=resolver)
    try:
        result=await asyncio.gather(*(p.resolve('burst%d.fixture'%i) for i in range(12)))
        check('12 distinct DNS queries queue successfully instead of rejecting 8',len(result)==12 and set(result)=={'8.8.8.8'})
        check('real DNS worker concurrency remains bounded to four',peak<=4)
        result=await asyncio.gather(*(p.resolve('same.fixture') for _ in range(20)))
        check('20 same-name requests share a single lookup',len(result)==20 and calls['same.fixture']==1)
        first=asyncio.create_task(p.resolve('cancel.fixture'));second=asyncio.create_task(p.resolve('cancel.fixture'))
        await asyncio.sleep(.01);first.cancel()
        await asyncio.gather(first,return_exceptions=True)
        check('one cancelled caller does not cancel a shared lookup',await second=='8.8.8.8' and calls['cancel.fixture']==1)
        result=await asyncio.gather(*(p.resolve('bounded%d.fixture'%i) for i in range(70)),return_exceptions=True)
        check('pending distinct DNS names have a hard 64-job bound',sum(isinstance(x,Denied) for x in result)==6)
        await asyncio.sleep(0)
        check('completed DNS tasks are removed',len(p.pending)==0)
    finally:p.pool.shutdown(wait=True)

    p=Policy(resolver=resolver);p.DNS_TIMEOUT=.01
    try:
        result=await asyncio.gather(*(p.resolve('slow%d.fixture'%i) for i in range(4)),return_exceptions=True)
        check('slow DNS times out without releasing running native worker slots',all(isinstance(x,Denied) for x in result))
        result=await asyncio.gather(*(p.resolve('wait%d.fixture'%i) for i in range(8)),return_exceptions=True)
        check('native executor does not accumulate queued jobs after timeouts',p.pool._work_queue.qsize()==0)
        await asyncio.sleep(.06);p.DNS_TIMEOUT=1
        check('DNS service recovers after timed-out native workers finish',await p.resolve('recovered.fixture')=='8.8.8.8')
    finally:p.pool.shutdown(wait=True)

    p=Policy(resolver=resolver)
    try:
        await p.resolve('scoped.fixture','a')
        await p.resolve('scoped.fixture','b')
        check('validated DNS cache scopes do not leak between nodes',calls['scoped.fixture']==2)
        check('production UDP frame idle budget is 180 seconds',p.UDP_IDLE_TIMEOUT==180)
        original=target_policy.exact
        async def short_exact(reader,size):return await asyncio.wait_for(reader.readexactly(size),.02)
        target_policy.exact=short_exact
        reader=asyncio.StreamReader();job=asyncio.create_task(p.datagram(reader))
        await asyncio.sleep(.05)
        check('idle before first UDP frame byte is not a partial-frame timeout',not job.done())
        frame=b'\x00\x03\xff\x01\x08\x08\x08\x08\x00\x35abc'
        reader.feed_data(frame)
        check('UDP frame works after waiting longer than partial-frame timeout',await job==frame)
        reader=asyncio.StreamReader();reader.feed_data(b'\x00')
        try:await p.datagram(reader);ok=False
        except TimeoutError:ok=True
        check('incomplete UDP frames still have a short timeout',ok)
        target_policy.exact=original
    finally:p.pool.shutdown(wait=True)

    print(json.dumps({'stability_unit_passed':RESULTS,'count':len(RESULTS)}))

if __name__=='__main__':asyncio.run(run())
