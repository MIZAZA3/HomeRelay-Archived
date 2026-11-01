"""Before/after regression: default source must queue DNS and preserve UDP idle."""
import asyncio, json, pathlib, socket, sys, time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'server'))
from target_policy import Policy, Denied

async def main():
    def resolver(*args):
        time.sleep(.2)
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',0))]
    policy=Policy(resolver=resolver)
    try:
        results=await asyncio.gather(*(policy.resolve('burst-%d.fixture'%i) for i in range(12)),return_exceptions=True)
        report={'synthetic':True,'concurrent_dns':12,
                'dns_success':sum(isinstance(x,str) for x in results),
                'dns_capacity_rejections':sum(isinstance(x,Denied) and 'capacity' in str(x) for x in results)}
        r=asyncio.StreamReader()
        start=time.monotonic()
        try:
            task=asyncio.create_task(policy.datagram(r))
            await asyncio.sleep(16)
            r.feed_data(b'\x00\x03\xff\x01\x08\x08\x08\x08\x00\x35abc')
            await task
            report['udp_idle_timeout']=False
        except TimeoutError:
            report['udp_idle_timeout']=True
            report['udp_idle_seconds']=round(time.monotonic()-start,2)
        print(json.dumps(report))
        assert report['dns_success']==12 and not report['udp_idle_timeout']
    finally:policy.pool.shutdown(wait=True)

if __name__=='__main__':asyncio.run(main())
