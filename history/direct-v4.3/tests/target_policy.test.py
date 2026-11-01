"""Policy unit tests; only synthetic DNS answers, no network lookups."""
import asyncio,ipaddress,pathlib,socket,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'server'))
from target_policy import Policy,Denied

async def run():
    mapping={'public.fixture':['8.8.8.8'],'private.fixture':['127.0.0.1'],
             'mixed.fixture':['8.8.8.8','10.0.0.1'],'pin.fixture':['8.8.4.4']}
    def resolver(host,*_):return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,0)) for ip in mapping[host]]
    p=Policy(blocked_ips=['203.0.113.20'],resolver=resolver)
    try:
        for value in ['127.0.0.1','10.0.0.1','169.254.169.254','100.100.100.200','203.0.113.20','224.0.0.1','ff02::1','::1','::ffff:127.0.0.1','64:ff9b::7f00:1','fe80::1%eth0','192.0.0.8','192.88.99.1','2001:20::1','3fff::1','5f00::1','localhost','x.local','private.fixture','mixed.fixture']:
            try:await p.resolve(value)
            except (Denied,ValueError):continue
            raise AssertionError('Unsafe target accepted: '+value)
        assert await p.resolve('public.fixture')=='8.8.8.8'
        assert await p.resolve('pin.fixture')=='8.8.4.4';mapping['pin.fixture']=['127.0.0.1']
        assert await p.resolve('pin.fixture')=='8.8.4.4' # still pinned, no second lookup
        p.cache.clear()
        try:await p.resolve('pin.fixture');raise AssertionError('rebound private answer accepted')
        except Denied:pass
        reader=asyncio.StreamReader();name=b'public.fixture';reader.feed_data(b'\x05\x01\x00\x03'+bytes([len(name)])+name+b'\x01\xbb')
        udp,request=await p.request(reader);assert not udp and request==b'\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb'
        reader=asyncio.StreamReader();reader.feed_data(b'\x00\x03\x00\x03'+bytes([len(name)])+name+b'\x00\x35abc')
        datagram=await p.datagram(reader);assert datagram==b'\x00\x03\x00\x01\x08\x08\x08\x08\x00\x35abc'
        reader=asyncio.StreamReader();reader.feed_data(b'\x00\x03\xff\x03'+bytes([len(name)])+name+b'\x00\x35abc')
        assert await p.datagram(reader)==b'\x00\x03\xff\x01\x08\x08\x08\x08\x00\x35abc'
        print('target-policy synthetic tests passed (private/mixed/rebinding/CONNECT/UDP pinning)')
    finally:p.pool.shutdown(wait=True)

if __name__=='__main__':asyncio.run(run())
