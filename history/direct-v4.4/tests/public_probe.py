"""Protocol-level test via a dedicated localhost SS client, never system proxy/TUN."""
import ipaddress,json,re,socket,ssl,struct,sys
PORT=int(sys.argv[1]) if len(sys.argv)>1 else 31980
def recv(s,n):
    b=b''
    while len(b)<n:
        q=s.recv(n-len(b))
        if not q:raise ConnectionError('proxy closed')
        b+=q
    return b
def socks(cmd,host,port):
    s=socket.create_connection(('127.0.0.1',PORT),timeout=12);s.settimeout(12)
    s.sendall(b'\x05\x01\x00');assert recv(s,2)==b'\x05\x00'
    h=host.encode();s.sendall(bytes([5,cmd,0,3,len(h)])+h+struct.pack('!H',port))
    r=recv(s,4)
    if r[1]!=0:s.close();raise ConnectionError('proxy rejected target')
    if r[3]==1:ip=socket.inet_ntoa(recv(s,4))
    elif r[3]==4:ip=socket.inet_ntop(socket.AF_INET6,recv(s,16))
    else:ip=recv(s,recv(s,1)[0]).decode()
    port=int.from_bytes(recv(s,2),'big')
    return s,('127.0.0.1' if ip in ('0.0.0.0','::') else ip,port)
result={'client':'independent standard Shadowsocks client','tcp':False,'udp':False}
for host in ['myip.ipip.net','api.ipify.org']:
    try:
        s,_=socks(1,host,443)
        with ssl.create_default_context().wrap_socket(s,server_hostname=host) as t:
            t.sendall(f'GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode());b=b''
            while len(b)<32768:
                q=t.recv(2048)
                if not q:break
                b+=q
        header,body=b.split(b'\r\n\r\n',1);assert b' 200 ' in header.split(b'\r\n')[0]
        m=re.search(rb'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',body);assert m
        result['exitIPv4']=str(ipaddress.ip_address(m[0].decode()));result['tcp']=True;break
    except Exception as e:result['tcp_error']=type(e).__name__
try:
    s,bound=socks(3,'0.0.0.0',0)
    with s,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
        u.settimeout(10);q=bytes.fromhex('5a7101000001000000000000')+b'\x07example\x03com\x00\x00\x01\x00\x01'
        u.sendto(bytes.fromhex('00000001df0505050035')+q,bound);a=u.recv(2048)
        off=10 if a[3]==1 else 22 if a[3]==4 else 7+a[4]
        assert a[off:off+2]==b'\x5a\x71' and a[off+2]&128 and a[off+3]&15==0
        result['udp']=True
except Exception as e:result['udp_error']=type(e).__name__
print(json.dumps(result))
if not result['tcp']:sys.exit(1)
