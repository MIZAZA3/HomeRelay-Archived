"""Read-only TLS 1.2/1.3 comparison for the launcher URL shown by the user."""
import ipaddress,json,socket,ssl,struct,time

HOST='one.tarenwang.net'
def exact(s,n):
    b=b''
    while len(b)<n:
        q=s.recv(n-len(b))
        if not q:raise EOFError('connection closed')
        b+=q
    return b

results=[]
try:
    ips=list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(HOST,443,socket.AF_INET,socket.SOCK_STREAM)))
    print(json.dumps({'system_dns':ips}),flush=True)
    allowed=[ip for ip in ips if ipaddress.ip_address(ip).is_global and not ipaddress.ip_address(ip).is_reserved and not ipaddress.ip_address(ip).is_multicast]
except OSError as error:allowed=[];print(json.dumps({'dns_error':type(error).__name__}),flush=True)

for mode,version in [('direct','default'),('direct','TLS1.2'),('proxy','default'),('proxy','TLS1.2')]:
    start=time.monotonic();s=None;phase='TCP/SOCKS';r={'via':mode,'requested_tls':version}
    try:
        if mode=='direct':
            if not allowed:raise OSError('no public target IP')
            s=socket.create_connection((allowed[0],443),7)
        else:
            s=socket.create_connection(('127.0.0.1',31980),7);s.settimeout(9)
            s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
            h=HOST.encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(h)])+h+b'\x01\xbb')
            header=exact(s,4);assert header[1]==0
            size=4 if header[3]==1 else 16 if header[3]==4 else exact(s,1)[0];exact(s,size+2)
        s.settimeout(9);phase='TLS-handshake';context=ssl.create_default_context()
        if version=='TLS1.2':context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
        s=context.wrap_socket(s,server_hostname=HOST)
        r['tls']=s.version();r['cipher']=s.cipher()[0];phase='HTTPS-response'
        s.sendall(('HEAD / HTTP/1.0\r\nHost: '+HOST+'\r\nConnection: close\r\n\r\n').encode())
        data=s.recv(1024);r.update(ok=data.startswith(b'HTTP/'),response=data.split(b'\r\n')[0].decode('ascii','replace'))
    except Exception as error:r.update(ok=False,phase=phase,error=type(error).__name__,detail=str(error)[:200])
    finally:
        if s:s.close()
    r['seconds']=round(time.monotonic()-start,3);results.append(r);print(json.dumps(r),flush=True)
print(json.dumps({'results':results}))
