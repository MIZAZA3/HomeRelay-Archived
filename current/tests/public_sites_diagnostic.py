"""Small TLS/HTTP checks via existing localhost test SS, no system proxy/TUN."""
import json,socket,ssl,struct,time

def exact(s,size):
    b=b''
    while len(b)<size:
        x=s.recv(size-len(b))
        if not x:raise EOFError('upstream closed')
        b+=x
    return b

results=[]
for host in ['ip77.net','4.ipw.cn','myip.ipip.net','api.ipify.org']*2:
    start=time.monotonic();s=None;phase='socks-negotiation'
    r={'host':host}
    try:
        s=socket.create_connection(('127.0.0.1',31980),10);s.settimeout(12)
        s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
        b=host.encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(b)])+b+struct.pack('!H',443))
        h=exact(s,4);assert h[1]==0
        n=4 if h[3]==1 else 16 if h[3]==4 else exact(s,1)[0];exact(s,n+2)
        phase='TLS-handshake'
        s=ssl.create_default_context().wrap_socket(s,server_hostname=host)
        phase='HTTPS-response'
        s.sendall(('GET / HTTP/1.0\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
        data=b''
        while b'\r\n' not in data and len(data)<4096:
            q=s.recv(1024)
            if not q:break
            data+=q
        r.update(tls=True,response=data.split(b'\r\n',1)[0].decode('ascii','replace'),ok=data.startswith(b'HTTP/'))
    except Exception as error:r.update(ok=False,phase=phase,error=type(error).__name__)
    finally:
        if s:s.close()
    r['seconds']=round(time.monotonic()-start,3);results.append(r)
    print(json.dumps(r),flush=True)
print(json.dumps({'results':results,'success':sum(r['ok'] for r in results)}))
