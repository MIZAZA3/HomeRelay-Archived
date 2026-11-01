"""Check standard SS UDP reuse using the same local association after 35 sec."""
import json,secrets,socket,struct,time

def exact(s,n):
    data=b''
    while len(data)<n:
        q=s.recv(n-len(data))
        if not q:raise EOFError('local test proxy closed')
        data+=q
    return data

result={'same_udp_socket':True,'same_socks_control':True,'idle_seconds':35,'before':False,'after':False}
try:
    with socket.create_connection(('127.0.0.1',31980),10) as s,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        s.settimeout(10);s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
        s.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        h=exact(s,4);assert h[1]==0
        if h[3]==1:host=socket.inet_ntoa(exact(s,4))
        elif h[3]==4:host=socket.inet_ntop(socket.AF_INET6,exact(s,16))
        else:host=exact(s,exact(s,1)[0]).decode()
        port=int.from_bytes(exact(s,2),'big');bound=('127.0.0.1' if host in ('0.0.0.0','::') else host,port)
        def query():
            tx=secrets.token_bytes(2)
            body=tx+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07example\x03com\x00\x00\x01\x00\x01'
            udp.settimeout(5);udp.sendto(b'\x00\x00\x00\x01'+socket.inet_aton('223.5.5.5')+b'\x00\x35'+body,bound)
            reply=udp.recv(2048);offset=10 if reply[3]==1 else 22 if reply[3]==4 else 7+reply[4]
            return reply[offset:offset+2]==tx and reply[offset+2]&128 and reply[offset+3]&15==0
        result['before']=bool(query())
        if result['before']:
            time.sleep(35)
            result['after']=bool(query())
except Exception as error:result['error']=type(error).__name__
print(json.dumps(result))
if not (result['before'] and result['after']):raise SystemExit(1)
