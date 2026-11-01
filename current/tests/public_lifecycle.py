"""Small public SS DNS-session pressure check through current friend exit."""
import json
import secrets
import socket
import time
from public_transport import socks,https

sessions=[]
result={'dns':[],'https':[],'same_socket_reuse':[]}

def query(udp,bound):
    tx=secrets.token_bytes(2)
    body=tx+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07example\x03com\x00\x00\x01\x00\x01'
    udp.sendto(b'\x00\x00\x00\x01'+socket.inet_aton('223.5.5.5')+b'\x00\x35'+body,bound)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        udp.settimeout(max(.01,deadline-time.monotonic()))
        reply=udp.recv(2048);offset=10 if reply[3]==1 else 22 if reply[3]==4 else 7+reply[4]
        # A late response to a previous timed-out query is not this query's
        # result. Keep reading until the matching transaction or real deadline.
        if reply[offset:offset+2]==tx:
            return bool(reply[offset+2]&128) and reply[offset+3]&15==0
    return False

try:
    for index in range(40):
        try:
            control,bound=socks(3,'0.0.0.0',0)
            udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sessions.append((control,udp,bound))
            ok=bool(query(udp,bound))
        except Exception as e:ok=False
        result['dns'].append(ok)
        if (index+1)%10==0:print(json.dumps({'progress_dns':index+1,'success':sum(result['dns'])}),flush=True)
        if (index+1)%10==0:
            host='one.tarenwang.net' if index in (19,39) else 'ip77.net'
            try:r=https(host)
            except Exception as e:r={'ok':False,'error':type(e).__name__}
            result['https'].append({'host':host,'after_dns':index+1,**r})
    time.sleep(.3)
    for _,udp,bound in sessions[:5]:
        try:ok=bool(query(udp,bound))
        except Exception:ok=False
        result['same_socket_reuse'].append(ok)
finally:
    for control,udp,bound in sessions:control.close();udp.close()
result['dns_success']=sum(result['dns']);result['dns_total']=len(result['dns'])
print(json.dumps(result),flush=True)
if not all(result['dns']) or not all(r['ok'] for r in result['https']) or not all(result['same_socket_reuse']):raise SystemExit(1)
