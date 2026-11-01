"""Read-only TLS diagnosis of two public IP-query hosts via the existing exit.

Never probes private destinations or prints node credentials. No state mutation.
"""
import json,socket,ssl,struct,sys,time
sys.path.insert(0,'/opt/home-relay-v2')
import controller as c
n=c.node('00000000000000000000000000000001')

def home():
    s=socket.create_connection(('127.0.0.1',22000+n['slot']),5);s.settimeout(7)
    s.sendall(b'\x05\x01\x02');assert c.recv(s,2)==b'\x05\x02'
    u=b'home';p=c.derive('home',n['slot']).encode()
    s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);assert c.recv(s,2)==b'\x01\x00'
    return s

def reply(s):
    h=c.recv(s,4);assert h[1]==0
    size=4 if h[3]==1 else 16 if h[3]==4 else c.recv(s,1)[0]
    c.recv(s,size+2)

def tls(host,ip,through_gate):
    start=time.monotonic();s=None
    try:
        c.TARGETS.safe_ip(ip)
        if through_gate:s,_=c.socks(n,1,ip,443)
        else:
            s=home();s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(ip)+b'\x01\xbb');reply(s)
        s.settimeout(7)
        s=ssl.create_default_context().wrap_socket(s,server_hostname=host)
        s.sendall(('GET / HTTP/1.0\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
        data=s.recv(256)
        return {'ip':ip,'via':'gate' if through_gate else 'friend-numeric-control','ok':data.startswith(b'HTTP/'),'seconds':round(time.monotonic()-start,2),'response':data.split(b'\r\n')[0].decode('ascii','replace')}
    except Exception as e:return {'ip':ip,'via':'gate' if through_gate else 'friend-numeric-control','ok':False,'seconds':round(time.monotonic()-start,2),'error':type(e).__name__}
    finally:
        if s:s.close()

def friend_dns(host):
    labels=b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+b'\x00'
    query=b'\x51\x77\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+labels+b'\x00\x01\x00\x01'
    with home() as s:
        s.sendall(b'\x05\xf3\x00\x01\x00\x00\x00\x00\x00\x00');reply(s)
        s.sendall(struct.pack('!H',len(query))+b'\xff\x01'+socket.inet_aton('223.5.5.5')+b'\x00\x35'+query)
        h=c.recv(s,4);size=struct.unpack('!H',h[:2])[0]
        c.recv(s,(4 if h[3]==1 else 16 if h[3]==4 else c.recv(s,1)[0])+2)
        data=c.recv(s,size)
    def skip(offset):
        while data[offset]:
            if data[offset]&192==192:return offset+2
            offset+=data[offset]+1
        return offset+1
    qd,an=struct.unpack('!HH',data[4:8]);offset=12
    for _ in range(qd):offset=skip(offset)+4
    ips=[]
    for _ in range(an):
        offset=skip(offset);kind,cls,ttl,size=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10
        if kind==1 and cls==1 and size==4:
            ip=socket.inet_ntoa(data[offset:offset+4]);c.TARGETS.safe_ip(ip)
            if ip not in ips:ips.append(ip)
        offset+=size
    return ips

result={'seen_age':round(time.time()-n['seen'],2),'hosts':[]}
for host in ('api.ipify.org','myip.ipip.net'):
    ips=[]
    for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM):
        ip=c.TARGETS.safe_ip(row[4][0])
        if ip not in ips:ips.append(ip)
    entry={'host':host,'server_dns':ips,'tests':[]}
    try:entry['friend_dns']=friend_dns(host)
    except Exception as e:entry['friend_dns_error']=type(e).__name__
    chosen=sorted(ips)[0]
    entry['tests'].append(tls(host,chosen,True))
    entry['tests'].append(tls(host,chosen,False))
    others=[ip for ip in entry.get('friend_dns',[]) if ip!=chosen]
    if others:entry['tests'].append(tls(host,others[0],False))
    result['hosts'].append(entry)
print(json.dumps(result,ensure_ascii=True))
