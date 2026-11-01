"""Temporary loopback-only SS client compares ingress vs private probe. No writes to service/config/DB."""
import contextlib,json,os,pathlib,socket,ssl,struct,subprocess,sys,tempfile,time
sys.path.insert(0,'/opt/home-relay-v2')
import controller as c
n=c.node('00000000000000000000000000000001')
cred=c.direct_proxy.credential(c.CFG,c.derive,n,c.access(n['id']))
os.umask(0o077)
work=pathlib.Path(tempfile.mkdtemp(prefix='hr-ss-comparison-',dir='/run'))
local=31870
check=socket.socket();check.bind(('127.0.0.1',local));check.close()
config={'log':{'level':'fatal'},'services':[{'name':'own-test','addr':'127.0.0.1:'+str(local),'handler':{'type':'socks5','chain':'ss','metadata':{'notls':True}},'listener':{'type':'tcp'}}],
        'chains':[{'name':'ss','hops':[{'name':'ss','nodes':[{'name':'ss','addr':'127.0.0.1:24443','connector':{'type':'ss','auth':{'username':cred['method'],'password':cred['password']}},'dialer':{'type':'tcp'}}]}]}]}
config_path=work/'client.json';config_path.write_text(json.dumps(config))
results=[]
with open(work/'client.log','wb') as log:
    process=subprocess.Popen(['/opt/gost-home-relay/gost','-C',str(config_path)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
    try:
        time.sleep(.3)
        for host in ['ip77.net','one.tarenwang.net','myip.ipip.net']:
            ip=next(row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM))
            c.TARGETS.safe_ip(ip)
            for path in ['loopback-standard-SS','private-probe']:
                start=time.monotonic();s=None
                r={'host':host,'path':path,'phase':'connect'}
                try:
                    if path=='private-probe':s,_=c.socks(n,1,ip,443)
                    else:
                        s=socket.create_connection(('127.0.0.1',local),6);s.settimeout(10)
                        s.sendall(b'\x05\x01\x00');assert c.recv(s,2)==b'\x05\x00'
                        s.sendall(b'\x05\x01\x00'+c.target_policy.encode(ip,443))
                        reply=c.recv(s,4);assert reply[1]==0
                        c.recv(s,(4 if reply[3]==1 else 16 if reply[3]==4 else c.recv(s,1)[0])+2)
                    r['phase']='TLS'
                    s=ssl.create_default_context().wrap_socket(s,server_hostname=host)
                    r['phase']='HTTPS'
                    s.sendall(('GET / HTTP/1.0\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
                    data=s.recv(256)
                    r.update(ok=data.startswith(b'HTTP/'),response=data.split(b'\r\n')[0].decode('ascii','replace'))
                except Exception as e:r.update(ok=False,error=type(e).__name__)
                finally:
                    if s:s.close()
                r['seconds']=round(time.monotonic()-start,3);results.append(r)
    finally:
        process.terminate();process.wait(timeout=5)
        # Both paths are fixed inside this script-created private directory.
        config_path.unlink();(work/'client.log').unlink();work.rmdir()
print(json.dumps({'results':results},ensure_ascii=True))
