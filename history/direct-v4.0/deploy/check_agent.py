import json,pathlib,socket,struct,subprocess,sys,time,http.client,ssl
sys.path.insert(0,'/opt/home-relay-v2');import controller as c
n=c.node('00000000000000000000000000000001')
print(json.dumps({'seen_age':time.time()-n['seen'],'state':n['state'],'tunnel':n['tunnel']}))
try:
 s=socket.create_connection(('127.0.0.1',22000),5);s.settimeout(8);s.sendall(b'\x05\x01\x02');method=c.recv(s,2)
 u=b'home';p=c.derive('home',0).encode();s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);auth=c.recv(s,2)
 print(json.dumps({'friend_method':method.hex(),'friend_auth':auth.hex()}));s.close()
except Exception as e:print('friend_protocol_error',type(e).__name__)
conn=http.client.HTTPConnection('127.0.0.1',18781,timeout=10)
conn.request('POST','/poll',json.dumps({'id':n['id'],'secret':'x'*43}),{'Content-Type':'application/json','X-Enrollment-Key':c.CFG['enrollment']});r=conn.getresponse();print('poll-invalid-secret-status',r.status);r.read();conn.close()
for a in [('ufw','allow','proto','udp','from','0.0.0.0/0','to','any','port','24443','comment','HomeRelay SS AEAD UDP'),('python3','/usr/local/sbin/home-relay-direct-firewall.py')]:
 p=subprocess.run(a,capture_output=True,text=True);print(p.returncode,p.stdout,p.stderr)
print('probe',json.dumps(c.probe(n)))
