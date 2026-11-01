import hashlib,http.client,json,pathlib,socket,sqlite3,subprocess,sys,time,urllib.request,urllib.error
sys.path.insert(0,'/opt/home-relay-v2');import controller as c
def run(*a):
 p=subprocess.run(a,capture_output=True,text=True,timeout=15);return {'rc':p.returncode,'output':p.stdout,'error':p.stderr}
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
n=c.node('00000000000000000000000000000001');probe=c.probe(n)
if probe['tcp']:
 with c.db() as d:d.execute('UPDATE nodes SET exit_ip=?,test_time=?,tcp=?,udp=? WHERE id=?',(probe['exit_ip'],time.time(),int(probe['tcp']),int(probe['udp']),n['id']))
r={'probe':probe,'seen_age':time.time()-n['seen'],'node_count':0,'usage_revision':c.access(n['id'])['revision'],
   'homepage_hash':sha('/opt/1panel/www/sites/example.invalid/index/index.html'),
   'routes_hash':sha('/opt/1panel/www/sites/example-site/public-routes.conf')}
with c.db() as d:r['node_count']=d.execute('SELECT COUNT(*) FROM nodes').fetchone()[0]
r['services']=run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','ssh.service','gost-home-relay.service','home-relay-v2-proxy.service','home-relay-direct-firewall.service','-p','Id,MainPID,ActiveState,UnitFileState')
r['sockets']=run('ss','-lntup')
r['containers']=run('docker','ps','--format','{{.Names}} {{.Status}}')
r['iptables']=run('iptables','-nvL','HR_DIRECT_EGRESS');r['ip6tables']=run('ip6tables','-S','HR_DIRECT_EGRESS')
r['nginx_test']=run('docker','exec','1Panel-openresty-KEVH','nginx','-t')
r['ssh_test']=run('/usr/sbin/sshd','-t')
for user in ['admin','gost-home-auto','gost-home-v2-client','gost-home-publisher']:
 result=run('/usr/sbin/sshd','-T','-C',f'user={user},host=localhost,addr=127.0.0.1')
 r['ssh_'+user]=[line for line in result['output'].splitlines() if line.split()[0] in ['allowtcpforwarding','authorizedkeysfile','authorizedkeyscommand','permitopen','permitlisten','forcecommand','passwordauthentication']]
test="import socket; s=socket.socket(); s.settimeout(3); r=s.connect_ex(('1.1.1.1',443)); print(r); assert r!=0"
r['uid_no_public_egress']=run('runuser','-u','home-relay-v2','--','python3','-c',test)
for path in ['/','/relay-admin/','/tools/image-lab/','/__home_relay_v2/consumer']:
 try:
  req=urllib.request.Request('https://relay.example.invalid'+path,data=b'{}' if path.endswith('consumer') else None,headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(req,timeout=12) as res:r['https_'+path]=res.status
 except urllib.error.HTTPError as e:r['https_'+path]=e.code
print(json.dumps(r,ensure_ascii=False))
