import hashlib,json,pathlib,sqlite3,subprocess
def run(*a):
    p=subprocess.run(a,capture_output=True,text=True);return {'rc':p.returncode,'out':p.stdout,'err':p.stderr}
r={}
r['publisher_include']=pathlib.Path('/etc/ssh/home-relay-publisher.inc').read_text()
r['listeners']=run('ss','-lntup')
r['uid']=run('id','home-relay-v2')
r['iptables']=run('iptables','-S','OUTPUT')
r['ipv6tables']=run('ip6tables','-S','OUTPUT')
r['unit_security']=run('systemctl','show','home-relay-v2-controller','-p','MainPID,ActiveState')
r['binary_access']=run('runuser','-u','home-relay-v2','--','/opt/gost-home-relay/gost','-V')
db=sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3');db.row_factory=sqlite3.Row
r['nodes']=[dict(x) for x in db.execute('SELECT n.id,n.slot,n.state,n.seen,n.tunnel,a.mode,a.revision FROM nodes n LEFT JOIN node_access a ON n.id=a.node_id')]
print(json.dumps(r))
