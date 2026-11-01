import json,pathlib,sqlite3,subprocess,sys,time
sys.path.insert(0,'/opt/home-relay-v2')
import controller as c
n=c.node('00000000000000000000000000000001')
print(json.dumps({'seen_age':time.time()-n['seen'],'tunnel':n['tunnel'],'state':n['state'],'probe':c.probe(n)}))
for args in [('ss','-ntp'),('iptables','-nvL','HR_DIRECT_EGRESS'),('systemctl','status','home-relay-v2-controller','--no-pager'),('journalctl','-u','home-relay-v2-controller','-n','10','--no-pager')]:
 p=subprocess.run(args,capture_output=True,text=True);print(' '.join(args),p.stdout[-6000:],p.stderr)
