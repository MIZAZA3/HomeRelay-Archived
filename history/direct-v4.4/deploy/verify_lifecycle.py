"""Read-only release preservation and live resource samples; no probe/DB writes."""
import collections
import contextlib
import hashlib
import json
import pathlib
import sqlite3
import stat
import subprocess
import time

base=pathlib.Path('/var/backups/home-relay-lifecycle/20261101T080748Z')
manifest=json.loads((base/'manifest.json').read_text())

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def run(*args):return subprocess.check_output(args,text=True,timeout=20)

r={'sources_match':all(sha(p)==h for p,h in manifest['installed'].items()),
   'protected_match':all(sha(p)==h for p,h in manifest['protected'].items()),'samples':[]}
with contextlib.closing(sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3')) as db,contextlib.closing(sqlite3.connect(base/'nodes.sqlite3')) as previous:
    r['access_history_limits_unchanged']=all(db.execute(q).fetchall()==previous.execute(q).fetchall() for q in (
        'SELECT * FROM node_access ORDER BY node_id','SELECT * FROM node_password_history ORDER BY node_id,digest',
        'SELECT * FROM node_limits ORDER BY node_id','SELECT id,slot,state,secret_hash,pubkey FROM nodes ORDER BY id'))
    r['nodes']=db.execute('SELECT n.id,n.slot,n.state,a.revision FROM nodes n JOIN node_access a ON a.node_id=n.id').fetchall()
pid=run('systemctl','show','home-relay-v2-controller.service','-p','MainPID','--value').strip()
for _ in range(16):
    counts=collections.Counter()
    for fd in pathlib.Path('/proc/'+pid+'/fd').iterdir():
        try:target=str(fd.readlink())
        except OSError:continue
        counts['sqlite' if 'nodes.sqlite3' in target else 'socket' if target.startswith('socket:') else 'other']+=1
    r['samples'].append({'time':time.time(),'fds':dict(counts),'diagnostics':json.loads(pathlib.Path('/var/lib/home-relay-v2/diagnostics.json').read_text())})
    time.sleep(2)
r['private_diagnostics_mode']=oct(stat.S_IMODE(pathlib.Path('/var/lib/home-relay-v2/diagnostics.json').stat().st_mode))
r['protected_services_unchanged']=run('systemctl','show','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')==manifest['protected_services_preserved']
r['services']=run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState,NRestarts,MemoryCurrent,TasksCurrent')
r['containers']=run('docker','ps','--format','{{.Names}} {{.Status}}')
r['website_hashes']={p:sha(p) for p in manifest['website_after']}
r['website_unchanged']=r['website_hashes']==manifest['website_after']
r['firewall_ipv4']=run('iptables','-S','HR_DIRECT_EGRESS')
r['firewall_ipv6']=run('ip6tables','-S','HR_DIRECT_EGRESS')
r['listeners']=run('ss','-lntup')
with contextlib.closing(sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3')) as db:
    seen,tunnel=db.execute('SELECT seen,tunnel FROM nodes ORDER BY slot LIMIT 1').fetchone()
    r['heartbeat_age']=time.time()-seen
    r['exit_online']=r['heartbeat_age']<45 and bool(tunnel)
print(json.dumps(r,ensure_ascii=True))
assert all(r[k] for k in ['sources_match','protected_match','access_history_limits_unchanged','protected_services_unchanged','website_unchanged'])
assert r['private_diagnostics_mode']=='0o600'
assert max(s['fds'].get('sqlite',0) for s in r['samples'])<=9

assert r['exit_online'],'Friend exit is offline: do not interpret as capacity failure'
