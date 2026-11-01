"""Read-only V4.3 preservation check after public tests."""
import hashlib,json,pathlib,sqlite3,subprocess,time
base=pathlib.Path('/var/backups/home-relay-stability/20261101T063121Z')
m=json.loads((base/'manifest.json').read_text())
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
report={'sources_match':all(sha(p)==h for p,h in m['installed'].items()),
        'protected_configuration_match':all(sha(p)==h for p,h in m['protected'].items()),
        'experimental_exit_dns_absent':not pathlib.Path('/opt/home-relay-v2/exit_dns.py').exists()}
with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db,sqlite3.connect(base/'nodes.sqlite3') as previous:
    report['access_history_limits_unchanged']=all(db.execute(q).fetchall()==previous.execute(q).fetchall() for q in
       ('SELECT * FROM node_access ORDER BY node_id','SELECT * FROM node_password_history ORDER BY node_id,digest','SELECT * FROM node_limits ORDER BY node_id'))
    report['nodes']=db.execute('SELECT n.id,n.state,n.slot,a.mode,a.revision FROM nodes n JOIN node_access a ON a.node_id=n.id ORDER BY n.id').fetchall()
    report['seen_age']=time.time()-db.execute('SELECT seen FROM nodes ORDER BY slot LIMIT 1').fetchone()[0]
def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=15);return {'rc':p.returncode,'out':p.stdout,'err':p.stderr}
report['services']=run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState,NRestarts,MemoryCurrent,TasksCurrent')
report['containers']=run('docker','ps','--format','{{.Names}} {{.Status}}')
report['website_hashes']={p:sha(p) for p in m['website_after']}
print(json.dumps(report,ensure_ascii=True))
assert report['sources_match'] and report['protected_configuration_match'] and report['access_history_limits_unchanged'] and report['experimental_exit_dns_absent']
