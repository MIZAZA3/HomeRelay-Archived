"""Read-only post-UI verification; never prints credentials or mutates nodes."""
import hashlib,json,pathlib,sqlite3,subprocess,time

root=pathlib.Path('/var/backups/home-relay-limits/20261101T041013Z')
manifest=json.loads((root/'manifest.json').read_text())
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def run(*a):
    p=subprocess.run(a,capture_output=True,text=True,timeout=20)
    return {'rc':p.returncode,'output':p.stdout,'error':p.stderr}
report={'installed_sources_match':all(sha(p)==value for p,value in manifest['installed'].items()),
        'protected_files_match':all(sha(p)==value for p,value in manifest.get('latest_protected',manifest['protected']).items())}
with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db:
    report['nodes']=db.execute('SELECT n.id,n.state,n.slot,a.mode,a.revision FROM nodes n JOIN node_access a ON a.node_id=n.id ORDER BY n.id').fetchall()
    report['limits']=db.execute('SELECT node_id,upload_kib,download_kib,revision FROM node_limits ORDER BY node_id').fetchall()
    report['seen_age']=time.time()-db.execute('SELECT seen FROM nodes ORDER BY slot LIMIT 1').fetchone()[0]
    with sqlite3.connect(root/'nodes.sqlite3') as previous:
        report['passwords_and_history_still_unchanged']=(
            db.execute('SELECT * FROM node_access ORDER BY node_id').fetchall()==previous.execute('SELECT * FROM node_access ORDER BY node_id').fetchall()
            and db.execute('SELECT * FROM node_password_history ORDER BY node_id,digest').fetchall()==previous.execute('SELECT * FROM node_password_history ORDER BY node_id,digest').fetchall())
report['services']=run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')
report['containers']=run('docker','ps','--format','{{.Names}} {{.Status}}')
report['ufw']=run('ufw','status','numbered')
print(json.dumps(report,ensure_ascii=True))
assert report['installed_sources_match'] and report['protected_files_match'] and report['passwords_and_history_still_unchanged']
