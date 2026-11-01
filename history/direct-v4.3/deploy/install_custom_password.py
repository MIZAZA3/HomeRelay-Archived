"""Source-only directional update. PAYLOAD is injected; do not run standalone."""
import base64,datetime,hashlib,hmac,io,json,os,pathlib,shutil,sqlite3,subprocess,sys,tarfile,time
def run(*args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=25)
 if p.returncode:raise RuntimeError('Command failed: '+args[0]+' '+p.stderr[-400:])
 return p.stdout
def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
for path,expected in PAYLOAD['expected'].items():
 if sha(path)!=expected:raise RuntimeError('Concurrent source modification: '+path)
newmodule=pathlib.Path('/opt/home-relay-v2/credential_admin.py')
if newmodule.exists():raise RuntimeError('Credential admin module already exists; use a new audited update')
run('runuser','-u','home-relay-v2','--','python3','-c','from cryptography.fernet import Fernet; assert Fernet')
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
base=pathlib.Path('/var/backups/home-relay-custom-password')/stamp
base.mkdir(parents=True,mode=0o700);os.chmod(base.parent,0o700)
for path in PAYLOAD['expected']:
 target=base/'before'/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copy2(path,target)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD['archive'])),mode='r:gz') as t:t.extractall(base/'source',filter='data')
for src,dst in PAYLOAD['mapping'].items():
 if sha(base/'source'/src)!=PAYLOAD['hashes'][dst]:raise RuntimeError('Staged source digest mismatch')
run('python3','-m','compileall','-q',str(base/'source/server'))
site='/opt/1panel/www/sites/example.invalid/index/index.html'
routes='/opt/1panel/www/sites/example-site/public-routes.conf'
protected={p:sha(p) for p in [site,routes,'/etc/ssh/home-relay-v2.inc','/etc/home-relay-v2/access.json']}
services_before=run('systemctl','show','home-relay-web.service','ssh.service','-p','Id,MainPID')
run('systemctl','stop','home-relay-v2-controller.service')
def access_state():
 with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db:
  return db.execute('SELECT node_id,mode,revision,updated FROM node_access ORDER BY node_id').fetchall()
before=access_state()
with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db,sqlite3.connect(base/'nodes.sqlite3') as backup:db.backup(backup)
def install(src,dst):
 p=pathlib.Path(dst);tmp=p.with_name(p.name+'.v41-new');tmp.write_bytes((base/'source'/src).read_bytes());os.chmod(tmp,0o644);os.chown(tmp,0,0);tmp.replace(p)
try:
 # Backend first; old browser JS cannot submit a custom password while migrating.
 for src,dst in PAYLOAD['mapping'].items():
  if dst.startswith('/opt/home-relay-v2/'):install(src,dst)
 run('systemctl','start','home-relay-v2-controller.service')
 for _ in range(80):
  time.sleep(.15)
  if '0.0.0.0:24443' in run('ss','-lntH') and '0.0.0.0:24443' in run('ss','-lnuH'):break
 else:raise RuntimeError('Standard ingress unavailable after update')
 after=access_state()
 if after!=before:raise RuntimeError('Access state changed during deployment; investigate before publishing UI')
 with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db:
  assert 'ss_secret' in {x[1] for x in db.execute('PRAGMA table_info(node_access)')}
  assert db.execute('SELECT COUNT(*) FROM node_access WHERE ss_secret!=""').fetchone()[0]==0
 for p,digest in protected.items():
  if sha(p)!=digest:raise RuntimeError('Protected file changed: '+p)
 if run('systemctl','show','home-relay-web.service','ssh.service','-p','Id,MainPID')!=services_before:raise RuntimeError('Protected process changed')
 for src,dst in PAYLOAD['mapping'].items():
  if dst.startswith('/opt/home-relay-web/'):install(src,dst)
except Exception:
 # Never roll back database or revive older versions. If a real custom password
 # was already saved externally, keep the new decrypt-capable backend in place.
 with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db:
  columns={x[1] for x in db.execute('PRAGMA table_info(node_access)')}
  custom=db.execute('SELECT COUNT(*) FROM node_access WHERE ss_secret!=""').fetchone()[0] if 'ss_secret' in columns else 0
 if not custom:
  run('systemctl','stop','home-relay-v2-controller.service')
  for path in PAYLOAD['expected']:shutil.copy2(base/'before'/path.lstrip('/'),path)
  run('systemctl','start','home-relay-v2-controller.service')
 raise
manifest={'release':str(base),'expected':PAYLOAD['expected'],'installed':PAYLOAD['hashes'],'protected':protected,'access_state_unchanged':before==after,'node_versions':[{'id':r[0],'mode':r[1],'revision':r[2]} for r in after]}
(base/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps({'release':str(base),'passwords_unchanged':before==after,'nodes':manifest['node_versions'],'services_preserved':services_before,'homepage_hash':protected[site],'routes_hash':protected[routes]}))
