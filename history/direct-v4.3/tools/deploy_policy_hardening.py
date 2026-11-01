"""Narrow supplemental deny-range update, no DB or password changes."""
import base64,hashlib,json,pathlib,sys
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
root=pathlib.Path(__file__).resolve().parents[1]
source=(root/'server/target_policy.py').read_bytes()
unit=(root/'tests/target_policy.test.py').read_bytes()
script='DATA='+repr(base64.b64encode(source).decode())+'\nUNIT='+repr(base64.b64encode(unit).decode())+'\n'+'''
import base64,datetime,hashlib,json,os,pathlib,py_compile,shutil,subprocess,time
base=pathlib.Path('/var/backups/home-relay-limits/20261101T041013Z')
manifest=json.loads((base/'manifest.json').read_text())
target=pathlib.Path('/opt/home-relay-v2/target_policy.py')
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
assert sha(target)==manifest['installed'][str(target)],'Concurrent policy source change'
assert 'special-use ranges' not in target.read_text(),'Patch already applied'
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
backup=base/('policy-hardening-'+stamp);backup.mkdir(mode=0o700)
shutil.copy2(target,backup/'target_policy-before.py')
new=backup/'target_policy.py';new.write_bytes(base64.b64decode(DATA));os.chmod(new,0o600)
test=backup/'target_policy.test.py';test.write_bytes(base64.b64decode(UNIT))
# The test file derives its import path from a repo tree. Explicitly load staged
# policy first, so this always tests the new source on Ubuntu's actual Python.
env=dict(os.environ,PYTHONPATH=str(backup))
subprocess.run(['python3',str(test)],env=env,check=True,timeout=15,capture_output=True)
py_compile.compile(str(new),doraise=True)
old_protected=dict(manifest['protected'])
website_paths={p for p in old_protected if p.startswith('/opt/1panel/www/sites/')}
assert all(sha(p)==value for p,value in old_protected.items() if p not in website_paths),'Protected HomeRelay/SSH configuration changed'
# Other approved website chats may publish concurrently. Read their CURRENT
# homepage/routes as preimages; never restore ours from a historical manifest.
protected={p:sha(p) for p in old_protected}
db='/var/lib/home-relay-v2/nodes.sqlite3'
import sqlite3
with sqlite3.connect(db) as c:before=c.execute('SELECT * FROM node_access ORDER BY node_id').fetchall()
temporary=target.with_name('target_policy.py.hardening-new');temporary.write_bytes(new.read_bytes());os.chmod(temporary,0o644);os.chown(temporary,0,0);temporary.replace(target)
subprocess.run(['systemctl','restart','home-relay-v2-controller.service'],check=True,timeout=25)
for _ in range(60):
 time.sleep(.2)
 tcp=subprocess.check_output(['ss','-lntH'],text=True);udp=subprocess.check_output(['ss','-lnuH'],text=True)
 if '0.0.0.0:24443' in tcp and '0.0.0.0:24443' in udp:break
else:raise RuntimeError('Ingress not ready after narrow policy update')
with sqlite3.connect(db) as c:assert before==c.execute('SELECT * FROM node_access ORDER BY node_id').fetchall()
assert all(sha(p)==value for p,value in protected.items()),'Protected file changed during patch'
manifest['installed'][str(target)]=sha(target)
manifest['latest_protected']=protected
pid=subprocess.check_output(['systemctl','show','home-relay-v2-controller.service','-p','MainPID','--value'],text=True).strip()
entry={'backup':str(backup),'policy_sha256':sha(target),'controller_pid':int(pid),'credentials_unchanged':True,'system_python_policy_unit_passed':True,'protected_preimage':protected,'external_website_changes_observed_before_patch':{p:protected[p] for p in website_paths if protected[p]!=old_protected[p]}}
manifest.setdefault('supplemental_patches',[]).append(entry)
(base/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(entry))
'''
result=ssh('sudo -n python3 -',script.encode()).decode('utf-8','replace')
pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/policy-hardening-deploy.json').write_text(result,'utf-8')
print(result)
