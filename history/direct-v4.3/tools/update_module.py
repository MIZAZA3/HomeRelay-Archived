"""One-time hardening patch; no node/password database changes."""
import base64,pathlib,sys
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
source=(pathlib.Path(__file__).resolve().parents[1]/'server/direct_proxy.py').read_bytes()
script='''import base64,datetime,hashlib,json,pathlib,shutil,subprocess,time
b=pathlib.Path('/var/backups/home-relay-direct-v4/20261031T194807Z');m=json.loads((b/'manifest.json').read_text());p=pathlib.Path('/opt/home-relay-v2/direct_proxy.py')
assert hashlib.sha256(p.read_bytes()).hexdigest()==m['installed'][str(p)]
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
shutil.copy2(p,b/('direct_proxy-before-'+stamp+'.py'))
p.write_bytes(base64.b64decode(PAYLOAD))
subprocess.run(['python3','-m','py_compile',str(p)],check=True)
subprocess.run(['systemctl','restart','home-relay-v2-controller.service'],check=True)
for _ in range(60):
 time.sleep(.2)
 if '0.0.0.0:24443' in subprocess.check_output(['ss','-lntH'],text=True):break
else:raise RuntimeError('SS listener did not recover')
m['installed'][str(p)]=hashlib.sha256(p.read_bytes()).hexdigest();(b/'manifest.json').write_text(json.dumps(m,indent=2))
print('Idempotent per-node provisioning and collision-safe YAML names deployed; password revision unchanged.')
'''.replace('PAYLOAD',repr(base64.b64encode(source).decode()))
print(ssh('sudo -n python3 -',script.encode()).decode())
