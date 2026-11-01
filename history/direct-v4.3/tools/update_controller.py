import base64,hashlib,pathlib,sys
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
root=pathlib.Path(__file__).resolve().parents[1]
source=(root/'server/controller.py').read_bytes()
script='''import base64,hashlib,json,pathlib,shutil,subprocess
b=pathlib.Path('/var/backups/home-relay-direct-v4/20261031T194807Z');m=json.loads((b/'manifest.json').read_text());p=pathlib.Path('/opt/home-relay-v2/controller.py')
assert hashlib.sha256(p.read_bytes()).hexdigest()==m['installed'][str(p)]
shutil.copy2(p,b/'controller-before-dynamic-gates.py')
p.write_bytes(base64.b64decode(PAYLOAD))
subprocess.run(['python3','-m','py_compile',str(p)],check=True)
subprocess.run(['systemctl','restart','home-relay-v2-controller.service'],check=True)
m['installed'][str(p)]=hashlib.sha256(p.read_bytes()).hexdigest();(b/'manifest.json').write_text(json.dumps(m,indent=2))
print('Controller dynamic gates installed; only registered-node loopback gates will listen.')
'''.replace('PAYLOAD',repr(base64.b64encode(source).decode()))
print(ssh('sudo -n python3 -',script.encode()).decode())
