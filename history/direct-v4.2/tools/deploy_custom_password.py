"""Narrow V4.1 update, current password unchanged; no credential data downloaded."""
import base64,hashlib,io,json,pathlib,sys,tarfile
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
root=pathlib.Path(__file__).resolve().parents[1]
baseline=json.loads(pathlib.Path('D:/CodexWork/HomeRelayDirectV4/custom-password-baseline/inventory.json').read_text('utf-8'))
mapping={'server/controller.py':'/opt/home-relay-v2/controller.py','server/direct_proxy.py':'/opt/home-relay-v2/direct_proxy.py',
         'server/credential_admin.py':'/opt/home-relay-v2/credential_admin.py','server/app.js':'/opt/home-relay-web/app.js',
         'server/panel.html':'/opt/home-relay-web/panel.html','server/style.css':'/opt/home-relay-web/style.css'}
archive=io.BytesIO()
with tarfile.open(fileobj=archive,mode='w:gz') as t:
    for source in mapping:t.add(root/source,arcname=source)
payload={'mapping':mapping,'expected':{p:baseline['files'][p]['sha256'] for p in mapping.values() if p in baseline['files']},
         'hashes':{dst:hashlib.sha256((root/src).read_bytes()).hexdigest() for src,dst in mapping.items()},
         'archive':base64.b64encode(archive.getvalue()).decode()}
script='PAYLOAD='+repr(payload)+'\n'+(root/'deploy/install_custom_password.py').read_text('utf-8')
result=ssh('sudo -n python3 -',script.encode()).decode('utf-8','replace')
pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/custom-password-deploy.txt').write_text(result,'utf-8')
print(result)
