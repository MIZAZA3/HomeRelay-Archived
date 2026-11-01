"""Publish only the verified V4.3 controller/transport stability patch."""
import base64,hashlib,io,json,pathlib,sys,tarfile
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
root=pathlib.Path(__file__).resolve().parents[1]
baseline=json.loads(pathlib.Path('D:/CodexWork/HomeRelayDirectV4/stability-baseline/inventory.json').read_text('utf-8'))
mapping={'server/'+name:'/opt/home-relay-v2/'+name for name in ('controller.py','target_policy.py','direct_proxy.py')}
archive=io.BytesIO()
with tarfile.open(fileobj=archive,mode='w:gz') as stream:
    for name in mapping:stream.add(root/name,arcname=name)
payload={'mapping':mapping,'expected':{dst:baseline['files'][dst]['sha256'] for dst in mapping.values()},
         'hashes':{dst:hashlib.sha256((root/src).read_bytes()).hexdigest() for src,dst in mapping.items()},
         'archive':base64.b64encode(archive.getvalue()).decode()}
script='PAYLOAD='+repr(payload)+'\n'+(root/'deploy/install_stability.py').read_text('utf-8')
result=ssh('sudo -n python3 -',script.encode()).decode('utf-8','replace')
pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/stability-v43-deploy.json').write_text(result,'utf-8')
print(result)
