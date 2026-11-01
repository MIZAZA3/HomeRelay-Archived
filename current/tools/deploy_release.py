"""Upload a source-only, hash-checked release. No credentials leave production."""
import base64,hashlib,io,json,pathlib,sys,tarfile
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
ROOT=pathlib.Path(__file__).resolve().parents[1]
baseline=json.loads(pathlib.Path('D:/CodexWork/HomeRelayDirectV4/baseline/inventory.json').read_text('utf-8'))
mapping={
    'server/controller.py':'/opt/home-relay-v2/controller.py',
    'server/direct_proxy.py':'/opt/home-relay-v2/direct_proxy.py',
    'server/web_gateway.py':'/opt/home-relay-web/web_gateway.py',
    'server/panel.html':'/opt/home-relay-web/panel.html',
    'server/app.js':'/opt/home-relay-web/app.js',
    'server/style.css':'/opt/home-relay-web/style.css',
    'deploy/home-relay-v2-controller.service':'/etc/systemd/system/home-relay-v2-controller.service',
    'deploy/home-relay-direct-firewall.service':'/etc/systemd/system/home-relay-direct-firewall.service',
    'deploy/home-relay-direct-firewall.py':'/usr/local/sbin/home-relay-direct-firewall.py',
}
out=io.BytesIO()
with tarfile.open(fileobj=out,mode='w:gz') as t:
    for source in mapping:t.add(ROOT/source,arcname=source)
payload={'archive':base64.b64encode(out.getvalue()).decode(),'mapping':mapping,
         'hashes':{dst:hashlib.sha256((ROOT/src).read_bytes()).hexdigest() for src,dst in mapping.items()},
         'expected':{path:obj['sha256'] for path,obj in baseline['files'].items() if path in mapping.values()}}
script=(ROOT/'deploy/install.py').read_text('utf-8')
script='PAYLOAD='+repr(payload)+'\n'+script
result=ssh('sudo -n python3 -',script.encode()).decode('utf-8','replace')
pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/deploy.txt').write_text(result,'utf-8')
print(result)
