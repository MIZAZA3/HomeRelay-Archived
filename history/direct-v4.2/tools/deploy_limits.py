"""Guarded V4.2 source update; existing node credentials and global cap remain."""
import base64, hashlib, io, json, pathlib, sys, tarfile
sys.path.insert(0, r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh

root = pathlib.Path(__file__).resolve().parents[1]
baseline = json.loads(pathlib.Path('D:/CodexWork/HomeRelayDirectV4/limits-baseline/inventory.json').read_text('utf-8'))
mapping = {f'server/{name}': f'/opt/home-relay-v2/{name}' for name in
           ('controller.py', 'direct_proxy.py', 'credential_admin.py', 'node_limits.py', 'target_policy.py')}
mapping.update({f'server/{name}': f'/opt/home-relay-web/{name}' for name in
                ('web_gateway.py', 'app.js', 'panel.html', 'style.css')})
archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w:gz') as stream:
    for source in mapping:
        stream.add(root / source, arcname=source)
payload = {'mapping': mapping,
           'expected': {p: baseline['files'][p]['sha256'] for p in mapping.values() if p in baseline['files']},
           'new_files': [p for p in mapping.values() if p not in baseline['files']],
           'hashes': {dst: hashlib.sha256((root / src).read_bytes()).hexdigest() for src, dst in mapping.items()},
           'archive': base64.b64encode(archive.getvalue()).decode()}
script = 'PAYLOAD=' + repr(payload) + '\n' + (root / 'deploy/install_limits.py').read_text('utf-8')
result = ssh('sudo -n python3 -', script.encode()).decode('utf-8', 'replace')
pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/limits-deploy.json').write_text(result, 'utf-8')
print(result)
