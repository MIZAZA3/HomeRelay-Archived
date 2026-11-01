"""One-time V4.2 directional deployment. PAYLOAD is injected by deploy_limits.py.

No production passwords, private configuration or DB contents leave the server.
No whole-DB rollback and no website, SSH, firewall or FlClash reconfiguration.
"""
import base64, datetime, hashlib, io, json, os, pathlib, shutil, sqlite3, subprocess, tarfile, time


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=25)
    if p.returncode:
        raise RuntimeError('Command failed: ' + args[0] + ' ' + p.stderr[-300:])
    return p.stdout


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


for path, expected in PAYLOAD['expected'].items():
    if sha(path) != expected:
        raise RuntimeError('Concurrent source modification: ' + path)
for path in PAYLOAD['new_files']:
    if pathlib.Path(path).exists():
        raise RuntimeError('New module already exists; use a fresh audited baseline: ' + path)

stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
base = pathlib.Path('/var/backups/home-relay-limits') / stamp
base.mkdir(parents=True, mode=0o700)
os.chmod(base.parent, 0o700)
for path in PAYLOAD['expected']:
    target = base / 'before' / path.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(path, target)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD['archive'])), mode='r:gz') as stream:
    stream.extractall(base / 'source', filter='data')
for src, dst in PAYLOAD['mapping'].items():
    if sha(base / 'source' / src) != PAYLOAD['hashes'][dst]:
        raise RuntimeError('Staged source digest mismatch')
run('python3', '-m', 'compileall', '-q', str(base / 'source/server'))

protected_paths = ['/opt/1panel/www/sites/example.invalid/index/index.html',
                   '/opt/1panel/www/sites/example-site/public-routes.conf',
                   '/etc/ssh/home-relay-v2.inc', '/etc/home-relay-v2/access.json',
                   '/etc/home-relay-web/web.json',
                   '/etc/systemd/system/home-relay-v2-controller.service',
                   '/etc/systemd/system/home-relay-web.service',
                   '/opt/home-relay-v2/ssh_authorize.py',
                   '/usr/local/sbin/home-relay-direct-firewall.py']
protected = {p: sha(p) for p in protected_paths}
ssh_before = run('systemctl', 'show', 'ssh.service', '-p', 'MainPID,ActiveState')
containers_before = run('docker', 'ps', '--format', '{{.Names}} {{.ID}} {{.Status}}')
business_before = run('docker', 'inspect', '--format', '{{.Name}} {{.Id}} {{.State.StartedAt}}',
                      'list94-web-1', 'example-site-website', 'list94-db-1')
ufw_before = run('ufw', 'status', 'numbered')
egress_before = {cmd: run(cmd, '-S', 'HR_DIRECT_EGRESS') for cmd in ('iptables', 'ip6tables')}
database = '/var/lib/home-relay-v2/nodes.sqlite3'


def access_state():
    with sqlite3.connect(database) as db:
        # Includes ciphertext and history, but neither is printed nor downloaded.
        return (db.execute('SELECT * FROM node_access ORDER BY node_id').fetchall(),
                db.execute('SELECT * FROM node_password_history ORDER BY node_id,digest').fetchall(),
                db.execute('SELECT id,slot,state,secret_hash,pubkey FROM nodes ORDER BY id').fetchall())


def install(src, dst):
    target = pathlib.Path(dst)
    temporary = target.with_name(target.name + '.v42-new')
    temporary.write_bytes((base / 'source' / src).read_bytes())
    os.chmod(temporary, 0o644)
    os.chown(temporary, 0, 0)
    temporary.replace(target)


# Stop only the HomeRelay control/data process group. Existing reverse SSH and
# normal SSH management remain up; clients may briefly reconnect.
run('systemctl', 'stop', 'home-relay-v2-controller.service')
try:
    before = access_state()
    with sqlite3.connect(database) as db, sqlite3.connect(base / 'nodes.sqlite3') as backup:
        db.backup(backup)
except Exception:
    run('systemctl', 'start', 'home-relay-v2-controller.service')
    raise
try:
    # Recheck after stopping: never blindly overwrite another publisher.
    for path, expected in PAYLOAD['expected'].items():
        if sha(path) != expected:
            raise RuntimeError('Source changed immediately before install: ' + path)
    for src, dst in PAYLOAD['mapping'].items():
        if dst.startswith('/opt/home-relay-v2/'):
            install(src, dst)
    run('systemctl', 'start', 'home-relay-v2-controller.service')
    for _ in range(100):
        time.sleep(.15)
        if '0.0.0.0:24443' in run('ss', '-lntH') and '0.0.0.0:24443' in run('ss', '-lnuH'):
            break
    else:
        raise RuntimeError('Standard encrypted ingress unavailable after update')
    if access_state() != before:
        raise RuntimeError('Access or node identity changed; investigate before publishing UI')
    with sqlite3.connect(database) as db:
        limits = db.execute('SELECT node_id,upload_kib,download_kib,revision FROM node_limits ORDER BY node_id').fetchall()
        if any(row[1:] != (0, 0, 1) for row in limits):
            raise RuntimeError('Unexpected initial limits; refusing to assume defaults')
        if len(limits) != len(before[2]):
            raise RuntimeError('Missing default node limits')
    for src, dst in PAYLOAD['mapping'].items():
        if dst.startswith('/opt/home-relay-web/'):
            install(src, dst)
    # Gateway must pick up the new authenticated route. Does not restart Nginx.
    run('systemctl', 'restart', 'home-relay-web.service')
    if run('systemctl', 'is-active', 'home-relay-web.service').strip() != 'active':
        raise RuntimeError('HomeRelay admin gateway failed to start')
    for path, expected in protected.items():
        if sha(path) != expected:
            raise RuntimeError('Protected file changed concurrently: ' + path)
    if run('systemctl', 'show', 'ssh.service', '-p', 'MainPID,ActiveState') != ssh_before:
        raise RuntimeError('SSH process changed concurrently')
    if run('docker', 'inspect', '--format', '{{.Name}} {{.Id}} {{.State.StartedAt}}',
           'list94-web-1', 'example-site-website', 'list94-db-1') != business_before:
        raise RuntimeError('Business container restarted concurrently')
    if run('ufw', 'status', 'numbered') != ufw_before:
        raise RuntimeError('UFW changed concurrently')
    for cmd, expected in egress_before.items():
        if run(cmd, '-S', 'HR_DIRECT_EGRESS') != expected:
            raise RuntimeError('UID egress policy changed concurrently')
except Exception:
    # Do not reactivate the pre-fix target gate just to restore availability.
    # Keep current sources and DB for diagnosis; stop only this proxy group.
    # The website/SSH/reverse-SSH are independent and remain available.
    run('systemctl', 'stop', 'home-relay-v2-controller.service')
    (base / 'FAILED-CLOSED.txt').write_text('Controller intentionally stopped. Repair current target policy; never restore old credentials or the pre-fix gate. Website and SSH not stopped.\n')
    raise

manifest = {'release': str(base), 'expected': PAYLOAD['expected'], 'installed': PAYLOAD['hashes'],
            'protected': protected, 'password_and_identity_unchanged': access_state() == before,
            'default_limits': limits, 'global_limit_kib_per_direction': 256,
            'ssh_preserved': ssh_before, 'containers_before': containers_before,
            'business_container_start_times_preserved': True,
            'containers_after': run('docker', 'ps', '--format', '{{.Names}} {{.ID}} {{.Status}}'),
            'services_after': run('systemctl', 'show', 'home-relay-v2-controller.service', 'home-relay-web.service', '-p', 'Id,MainPID,ActiveState'),
            'dns_resolution_policy_changed': True,
            'target_policy': 'public numeric targets pinned after resolution for TCP and UDP'}
(base / 'manifest.json').write_text(json.dumps(manifest, indent=2))
print(json.dumps(manifest, ensure_ascii=True))
