"""Production directional install; PAYLOAD injected by deploy_release.py."""
import base64,datetime,hashlib,io,json,os,pathlib,shutil,sqlite3,subprocess,tarfile,time
def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=45)
    if p.returncode:raise RuntimeError('Command failed: '+args[0]+' '+str(p.returncode)+' '+p.stderr[-600:])
    return p.stdout
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
release=pathlib.Path('/var/backups/home-relay-direct-v4')/stamp
release.mkdir(parents=True,mode=0o700);os.chmod(release.parent,0o700)
for path,expected in PAYLOAD['expected'].items():
    if sha(path)!=expected:raise RuntimeError('Production preimage changed: '+path)
for path in PAYLOAD['mapping'].values():
    if path not in PAYLOAD['expected'] and pathlib.Path(path).exists():raise RuntimeError('New target already exists: '+path)
extra=['/etc/home-relay-v2/access.json','/etc/home-relay-v2/gost.json',
       '/etc/systemd/system/home-relay-v2-proxy.service','/etc/systemd/system/gost-home-relay.service',
       '/etc/ssh/home-relay-v2.inc','/etc/ssh/home-relay-publisher.inc',
       '/opt/1panel/www/sites/example-site/public-routes.conf']
before={}
for path in list(PAYLOAD['expected'])+extra:
    p=pathlib.Path(path)
    if not p.exists():continue
    dst=release/'before'/path.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copy2(p,dst)
    before[path]=sha(p)
with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db,sqlite3.connect(release/'nodes.sqlite3') as backup:db.backup(backup)
(release/'iptables-before.txt').write_text(run('iptables-save'))
(release/'ip6tables-before.txt').write_text(run('ip6tables-save'))
(release/'ufw-before.txt').write_text(run('ufw','status','numbered'))
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD['archive'])),mode='r:gz') as t:t.extractall(release/'source',filter='data')
for src,dst in PAYLOAD['mapping'].items():
    if sha(release/'source'/src)!=PAYLOAD['hashes'][dst]:raise RuntimeError('Source hash mismatch')
run('python3','-m','compileall','-q',str(release/'source/server'))
for name in ['home-relay-v2-controller.service','home-relay-direct-firewall.service']:
    # Requires= helper is not installed yet; verify both together below instead.
    pass
cfgpath=pathlib.Path('/etc/home-relay-v2/access.json');cfg=json.loads(cfgpath.read_text())
with sqlite3.connect('/var/lib/home-relay-v2/nodes.sqlite3') as db:
    rows=db.execute('SELECT slot,state FROM nodes ORDER BY slot').fetchall()
    if not rows or rows[0][0]!=0:raise RuntimeError('Expected published slot zero missing')
cfg.update(direct_open_slots=[0],direct_base_port=24443,direct_server='203.0.113.20')
for key in ['consumer_key','known_hosts','auth_plugin_token']:cfg.pop(key,None)
# Stop only superseded relay data planes, never friend SSH or website containers.
run('systemctl','stop','gost-home-relay.service','home-relay-v2-proxy.service','home-relay-v2-controller.service')
try:
    for src,dst in PAYLOAD['mapping'].items():
        p=pathlib.Path(dst);tmp=p.with_name(p.name+'.hr4-new')
        tmp.write_bytes((release/'source'/src).read_bytes());os.chmod(tmp,0o644);os.chown(tmp,0,0);tmp.replace(p)
    tmp=cfgpath.with_suffix('.json.hr4-new');tmp.write_text(json.dumps(cfg));os.chmod(tmp,0o600);tmp.replace(cfgpath)
    run('systemctl','daemon-reload')
    run('systemd-analyze','verify','/etc/systemd/system/home-relay-v2-controller.service','/etc/systemd/system/home-relay-direct-firewall.service')
    run('systemctl','enable','--now','home-relay-direct-firewall.service')
    # Explicitly re-verify the owner filter when the unit is already active.
    run('python3','/usr/local/sbin/home-relay-direct-firewall.py')
    run('systemctl','start','home-relay-v2-controller.service')
    for _ in range(80):
        time.sleep(.25)
        if '0.0.0.0:24443' in run('ss','-lntH') and '0.0.0.0:24443' in run('ss','-lnuH'):break
    else:raise RuntimeError('New standard TCP/UDP ingress not ready')
    run('systemctl','restart','home-relay-web.service')
except Exception:
    run('systemctl','stop','home-relay-v2-controller.service')
    for path in list(PAYLOAD['expected'])+['/etc/home-relay-v2/access.json']:
        shutil.copy2(release/'before'/path.lstrip('/'),path)
    run('systemctl','daemon-reload')
    run('systemctl','start','gost-home-relay.service','home-relay-v2-proxy.service','home-relay-v2-controller.service')
    run('systemctl','restart','home-relay-web.service')
    raise
manifest={'release':str(release),'before':before,'installed':PAYLOAD['hashes'],'phase':'standard-ingress-running; retirement pending public verification'}
(release/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps({'release':str(release),'phase':manifest['phase'],'controller':run('systemctl','show','home-relay-v2-controller.service','-p','MainPID,ActiveState'),'web':run('systemctl','show','home-relay-web.service','-p','MainPID,ActiveState'),'homepage_hash':sha('/opt/1panel/www/sites/example.invalid/index/index.html')}))
