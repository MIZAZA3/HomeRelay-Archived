"""One-time source-only stability update; no DB/settings/website migration."""
import base64,datetime,hashlib,io,json,os,pathlib,shutil,sqlite3,subprocess,tarfile,time

def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=25)
    if p.returncode:raise RuntimeError('Failed '+args[0]+': '+p.stderr[-300:])
    return p.stdout
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

os.umask(0o077)
for p,h in PAYLOAD['expected'].items():
    if sha(p)!=h:raise RuntimeError('Concurrent source change: '+p)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
base=pathlib.Path('/var/backups/home-relay-stability')/stamp;base.mkdir(parents=True,mode=0o700)
for p in PAYLOAD['expected']:
    target=base/'before'/p.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD['archive'])),mode='r:gz') as stream:stream.extractall(base/'source',filter='data')
for src,dst in PAYLOAD['mapping'].items():
    if sha(base/'source'/src)!=PAYLOAD['hashes'][dst]:raise RuntimeError('Staged digest mismatch')
run('python3','-m','compileall','-q',str(base/'source/server'))
protected_paths=['/etc/home-relay-v2/access.json','/etc/home-relay-web/web.json','/etc/ssh/home-relay-v2.inc',
                 '/etc/systemd/system/home-relay-v2-controller.service','/etc/systemd/system/home-relay-web.service',
                 '/opt/home-relay-v2/node_limits.py','/opt/home-relay-v2/credential_admin.py','/opt/home-relay-v2/ssh_authorize.py',
                 '/usr/local/sbin/home-relay-direct-firewall.py']
protected={p:sha(p) for p in protected_paths}
website_paths=['/opt/1panel/www/sites/example.invalid/index/index.html','/opt/1panel/www/sites/example-site/public-routes.conf']
website_before={p:sha(p) for p in website_paths}
services_before=run('systemctl','show','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')
containers_before=run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1')
firewall_before={'ufw':run('ufw','status','numbered'),'ipv4':run('iptables','-S','HR_DIRECT_EGRESS'),'ipv6':run('ip6tables','-S','HR_DIRECT_EGRESS')}
database='/var/lib/home-relay-v2/nodes.sqlite3'
def data_state():
    with sqlite3.connect(database) as db:
        return {'access':db.execute('SELECT * FROM node_access ORDER BY node_id').fetchall(),
                'history':db.execute('SELECT * FROM node_password_history ORDER BY node_id,digest').fetchall(),
                'limits':db.execute('SELECT * FROM node_limits ORDER BY node_id').fetchall(),
                'identity':db.execute('SELECT id,slot,state,secret_hash,pubkey FROM nodes ORDER BY id').fetchall()}

# Only the HomeRelay process group restarts. Active proxy streams reconnect;
# management SSH and the friend's reverse-SSH process are not restarted.
run('systemctl','stop','home-relay-v2-controller.service')
try:
    before=data_state()
    with sqlite3.connect(database) as db,sqlite3.connect(base/'nodes.sqlite3') as backup:db.backup(backup)
    for path,expected in PAYLOAD['expected'].items():
        if sha(path)!=expected:raise RuntimeError('Source changed just before install')
    for src,dst in PAYLOAD['mapping'].items():
        target=pathlib.Path(dst);tmp=target.with_name(target.name+'.stability-new')
        tmp.write_bytes((base/'source'/src).read_bytes());os.chmod(tmp,0o644);os.chown(tmp,0,0);tmp.replace(target)
    run('systemctl','start','home-relay-v2-controller.service')
    cfg=json.loads(pathlib.Path('/etc/home-relay-v2/access.json').read_text())
    with sqlite3.connect(database) as db:
        ports=[cfg.get('direct_base_port',24443)+slot for slot, in db.execute('SELECT n.slot FROM nodes n JOIN node_access a ON a.node_id=n.id WHERE n.state="enabled" AND a.mode="password"') if slot in cfg.get('direct_open_slots',[])]
    for _ in range(100):
        time.sleep(.15);tcp=run('ss','-lntH');udp=run('ss','-lnuH')
        if '127.0.0.1:18780' in tcp and all('0.0.0.0:'+str(p) in tcp and '0.0.0.0:'+str(p) in udp for p in ports):break
    else:raise RuntimeError('Expected HomeRelay listeners not ready')
    if data_state()!=before:raise RuntimeError('Concurrent credential/identity/settings update; review before declaring preservation')
    if any(sha(p)!=value for p,value in protected.items()):raise RuntimeError('Protected HomeRelay/SSH configuration changed')
    if run('systemctl','show','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')!=services_before:raise RuntimeError('Protected service restarted concurrently')
    if run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1')!=containers_before:raise RuntimeError('Business container restarted concurrently')
    if run('ufw','status','numbered')!=firewall_before['ufw'] or run('iptables','-S','HR_DIRECT_EGRESS')!=firewall_before['ipv4'] or run('ip6tables','-S','HR_DIRECT_EGRESS')!=firewall_before['ipv6']:raise RuntimeError('Firewall changed concurrently')
except Exception:
    # Current preimage V4.2 already validates/pins public targets and understands
    # encrypted current passwords. Source-only rollback never restores the DB.
    run('systemctl','stop','home-relay-v2-controller.service')
    for path in PAYLOAD['expected']:shutil.copy2(base/'before'/path.lstrip('/'),path)
    run('systemctl','start','home-relay-v2-controller.service')
    raise
with sqlite3.connect(database) as db:
    nodes=db.execute('SELECT n.id,n.state,n.slot,a.mode,a.revision FROM nodes n JOIN node_access a ON a.node_id=n.id ORDER BY n.id').fetchall()
    limits=db.execute('SELECT node_id,upload_kib,download_kib,revision FROM node_limits ORDER BY node_id').fetchall()
manifest={'release':str(base),'expected':PAYLOAD['expected'],'installed':PAYLOAD['hashes'],'protected':protected,
          'password_identity_limits_history_unchanged':data_state()==before,'nodes':nodes,'limits':limits,
          'website_before':website_before,'website_after':{p:sha(p) for p in website_paths},
          'protected_services_preserved':services_before,'business_container_start_times_preserved':True,
          'firewall_unchanged':True,'global_connections':64,'node_connections':32,'global_kib_per_direction':256,
          'dns_workers':4,'dns_pending_names':64,'dns_names_coalesced':True,'udp_frame_idle_seconds':180,'udp_partial_frame_seconds':15,'ss_udp_ttl_seconds':120,
          'exit_dns_experiment_deployed':False,'services_after':run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')}
(base/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest,ensure_ascii=True))
