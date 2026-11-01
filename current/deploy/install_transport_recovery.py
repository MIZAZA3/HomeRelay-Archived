"""Targeted reverse-SSH recovery update; no credential/DB/site migration."""
import base64,datetime,hashlib,io,json,os,pathlib,shutil,sqlite3,subprocess,tarfile,time

def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=25)
    if p.returncode:raise RuntimeError('Failed '+args[0]+': '+p.stderr[-300:])
    return p.stdout
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def current(p):return sha(p) if pathlib.Path(p).exists() else None

os.umask(0o077)
for p,h in PAYLOAD['expected'].items():
    if current(p)!=h:raise RuntimeError('Concurrent source change: '+p)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
base=pathlib.Path('/var/backups/home-relay-transport-recovery')/stamp;base.mkdir(parents=True,mode=0o700)
for p,h in PAYLOAD['expected'].items():
    if h is None:continue
    target=base/'before'/p.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD['archive'])),mode='r:gz') as stream:stream.extractall(base/'source',filter='data')
for src,dst in PAYLOAD['mapping'].items():
    if sha(base/'source'/src)!=PAYLOAD['hashes'][dst]:raise RuntimeError('Staged digest mismatch')
run('python3','-m','compileall','-q',str(base/'source/server'))
# Mandatory runtime tests BEFORE stopping or changing any production service.
run('python3',str(base/'source/tests/lifecycle_unit.py'))
run('python3',str(base/'source/tests/transport_health_unit.py'))
protected_paths=['/etc/home-relay-v2/access.json','/etc/home-relay-web/web.json','/etc/ssh/home-relay-v2.inc',
                 '/etc/systemd/system/home-relay-v2-controller.service','/etc/systemd/system/home-relay-web.service',
                 '/opt/home-relay-v2/direct_proxy.py','/opt/home-relay-v2/node_limits.py','/opt/home-relay-v2/credential_admin.py','/opt/home-relay-v2/ssh_authorize.py',
                 '/usr/local/sbin/home-relay-direct-firewall.py']
protected={p:sha(p) for p in protected_paths}
ssh_path=pathlib.Path('/etc/ssh/home-relay-v2.inc')
ssh_before=ssh_path.read_bytes()
assert sha(ssh_path)==PAYLOAD['ssh_expected'],'Concurrent SSH include update'
(base/'ssh-include.before').write_bytes(ssh_before)
def effective(user):return run('/usr/sbin/sshd','-T','-C','user='+user+',host=localhost,addr=127.0.0.1')
admin_before=effective('admin');retired_before=effective('gost-home-v2-client');home_before=effective('gost-home-auto')
main_ssh_pid=run('systemctl','show','ssh.service','-p','MainPID','--value').strip()
# Pin only the non-root restricted child owning this node's loopback listener.
import pwd,re,signal
home_uid=pwd.getpwnam('gost-home-auto').pw_uid
listeners=run('ss','-lntpH','sport = :22000')
recycle=[]
for pid in set(re.findall(r'pid=(\d+)',listeners)):
    p=pathlib.Path('/proc')/pid
    try:
        uid=[int(x) for x in next(x for x in (p/'status').read_text().splitlines() if x.startswith('Uid:')).split()[1:]]
        cmd=(p/'cmdline').read_bytes()
        if all(x==home_uid for x in uid) and b'sshd: gost-home-auto' in cmd:
            recycle.append((int(pid),(p/'stat').read_text().rsplit(')',1)[1].split()[19]))
    except (OSError,StopIteration):pass
assert len(recycle)<=1,'Ambiguous restricted reverse-forward owner; refusing to signal'
ssh_changed=False

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
    text=ssh_before.decode('utf-8');first,rest=text.split('Match User gost-home-v2-client',1)
    assert first.count('ClientAliveInterval 30')==1 and first.startswith('Match User gost-home-auto')
    first=first.replace('ClientAliveInterval 30','ClientAliveInterval 15',1)
    candidate=(first+'Match User gost-home-v2-client'+rest).encode()
    ssh_path.write_bytes(candidate);os.chmod(ssh_path,0o644);ssh_changed=True
    run('/usr/sbin/sshd','-t')
    assert effective('admin')==admin_before,'Admin SSH effective options changed'
    assert effective('gost-home-v2-client')==retired_before,'Retired SSH options changed'
    assert effective('gost-home-auto')==home_before.replace('clientaliveinterval 30\n','clientaliveinterval 15\n'),'Unexpected restricted SSH option change'
    protected[str(ssh_path)]=sha(ssh_path)
    run('systemctl','reload','ssh.service')
    assert run('systemctl','show','ssh.service','-p','MainPID','--value').strip()==main_ssh_pid,'SSH master unexpectedly changed'

    with sqlite3.connect(database) as db,sqlite3.connect(base/'nodes.sqlite3') as backup:db.backup(backup)
    for path,expected in PAYLOAD['expected'].items():
        if current(path)!=expected:raise RuntimeError('Source changed just before install')
    for src,dst in PAYLOAD['mapping'].items():
        target=pathlib.Path(dst);tmp=target.with_name(target.name+'.lifecycle-new')
        tmp.write_bytes((base/'source'/src).read_bytes());os.chmod(tmp,0o644);os.chown(tmp,0,0);tmp.replace(target)
    run('systemctl','start','home-relay-v2-controller.service')
    cfg=json.loads(pathlib.Path('/etc/home-relay-v2/access.json').read_text())
    with sqlite3.connect(database) as db:
        ports=[cfg.get('direct_base_port',24443)+slot for slot, in db.execute('SELECT n.slot FROM nodes n JOIN node_access a ON a.node_id=n.id WHERE n.state="enabled" AND a.mode="password"') if slot in cfg.get('direct_open_slots',[])]
    for _ in range(100):
        time.sleep(.15);tcp=run('ss','-lntH');udp=run('ss','-lnuH')
        if '127.0.0.1:18780' in tcp and all('0.0.0.0:'+str(p) in tcp and '0.0.0.0:'+str(p) in udp for p in ports):break
    else:raise RuntimeError('Expected HomeRelay listeners not ready')
    recycled=[]
    for pid,start in recycle:
        p=pathlib.Path('/proc')/str(pid)
        try:
            same=(p/'stat').read_text().rsplit(')',1)[1].split()[19]==start
            uid=[int(x) for x in next(x for x in (p/'status').read_text().splitlines() if x.startswith('Uid:')).split()[1:]]
            if same and all(x==home_uid for x in uid) and b'sshd: gost-home-auto' in (p/'cmdline').read_bytes():
                os.kill(pid,signal.SIGTERM);recycled.append(pid)
        except (ProcessLookupError,FileNotFoundError):pass
    if data_state()!=before:raise RuntimeError('Concurrent credential/identity/settings update; review before declaring preservation')
    if any(sha(p)!=value for p,value in protected.items()):raise RuntimeError('Protected HomeRelay/SSH configuration changed')
    if run('systemctl','show','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')!=services_before:raise RuntimeError('Protected service restarted concurrently')
    if run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1')!=containers_before:raise RuntimeError('Business container restarted concurrently')
    if run('ufw','status','numbered')!=firewall_before['ufw'] or run('iptables','-S','HR_DIRECT_EGRESS')!=firewall_before['ipv4'] or run('ip6tables','-S','HR_DIRECT_EGRESS')!=firewall_before['ipv6']:raise RuntimeError('Firewall changed concurrently')
except Exception:
    # Current preimage already validates/pins public targets and understands
    # encrypted current passwords. Source-only rollback never restores the DB.
    run('systemctl','stop','home-relay-v2-controller.service')
    for path,expected in PAYLOAD['expected'].items():
        if expected is not None:shutil.copy2(base/'before'/path.lstrip('/'),path)
        elif current(path)==PAYLOAD['hashes'][path]:pathlib.Path(path).unlink()
    if ssh_changed:
        ssh_path.write_bytes(ssh_before);os.chmod(ssh_path,0o644);run('/usr/sbin/sshd','-t');run('systemctl','reload','ssh.service')
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
          'exit_dns_experiment_deployed':False,'completed_dns_reclaim_on_pressure':True,'explicit_db_close':True,'wal_anchor':True,'private_header_only_diagnostics':True,'reverse_auth_health_check':True,'health_probe_concurrency':4,'health_probe_timeout':6,'health_failures_before_recovery':3,'quiet_recovery_seconds':60,'ssh_keepalive_interval':15,'ssh_keepalive_count':2,'admin_ssh_effective_options_preserved':True,'retired_ssh_options_preserved':True,'restricted_child_sessions_recycled':recycled,'ssh_include_before_sha256':hashlib.sha256(ssh_before).hexdigest(),'services_after':run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','ssh.service','-p','Id,MainPID,ActiveState')}
(base/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest,ensure_ascii=True))
