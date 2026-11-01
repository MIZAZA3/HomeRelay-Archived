"""Remove only the previously inventoried HomeRelay installation.
Requires a verified local copy of the private backup; no website/database reset.
"""
import hashlib,json,os,pathlib,pwd,shutil,subprocess,time,urllib.request,urllib.error

def run(*args,check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if check and p.returncode:raise RuntimeError(args[0]+': '+p.stderr[-400:])
    return p.stdout
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
base=pathlib.Path(REMOTE_BASE)
assert base.parent==pathlib.Path('/var/backups/home-relay-retirement')
plan=json.loads((base/'plan.json').read_text())
before=json.loads((base/'before.json').read_text())
assert sha(plan['archive'])==VERIFIED_BACKUP_SHA256
units=plan['units']
for unit in units:
    assert run('systemctl','is-active',unit,check=False).strip() not in ('active','activating')
    for root in ['/usr/lib/systemd/system','/lib/systemd/system']:
        assert not (pathlib.Path(root)/unit).exists(),'Unexpected vendor unit; inventory it before removal'

routes=pathlib.Path('/opt/1panel/www/sites/example-site/public-routes.conf')
sshd=pathlib.Path('/etc/ssh/sshd_config')
limit=pathlib.Path('/opt/1panel/www/conf.d/00-home-relay-web-limits.conf')
route_before=routes.read_bytes();ssh_before=sshd.read_bytes()
admin_before=run('/usr/sbin/sshd','-T','-C','user=admin,host=localhost,addr=127.0.0.1')
ssh_service=run('systemctl','show','ssh.service','-p','Id,MainPID,ActiveState')
route_owned={
 'include /www/sites/example-site/home-relay-v2.conf;',
 'include /www/sites/example-site/home-relay-admin.conf;',
 '# HomeRelay V2 isolated enrollment endpoint',
 '# HomeRelay V2 independent HTTPS administration gateway',
 '# HomeRelay legacy receiver exchange retired (Direct V4).'}
route_after=b''.join(line for line in route_before.splitlines(keepends=True) if line.decode().strip() not in route_owned)
ssh_owned={'Include /etc/ssh/home-relay-v2.inc','Include /etc/ssh/home-relay-publisher.inc'}
ssh_after=b''.join(line for line in ssh_before.splitlines(keepends=True) if line.decode().strip() not in ssh_owned)
assert route_before!=route_after and ssh_before!=ssh_after
(base/'public-routes.detachment-before').write_bytes(route_before)
(base/'sshd_config.detachment-before').write_bytes(ssh_before)
limits_moved=False
try:
    assert routes.read_bytes()==route_before and sshd.read_bytes()==ssh_before,'Concurrent shared config update'
    routes.write_bytes(route_after);sshd.write_bytes(ssh_after)
    if limit.exists():limit.rename(base/'detached-nginx-limits.conf');limits_moved=True
    run('docker','exec','1Panel-openresty-KEVH','nginx','-t')
    run('/usr/sbin/sshd','-t')
    assert run('/usr/sbin/sshd','-T','-C','user=admin,host=localhost,addr=127.0.0.1')==admin_before,'Admin SSH options changed'
except Exception:
    # Restore only our just-written preimages, never a stale entire website.
    if routes.read_bytes()==route_after:routes.write_bytes(route_before)
    if sshd.read_bytes()==ssh_after:sshd.write_bytes(ssh_before)
    if limits_moved:(base/'detached-nginx-limits.conf').rename(limit)
    raise
run('docker','exec','1Panel-openresty-KEVH','nginx','-s','reload')
run('systemctl','reload','ssh.service')
assert run('systemctl','show','ssh.service','-p','Id,MainPID,ActiveState')==ssh_service

# Remove only the two project ingress rules. Never disable/reset UFW.
for proto in ['tcp','udp']:run('ufw','--force','delete','allow','24443/'+proto)
for binary in ['iptables','ip6tables']:
    rule=['OUTPUT','-m','owner','--uid-owner','996','-j','HR_DIRECT_EGRESS']
    while subprocess.run([binary,'-C',*rule],capture_output=True).returncode==0:run(binary,'-D',*rule)
    rules=run(binary,'-S')
    assert not any(line.endswith(' -j HR_DIRECT_EGRESS') for line in rules.splitlines()),'Unexpected external project-chain reference'
    if '-N HR_DIRECT_EGRESS' in rules:run(binary,'-F','HR_DIRECT_EGRESS');run(binary,'-X','HR_DIRECT_EGRESS')

fixed={
 '/opt/home-relay-v2','/opt/home-relay-web','/opt/gost-home-relay',
 '/etc/home-relay-v2','/etc/home-relay-web','/etc/gost-home-relay','/var/lib/home-relay-v2',
 '/etc/ssh/home-relay-v2.inc','/etc/ssh/home-relay-publisher.inc',
 '/usr/local/sbin/home-relay-direct-firewall.py',
 '/opt/1panel/www/sites/example-site/home-relay-v2.conf',
 '/opt/1panel/www/sites/example-site/home-relay-admin.conf',
 '/opt/1panel/www/conf.d/00-home-relay-web-limits.conf','/tmp/gost-home-relay-stage'}
def allowed(p):
    if str(p) in fixed:return True
    if p.parent==pathlib.Path('/var/backups'):
        return p.name.startswith(('home-relay','gost-home')) and p.name!='home-relay-retirement'
    if p.parent in map(pathlib.Path,['/etc/systemd/system','/usr/local/bin','/etc/ssh/authorized_keys']):
        return p.name.startswith(('home-relay','gost-home'))
    return (p.parent==pathlib.Path('/run') and p.name.startswith('home-relay-v4-test-')) or (p.parent==pathlib.Path('/tmp') and p.name.startswith('hr4-fixture-'))
removed=[]
for value in plan['owned_paths']:
    p=pathlib.Path(value)
    assert p.is_absolute() and '..' not in p.parts and allowed(p),'Refusing unowned path '+value
    if p.is_symlink() or p.is_file():p.unlink();removed.append(value)
    elif p.exists():shutil.rmtree(p);removed.append(value)
run('systemctl','daemon-reload')
run('systemctl','reset-failed',*units,check=False)

accounts=[]
for name in plan['static_users']:
    assert name in ['gost-home-auto','gost-home-v2-client','gost-home-publisher','home-relay-v2']
    try:user=pwd.getpwnam(name)
    except KeyError:continue
    assert user.pw_dir=='/nonexistent' and user.pw_shell=='/usr/sbin/nologin'
    # No -r and no process kill. An old UID may also be a live Docker UID.
    result=subprocess.run(['userdel',name],capture_output=True,text=True)
    accounts.append({'name':name,'removed':result.returncode==0,'rc':result.returncode})
    if result.returncode:
        run('usermod','--expiredate','1970-01-02',name)
        run('usermod','--lock',name)
for name in ['home-relay-v2','gost-home-auto','gost-home-v2-client','gost-home-publisher']:
    run('groupdel',name,check=False)
report={'base':str(base),'removed_paths':removed,'accounts':accounts,
 'routes_after_sha256':sha(routes),'ssh_config_after_sha256':sha(sshd),
 'admin_ssh_options_preserved':run('/usr/sbin/sshd','-T','-C','user=admin,host=localhost,addr=127.0.0.1')==admin_before,
 'management_ssh_preserved':run('systemctl','show','ssh.service','-p','Id,MainPID,ActiveState')==before['ssh_service'],
 'business_containers_preserved':run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1')==before['containers'],
 'homepage_unchanged':sha('/opt/1panel/www/sites/example.invalid/index/index.html')==before['homepage_sha256'],
 'nginx_test':run('docker','exec','1Panel-openresty-KEVH','nginx','-t'),
 'ssh_test':run('/usr/sbin/sshd','-t'),
 'remaining_units':run('systemctl','list-unit-files','--no-pager','--no-legend','home-relay*','gost-home*',check=False),
 'listeners':run('ss','-lntup'),'ufw':run('ufw','status','numbered'),
 'iptables4':run('iptables','-S'),'iptables6':run('ip6tables','-S'),
 'containers':run('docker','ps','--format','{{.Names}} {{.Status}}')}
assert all(report[k] for k in ['admin_ssh_options_preserved','management_ssh_preserved','business_containers_preserved','homepage_unchanged'])
(base/'removal-report.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
