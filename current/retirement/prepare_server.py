"""Stop only HomeRelay and build a private, consistent retirement archive.
This is a one-time maintenance script for the inventoried existing installation.
The archive contains secrets: never publish it or include it in a source repo.
"""
import datetime,hashlib,json,os,pathlib,pwd,subprocess,tarfile

def run(*args,check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if check and p.returncode:raise RuntimeError(args[0]+': '+p.stderr[-300:])
    return p.stdout
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
os.umask(0o077)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
base=pathlib.Path('/var/backups/home-relay-retirement')/stamp
base.mkdir(parents=True,mode=0o700)
units=['home-relay-v2-controller.service','home-relay-web.service','home-relay-direct-firewall.service','home-relay-v2-proxy.service','gost-home-relay.service']
users=['gost-home-auto','gost-home-v2-client','gost-home-publisher','home-relay-v2']
routes=pathlib.Path('/opt/1panel/www/sites/example-site/public-routes.conf')
sshd=pathlib.Path('/etc/ssh/sshd_config')
before={'units':run('systemctl','list-unit-files','--no-pager','--no-legend',*units),
        'ssh_service':run('systemctl','show','ssh.service','-p','Id,MainPID,ActiveState'),
        'admin_ssh_options':run('/usr/sbin/sshd','-T','-C','user=admin,host=localhost,addr=127.0.0.1'),
        'containers':run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1'),
        'homepage_sha256':sha('/opt/1panel/www/sites/example.invalid/index/index.html'),
        'routes_sha256':sha(routes),'ssh_config_sha256':sha(sshd),
        'ufw':run('ufw','status','numbered'),'iptables4':run('iptables','-S'),'iptables6':run('ip6tables','-S'),
        'project_users':[{'name':p.pw_name,'uid':p.pw_uid,'gid':p.pw_gid,'home':p.pw_dir,'shell':p.pw_shell} for p in pwd.getpwall() if p.pw_name in users]}
(base/'before.json').write_text(json.dumps(before,indent=2))
(base/'public-routes.before').write_bytes(routes.read_bytes())
(base/'sshd_config.before').write_bytes(sshd.read_bytes())
# Service stop is cgroup-scoped. Never kill a UID wholesale: container processes
# may use the same numeric UID as an old, unprivileged project account.
for unit in units:
    run('systemctl','stop',unit,check=False)
for unit in units[:3]:run('systemctl','disable',unit)
# Expire only static project forwarding accounts while files are archived.
# Never use userdel -r: the dynamic web account has home=/.
for name in users[:3]:
    if any(p['name']==name for p in before['project_users']):run('usermod','--expiredate','1970-01-02',name)
for directory in pathlib.Path('/proc').iterdir():
    if not directory.name.isdigit():continue
    try:
        cmd=(directory/'cmdline').read_bytes()
        if any(cmd.startswith(('sshd: '+name).encode()) for name in users[:3]):
            # Only an exact sshd process title, never a container or SSH master.
            if (directory/'comm').read_text().strip()=='sshd':os.kill(int(directory.name),15)
    except (OSError,ProcessLookupError):pass

paths=[pathlib.Path(p) for p in (
 '/opt/home-relay-v2','/opt/home-relay-web','/opt/gost-home-relay',
 '/etc/home-relay-v2','/etc/home-relay-web','/etc/gost-home-relay','/var/lib/home-relay-v2',
 '/etc/ssh/home-relay-v2.inc','/etc/ssh/home-relay-publisher.inc',
 '/usr/local/sbin/home-relay-direct-firewall.py',
 '/opt/1panel/www/sites/example-site/home-relay-v2.conf',
 '/opt/1panel/www/sites/example-site/home-relay-admin.conf',
 '/opt/1panel/www/conf.d/00-home-relay-web-limits.conf')]
for root in ['/etc/systemd/system','/var/backups','/usr/local/bin','/etc/ssh/authorized_keys']:
    directory=pathlib.Path(root)
    if directory.exists():
        paths.extend(p for p in directory.iterdir() if p.name.startswith(('home-relay','gost-home')) and p.name!='home-relay-retirement')
for root,prefix in [('/run','home-relay-v4-test-'),('/tmp','hr4-fixture-')]:
    paths.extend(p for p in pathlib.Path(root).iterdir() if p.name.startswith(prefix))
if pathlib.Path('/tmp/gost-home-relay-stage').exists():paths.append(pathlib.Path('/tmp/gost-home-relay-stage'))
paths=sorted(set(p for p in paths if p.exists() or p.is_symlink()))
plan={'base':str(base),'archive':str(base/'private-retirement.tar.gz'),'owned_paths':[str(p) for p in paths],
      'units':units,'static_users':[p['name'] for p in before['project_users']],
      'homepage_sha256':before['homepage_sha256'],'routes_sha256':before['routes_sha256'],
      'ssh_config_sha256':before['ssh_config_sha256']}
(base/'plan.json').write_text(json.dumps(plan,indent=2))
with tarfile.open(plan['archive'],'w:gz',compresslevel=3) as archive:
    for p in paths:archive.add(p,arcname=str(p).lstrip('/'),recursive=True)
    for name in ['before.json','plan.json','public-routes.before','sshd_config.before']:
        archive.add(base/name,arcname='retirement-metadata/'+name)
os.chmod(plan['archive'],0o600)
report={'base':str(base),'archive':plan['archive'],'bytes':pathlib.Path(plan['archive']).stat().st_size,
        'sha256':sha(plan['archive']),'owned_path_count':len(paths),'project_services_stopped':True,
        'management_ssh_preserved':run('systemctl','show','ssh.service','-p','Id,MainPID,ActiveState')==before['ssh_service'],
        'business_containers_preserved':run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1')==before['containers']}
(base/'archive-manifest.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
