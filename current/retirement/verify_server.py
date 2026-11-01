"""Read-only verification after uninstall; preserve unrelated services and data."""
import hashlib,json,pathlib,pwd,subprocess,time,urllib.request,urllib.error
base=pathlib.Path(REMOTE_BASE)
before=json.loads((base/'before.json').read_text());plan=json.loads((base/'plan.json').read_text())
def run(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    return {'rc':p.returncode,'out':p.stdout,'err':p.stderr}
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
r={'owned_paths_remaining':[p for p in plan['owned_paths'] if pathlib.Path(p).exists() or pathlib.Path(p).is_symlink()],
   'remaining_units':run('systemctl','list-unit-files','--no-pager','--no-legend','home-relay*','gost-home*'),
   'listeners':run('ss','-lntup'),'ufw':run('ufw','status','numbered'),
   'iptables4':run('iptables','-S'),'iptables6':run('ip6tables','-S'),
   'containers':run('docker','ps','--format','{{.Names}} {{.Status}}'),
   'ssh_service':run('systemctl','show','ssh.service','-p','Id,MainPID,ActiveState'),
   'admin_ssh_options_preserved':run('/usr/sbin/sshd','-T','-C','user=admin,host=localhost,addr=127.0.0.1')['out']==before['admin_ssh_options'],
   'homepage_unchanged':sha('/opt/1panel/www/sites/example.invalid/index/index.html')==before['homepage_sha256'],
   'business_containers_preserved':run('docker','inspect','--format','{{.Name}} {{.Id}} {{.State.StartedAt}}','list94-web-1','example-site-website','list94-db-1')['out']==before['containers'],
   'nginx_test':run('docker','exec','1Panel-openresty-KEVH','nginx','-t'),'ssh_test':run('/usr/sbin/sshd','-t'),
   'retained_accounts':[],'http':{}}
for name in plan['static_users']:
    try:user=pwd.getpwnam(name)
    except KeyError:continue
    # Never emit hashes from shadow.
    shadow=run('getent','shadow',name)['out'].strip().split(':')
    r['retained_accounts'].append({'name':name,'uid':user.pw_uid,'shell':user.pw_shell,
        'password_locked':len(shadow)>1 and shadow[1].startswith(('!','*')),
        'expired':len(shadow)>7 and bool(shadow[7]) and int(shadow[7])<int(time.time()/86400),
        'processes':run('ps','-u',str(user.pw_uid),'-o','pid,comm,cgroup','--no-headers')['out']})
for path in ['/','/relay-admin/','/__home_relay_v2/register','/__home_relay_v2/poll','/tools/image-lab/']:
    try:
        req=urllib.request.Request('https://relay.example.invalid'+path,data=b'{}' if path.startswith('/__') else None,headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=12) as result:r['http'][path]=result.status
    except urllib.error.HTTPError as e:r['http'][path]=e.code
r['management_ssh_preserved']=r['ssh_service']['out']==before['ssh_service']
r['relay_route_references_absent']=not any(x in pathlib.Path('/opt/1panel/www/sites/example-site/public-routes.conf').read_text() for x in ['home-relay','home_relay','relay-admin'])
r['ssh_project_includes_absent']=not any(x in pathlib.Path('/etc/ssh/sshd_config').read_text() for x in ['home-relay','gost-home'])
assert not r['owned_paths_remaining'] and not r['remaining_units']['out']
assert '24443' not in r['ufw']['out'] and 'HR_DIRECT_EGRESS' not in r['iptables4']['out'] and 'HR_DIRECT_EGRESS' not in r['iptables6']['out']
assert all(r[k] for k in ['admin_ssh_options_preserved','homepage_unchanged','business_containers_preserved','management_ssh_preserved','relay_route_references_absent','ssh_project_includes_absent'])
assert all(a['expired'] and a['password_locked'] and a['shell']=='/usr/sbin/nologin' for a in r['retained_accounts'])
assert r['http']['/']==200 and r['http']['/tools/image-lab/']==200
assert r['http']['/relay-admin/'] in [404,410] and r['http']['/__home_relay_v2/poll'] in [404,410]
print(json.dumps(r))
