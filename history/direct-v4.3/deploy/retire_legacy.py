"""After verified public SS TCP/UDP, retire only obsolete relay authorization."""
import hashlib,json,os,pathlib,shutil,subprocess,time
BASE=pathlib.Path('/var/backups/home-relay-direct-v4/20261031T194807Z')
manifest=json.loads((BASE/'manifest.json').read_text())
def run(*a,check=True):
 p=subprocess.run(a,capture_output=True,text=True,timeout=40)
 if check and p.returncode:raise RuntimeError(a[0]+': '+p.stderr[-800:])
 return p.stdout
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def backup(path):
 dst=BASE/'retirement-before'/path.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copy2(path,dst)
 return pathlib.Path(path).read_text()
assert '0.0.0.0:24443' in run('ss','-lntH') and '0.0.0.0:24443' in run('ss','-lnuH')
paths=['/etc/ssh/home-relay-v2.inc','/opt/1panel/www/sites/example-site/public-routes.conf']
for path in paths:
 assert sha(path)==manifest['before'][path], 'Concurrent modification: '+path
inc=paths[0];old=backup(inc);friend=old.split('Match User gost-home-v2-client')[0]
client=old[len(friend):]
client=client.replace('AuthorizedKeysFile /etc/ssh/home-relay-v2-client.authorized_keys','AuthorizedKeysFile none').replace('AllowTcpForwarding local','AllowTcpForwarding no')
client='\n'.join(' PermitOpen none' if line.strip().startswith('PermitOpen ') else line for line in client.splitlines())+'\n'
assert friend==(friend+client).split('Match User gost-home-v2-client')[0]
publisher='/etc/ssh/home-relay-publisher.inc';oldpub=backup(publisher)
newpub=oldpub.replace('AuthorizedKeysFile /etc/ssh/gost-home-publisher.authorized_keys','AuthorizedKeysFile none').replace('AllowTcpForwarding remote','AllowTcpForwarding no').replace('PermitListen 127.0.0.1:19080','PermitListen none')
pathlib.Path(inc).write_text(friend+client);pathlib.Path(publisher).write_text(newpub)
try:run('/usr/sbin/sshd','-t')
except Exception:
 pathlib.Path(inc).write_text(old);pathlib.Path(publisher).write_text(oldpub);raise
run('systemctl','reload','ssh.service')
# Target only the two superseded proxy accounts, never admin or gost-home-auto.
for user in ['gost-home-v2-client','gost-home-publisher']:
 run('pkill','-TERM','-u',user,'-x','sshd',check=False)
route=paths[1];text=backup(route)
line='# HomeRelay V3 independent password exchange\ninclude /www/sites/example-site/home-relay-v3-consumer.conf;'
assert text.count(line)==1
pathlib.Path(route).write_text(text.replace(line,'# HomeRelay legacy receiver exchange retired (Direct V4).'))
try:run('docker','exec','1Panel-openresty-KEVH','nginx','-t')
except Exception:pathlib.Path(route).write_text(text);raise
run('docker','exec','1Panel-openresty-KEVH','nginx','-s','reload')
retired=BASE/'retired';retired.mkdir(mode=0o700,exist_ok=True)
files=['/etc/systemd/system/gost-home-relay.service','/etc/systemd/system/home-relay-v2-proxy.service',
       '/etc/home-relay-v2/gost.json','/etc/ssh/home-relay-v2-client.authorized_keys',
       '/etc/ssh/gost-home-publisher.authorized_keys',
       '/opt/1panel/www/sites/example-site/home-relay-v3-consumer.conf']
for unit in ['gost-home-relay.service','home-relay-v2-proxy.service']:run('systemctl','disable','--now',unit)
for f in files:
 p=pathlib.Path(f)
 if p.exists():
  dst=retired/f.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700);p.rename(dst)
for unit in ['gost-home-relay.service','home-relay-v2-proxy.service']:run('systemctl','mask',unit)
run('systemctl','daemon-reload')
run('ufw','allow','proto','tcp','from','0.0.0.0/0','to','any','port','24443','comment','HomeRelay SS AEAD TCP')
run('python3','/usr/local/sbin/home-relay-direct-firewall.py')
manifest['phase']='legacy retired; direct SS TCP/UDP verified'
manifest['retired_files']=files
manifest['retirement_hashes']={p:sha(p) for p in [inc,publisher,route]}
(BASE/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps({'phase':manifest['phase'],'retired_files':len(files),'friend_ssh_match_unchanged':True,'homepage_hash':sha('/opt/1panel/www/sites/example.invalid/index/index.html'),'firewall':run('ufw','status','numbered')}))
