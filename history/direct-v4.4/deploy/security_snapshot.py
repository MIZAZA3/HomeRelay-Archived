"""Read-only production security inventory; never print secret file contents."""
import hashlib,json,os,pathlib,stat,subprocess
def run(*args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=20)
 return {'rc':p.returncode,'output':p.stdout,'error':p.stderr}
r={'files':{}}
for name in ['/etc/home-relay-v2/access.json','/etc/home-relay-web/web.json','/var/lib/home-relay-v2',
             '/var/lib/home-relay-v2/nodes.sqlite3','/var/lib/home-relay-v2/direct-api.sock',
             '/opt/home-relay-v2/controller.py','/opt/home-relay-v2/direct_proxy.py',
             '/opt/home-relay-v2/credential_admin.py','/opt/home-relay-v2/ssh_authorize.py',
             '/usr/local/sbin/home-relay-direct-firewall.py']:
 p=pathlib.Path(name)
 if p.exists():
  s=p.stat();r['files'][name]={'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode))}
r['services']=run('systemctl','show','home-relay-v2-controller.service','home-relay-web.service','home-relay-direct-firewall.service','-p','Id,MainPID,ActiveState,User,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CPUQuotaPerSecUSec,MemoryMax,TasksMax')
r['listeners']=run('ss','-lntup')
r['ufw']=run('ufw','status','numbered')
r['egress_ipv4']=run('iptables','-S','HR_DIRECT_EGRESS');r['egress_ipv6']=run('ip6tables','-S','HR_DIRECT_EGRESS')
r['packages']=run('dpkg-query','-W','-f=${Package} ${Version}\n','python3-cryptography','python3.12','openssl')
r['versions']=run('python3','-c','import ssl,cryptography;print(ssl.OPENSSL_VERSION);print(cryptography.__version__)')
pid=subprocess.check_output(['systemctl','show','home-relay-v2-controller.service','-p','MainPID','--value'],text=True).strip()
r['controller_process_security']=[line for line in pathlib.Path('/proc/'+pid+'/status').read_text().splitlines() if line.startswith(('Uid:','Gid:','CapEff:','NoNewPrivs:','Seccomp:'))]
print(json.dumps(r,ensure_ascii=True))
