"""Keep live node credentials in an ACL-protected private work directory only."""
import json,pathlib,sys
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
script='''import json,sys
sys.path.insert(0,"/opt/home-relay-v2")
import controller as c
n=c.node("00000000000000000000000000000001");a=c.access(n["id"])
assert a["mode"]=="password" and n["slot"]==0
print(json.dumps(c.direct_proxy.credential(c.CFG,c.derive,n,a)))
'''
cred=json.loads(ssh('sudo -n python3 -',script.encode()))
p=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/private/standard-node.json');p.write_text(json.dumps(cred),'utf-8')
config={'log':{'level':'fatal','output':'D:/CodexWork/HomeRelayDirectV4/private/sing-box.log'},
        'inbounds':[{'type':'socks','tag':'test-in','listen':'127.0.0.1','listen_port':31980}],
        'outbounds':[{'type':'shadowsocks','tag':'test-node','server':cred['server'],'server_port':cred['port'],'method':cred['method'],'password':cred['password']}],
        'route':{'final':'test-node'}}
(p.parent/'sing-box.json').write_text(json.dumps(config),'utf-8')
(p.parent/'flclash-test.yaml').write_text(cred['flclash_yaml'],'utf-8')
print('Private SS test profile prepared; no credentials printed.')
