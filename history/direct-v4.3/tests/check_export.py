"""Parse the real export without echoing its password or URI."""
import json,pathlib,yaml
p=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/private')
cred=json.loads((p/'standard-node.json').read_text())
cfg=yaml.safe_load(cred['flclash_yaml'])
assert cfg['tun']['enable'] is False and cfg['allow-lan'] is False
assert cfg['proxies'][0]['type']=='ss' and cfg['proxies'][0]['cipher']=='aes-256-gcm' and cfg['proxies'][0]['udp'] is True
assert cfg['proxies'][0]['server']==cred['server'] and cfg['proxies'][0]['password']==cred['password'] and cfg['proxies'][0]['port']==cred['port']
assert cfg['rules']==['MATCH,HomeRelay'] and 'DIRECT' not in cfg['proxy-groups'][0]['proxies']
assert len(cred['password'])>=32
print(json.dumps({'yaml_valid':True,'node_matches':True,'tun_default_off':True,'allow_lan_off':True,'no_direct_fallback':True}))
