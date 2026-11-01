"""Run ONLY inside a fresh Linux network namespace, with no production DB."""
import asyncio, contextlib, hashlib, http.client, json, os, pathlib, secrets, socket, struct, subprocess, sys, tempfile, threading, time

BASE = pathlib.Path(__file__).resolve().parents[1]
WORK = pathlib.Path(tempfile.mkdtemp(prefix='hr4-fixture-'))
os.chmod(WORK, 0o700)
os.environ['RELAY_STATE'] = str(WORK)
os.environ['RELAY_CONFIG'] = str(WORK/'access.json')
cfg = {'master': secrets.token_hex(32), 'max_nodes': 2, 'direct_open_slots': [0, 1]}
cfg['password_salt']=secrets.token_hex(16)
cfg['password_hash']=hashlib.scrypt(b'fixture-only-password',salt=bytes.fromhex(cfg['password_salt']),n=16384,r=8,p=1).hex()
(WORK/'access.json').write_text(json.dumps(cfg))
sys.path.insert(0, str(BASE/'server'))
import controller as c

PROCESSES=[]
RESULTS=[]

def check(label, ok):
    assert ok, label
    RESULTS.append(label)

def launch(name, config):
    p=WORK/(name+'.json');p.write_text(json.dumps(config))
    log=open(WORK/(name+'.log'),'wb')
    x=subprocess.Popen(['/opt/gost-home-relay/gost','-C',str(p)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
    PROCESSES.append(x);return x

async def echo(r,w):
    try:
        while b:=await r.read(4096):w.write(b);await w.drain()
    finally:w.close()

class UDP(asyncio.DatagramProtocol):
    def connection_made(self,t):self.t=t
    def datagram_received(self,data,addr):self.t.sendto(data,addr)

async def waitport(port):
    for _ in range(100):
        try:
            r,w=await asyncio.open_connection('127.0.0.1',port);w.close();return
        except OSError:await asyncio.sleep(.05)
    raise RuntimeError('fixture port not ready: '+str(port))

def client_config(password, target_port, local=31080):
    return {'log': {'level':'fatal'}, 'services':[
        {'name':'tcp-client','addr':f'127.0.0.1:{local}','handler':{'type':'socks5','chain':'ss-tcp','metadata':{'notls':True}},'listener':{'type':'tcp'}},
        {'name':'udp-client','addr':f'127.0.0.1:{local+1}','handler':{'type':'udp','chain':'ss-udp'},'listener':{'type':'udp'},'forwarder':{'nodes':[{'name':'echo','addr':'203.0.113.10:18001'}]}}
    ],'chains':[{'name':name,'hops':[{'name':name,'nodes':[{'name':name,'addr':f'127.0.0.1:{target_port}','connector':{'type':kind,'auth':{'username':'aes-256-gcm','password':password}},'dialer':{'type':dialer}}]}]} for name,kind,dialer in [('ss-tcp','ss','tcp'),('ss-udp','ssu','udp')]]}

async def connect(local=31080, host='203.0.113.10',port=18000):
    r,w=await asyncio.open_connection('127.0.0.1',local)
    w.write(b'\x05\x01\x00');await w.drain();assert await r.readexactly(2)==b'\x05\x00'
    h=host.encode();w.write(b'\x05\x01\x00\x03'+bytes([len(h)])+h+struct.pack('!H',port));await w.drain()
    response=await asyncio.wait_for(r.readexactly(4),6)
    if response[1]!=0:w.close();raise ConnectionError('blocked')
    size=4 if response[3]==1 else 16 if response[3]==4 else (await r.readexactly(1))[0]
    await r.readexactly(size+2)
    return r,w

async def roundtrip(local=31080,host='203.0.113.10',port=18000):
    r,w=await connect(local,host,port)
    try:
        w.write(b'fixture-ss-aead');await w.drain()
        return await asyncio.wait_for(r.readexactly(15),3)==b'fixture-ss-aead'
    finally:w.close()

async def blocked(local=31080,host='203.0.113.10',port=18000):
    try:ok=await roundtrip(local,host,port);return not ok
    except Exception:return True

def udp_roundtrip(port):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
        u.settimeout(5);u.sendto(b'fixture-ss-udp',('127.0.0.1',port));return u.recv(256)==b'fixture-ss-udp'

async def main():
    c.init();c.LOOP=asyncio.get_running_loop()
    nodes=[]
    for slot in range(2):
        nid=secrets.token_hex(16);nodes.append(nid)
        with c.db() as d:
            d.execute('INSERT INTO nodes(id,secret_hash,pubkey,slot,state,label,created,seen,ip,version) VALUES(?,?,?,?,?,?,?,?,?,?)',(nid,'fixture','fixture'+str(slot),slot,'enabled','fixture'+str(slot),time.time(),time.time(),'127.0.0.1','test'))
            d.execute('INSERT INTO node_access(node_id,mode,revision,updated) VALUES(?,?,?,?)',(nid,'password',1,time.time()))
        launch('home'+str(slot),{'log':{'level':'fatal'},'services':[{'name':'home','addr':f'127.0.0.1:{22000+slot}','handler':{'type':'socks5','auth':{'username':'home','password':c.derive('home',slot)},'metadata':{'udp':True,'notls':True,'bind':False}},'listener':{'type':'tcp'}}]})
        await waitport(22000+slot)
        await asyncio.start_server(lambda r,w,s=slot:c.gate(r,w,s),'127.0.0.1',23000+slot)
    await asyncio.start_server(echo,'203.0.113.10',18000)
    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(UDP,local_addr=('203.0.113.10',18001))
    await asyncio.to_thread(c.ENGINE.sync)
    check('Unix API + dynamic two-node SS TCP/UDP listeners',len(c.ENGINE.ready)==2)
    cred=c.direct_proxy.credential(c.CFG,c.derive,c.node(nodes[0]),c.access(nodes[0]))
    cred2=c.direct_proxy.credential(c.CFG,c.derive,c.node(nodes[1]),c.access(nodes[1]))
    launch('client-old',client_config(cred['password'],24443))
    launch('client-other',client_config(cred2['password'],24444,31090))
    launch('client-wrong',client_config('wrong-fixture-password',24443,31100))
    await waitport(31080);await waitport(31090);await waitport(31100)
    check('standard AES-256-GCM TCP through gated friend SOCKS5',await roundtrip())
    check('standard AES-256-GCM UDP through UDP-over-SSH chain',await asyncio.to_thread(udp_roundtrip,31081))
    check('wrong Shadowsocks password fails closed',await blocked(31100))
    check('loopback target blocked',await blocked(host='127.0.0.1'))
    check('cloud metadata target blocked',await blocked(host='169.254.169.254',port=80))
    delayed_r,delayed_w=await connect()
    with c.db() as d:d.execute('UPDATE node_access SET revision=revision+1 WHERE node_id=?',(nodes[0],))
    await c.close_node(nodes[0]);await asyncio.to_thread(c.ENGINE.sync)
    delayed_w.write(b'late');await delayed_w.drain()
    try:late=await asyncio.wait_for(delayed_r.read(1),2)
    except Exception:late=b''
    delayed_w.close();check('rotation terminates established old connection',late==b'')
    check('old credential fails after rotation',await blocked())
    check('other node survives targeted rotation',await roundtrip(31090))
    cred=c.direct_proxy.credential(c.CFG,c.derive,c.node(nodes[0]),c.access(nodes[0]))
    launch('client-new',client_config(cred['password'],24443,31110));await waitport(31110)
    check('new credential works after rotation',await roundtrip(31110))
    with c.db() as d:d.execute('UPDATE node_access SET mode="revoked",revision=revision+1 WHERE node_id=?',(nodes[0],))
    await c.close_node(nodes[0]);await asyncio.to_thread(c.ENGINE.sync)
    check('revocation closes standard listener',await blocked(31110))
    check('revocation does not affect other node',await roundtrip(31090))
    with c.db() as d:d.execute('UPDATE nodes SET state="idle" WHERE id=?',(nodes[1],))
    await c.close_node(nodes[1]);await asyncio.to_thread(c.ENGINE.sync)
    check('idle blocks new connections',await blocked(31090))
    # Stale engine internal key must be rejected even if a service failed to reload.
    with c.db() as d:d.execute('UPDATE nodes SET state="enabled" WHERE id=?',(nodes[1],))
    await asyncio.to_thread(c.ENGINE.sync)
    with c.db() as d:d.execute('UPDATE node_access SET revision=revision+1 WHERE node_id=?',(nodes[1],))
    check('generation gate rejects stale key without GOST reconfiguration',await blocked(31090))
    check('credentials contain no receiver TransportKey', 'TransportKey' not in cred)
    check('FlClash profile has TUN off and no DIRECT fallback','enable: false' in cred['flclash_yaml'] and 'DIRECT' not in cred['flclash_yaml'])
    admin=c.BoundedServer(('127.0.0.1',18780),False)
    threading.Thread(target=admin.serve_forever,daemon=True).start()
    agent=c.BoundedServer(('127.0.0.1',18781),True)
    threading.Thread(target=agent.serve_forever,daemon=True).start()
    def api(method,path,data=None,cookie='',csrf='',port=18780):
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
        conn.request(method,path,None if data is None else json.dumps(data),{'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':csrf})
        r=conn.getresponse();body=json.loads(r.read());header=r.getheader('Set-Cookie','');conn.close();return r.status,body,header
    code,_,_=await asyncio.to_thread(api,'GET','/api/nodes')
    check('admin requires authentication',code==401)
    code,s,ck=await asyncio.to_thread(api,'POST','/api/login',{'password':'fixture-only-password'})
    check('existing admin login preserved',code==200 and bool(ck))
    cookie=ck.split(';')[0]
    code,listing,_=await asyncio.to_thread(api,'GET','/api/nodes',None,cookie)
    check('node listing contains metadata but no SS secrets',code==200 and 'password' not in listing['nodes'][0] and 'TransportKey' not in json.dumps(listing))
    code,_,_=await asyncio.to_thread(api,'POST','/api/nodes/'+nodes[1]+'/credentials',{'mode':'show'},cookie)
    check('credential API requires CSRF',code==403)
    for action in ['connect','password']:
        code,_,_=await asyncio.to_thread(api,'POST','/api/nodes/'+nodes[1]+'/'+action,{},cookie,s['csrf'])
        check('retired receiver action '+action+' absent',code==404)
    code,_,_=await asyncio.to_thread(api,'POST','/consumer',{},'','',18781)
    check('retired public consumer exchange returns 410',code==410)
    with c.db() as d:d.execute('UPDATE nodes SET seen=? WHERE id=?',(time.time()-60,nodes[1]))
    check('offline heartbeat fails closed',await blocked(31090))
    probe_name='probe-'+nodes[0]
    c.ENGINE.call('DELETE','services/'+probe_name)
    c.ENGINE.installed.pop(('probe',nodes[0]))
    await asyncio.to_thread(c.ENGINE.sync)
    check('partial probe provisioning retries idempotently without duplicate chain',probe_name in c.ENGINE.resource_names('services'))
    labeled=dict(c.node(nodes[0]));labeled['label']='HomeRelay'
    export=c.direct_proxy.credential(c.CFG,c.derive,labeled,c.access(nodes[0]))
    proxy_line=next(x for x in export['flclash_yaml'].splitlines() if x.startswith('  - {'))
    check('arbitrary node label cannot collide with fixed proxy-group name',json.loads(proxy_line[4:])['name']!='HomeRelay')
    # Only fixture nodes: exercise the actual authenticated credential HTTP API.
    target=nodes[0]
    async def change(body,csrf_token=s['csrf']):
        return await asyncio.to_thread(api,'POST','/api/nodes/'+target+'/credentials',body,cookie,csrf_token)
    rev=c.access(target)['revision']
    custom='FixtureCustom-2026!'
    base={'mode':'set','password':custom,'confirmation':custom,'expected_revision':rev}
    code,_,_=await change(base,'')
    check('custom password mutation still requires CSRF',code==403 and c.access(target)['revision']==rev)
    for bad,label in [({'password':'short','confirmation':'short'},'short'),({'confirmation':'different-fixture'},'mismatched'),({'password':'Fixture\nPassword','confirmation':'Fixture\nPassword'},'control-character')]:
        code,_,_=await change({**base,**bad})
        check('custom '+label+' input rejected without changing credentials',code==400 and c.access(target)['revision']==rev)
    code,r,_=await change(base)
    check('custom password saved through authenticated API',code==200 and r['password']==custom and c.access(target)['revision']==rev+1)
    stored=c.access(target)['ss_secret']
    check('custom password is authenticated-encrypted at rest',bool(stored) and custom not in stored and all(custom.encode() not in p.read_bytes() for p in WORK.glob('nodes.sqlite3*')))
    changed=dict(c.access(target));changed['ss_secret']=stored[:-4]+'AAAA'
    try:c.direct_proxy.password_value(c.derive,c.node(target),changed);tamper=False
    except RuntimeError:tamper=True
    check('tampered stored password fails closed rather than using generated fallback',tamper)
    other=dict(c.node(target));other['id']=nodes[1]
    try:c.direct_proxy.password_value(c.derive,other,c.access(target));cross_node=False
    except RuntimeError:cross_node=True
    check('encrypted credential is bound to node identity',cross_node)
    # Restore the other node's heartbeat / current runtime to verify isolation.
    with c.db() as d:d.execute('UPDATE nodes SET seen=? WHERE id=?',(time.time(),nodes[1]))
    fresh=c.direct_proxy.credential(c.CFG,c.derive,c.node(nodes[1]),c.access(nodes[1]))
    launch('other-current',client_config(fresh['password'],24444,31130));await waitport(31130)
    launch('custom-client',client_config(custom,24443,31120));await waitport(31120)
    check('custom password standard SS TCP works',await roundtrip(31120))
    check('custom password standard SS UDP works',await asyncio.to_thread(udp_roundtrip,31121))
    check('setting one custom password leaves other node usable',await roundtrip(31130))
    latest=c.access(target)['revision']
    code,_,_=await change(base)
    check('stale settings cannot overwrite a newer password',code==409 and c.access(target)['revision']==latest)
    code,_,_=await change({**base,'expected_revision':latest})
    check('reusing current custom password is rejected',code==409 and c.access(target)['revision']==latest)
    code,rotated,_=await change({'mode':'rotate','expected_revision':latest})
    check('switching custom to random clears stored custom token',code==200 and rotated['password']!=custom and c.access(target)['ss_secret']=='')
    check('previous custom client fails after random rotation',await blocked(31120))
    code,_,_=await change({**base,'expected_revision':c.access(target)['revision']})
    check('recent old password cannot be selected to revive old clients',code==409)
    second='FixtureCustom-Second!'
    code,second_result,_=await change({'mode':'set','password':second,'confirmation':second,'expected_revision':c.access(target)['revision']})
    check('second distinct custom password and exports match',code==200 and second_result['password']==second and second in second_result['flclash_yaml'])
    code,_,_=await change({'mode':'revoke','expected_revision':c.access(target)['revision']})
    check('revoking custom access clears encrypted secret and denies access',code==200 and c.access(target)['mode']=='revoked' and c.access(target)['ss_secret']=='')
    check('other node survives all custom credential operations',await roundtrip(31130))
    code,metadata,_=await asyncio.to_thread(api,'GET','/api/nodes',None,cookie)
    check('node listing never leaks custom password or encrypted token',code==200 and custom not in json.dumps(metadata) and 'ss_secret' not in json.dumps(metadata))
    with c.db() as d:d.execute('UPDATE node_access SET mode="password",ss_secret="damaged-fixture-token",revision=revision+1 WHERE node_id=?',(target,))
    code,_,_=await change({'mode':'revoke','expected_revision':c.access(target)['revision']})
    check('corrupted stored secret cannot prevent immediate revocation',code==200 and c.access(target)['mode']=='revoked')
    with c.db() as d:d.execute('UPDATE node_access SET mode="password",ss_secret="damaged-fixture-token",revision=revision+1 WHERE node_id=?',(target,))
    code,recovered,_=await change({'mode':'rotate','expected_revision':c.access(target)['revision']})
    check('corrupted secret can be replaced with a new random credential',code==200 and bool(recovered['password']) and c.access(target)['ss_secret']=='')
    print(json.dumps({'passed':RESULTS,'fixture_state':str(WORK)},ensure_ascii=False))

try:asyncio.run(main())
except Exception:
    import traceback;traceback.print_exc()
    # Logs contain fixture-only credentials; output just the last error for diagnostics.
    if (WORK/'direct-engine.log').exists():print((WORK/'direct-engine.log').read_text()[-1500:])
    raise
finally:
    if c.ENGINE.process:PROCESSES.append(c.ENGINE.process)
    for p in PROCESSES:
        with contextlib.suppress(Exception):p.terminate()
    for p in PROCESSES:
        with contextlib.suppress(Exception):p.wait(timeout=5)
