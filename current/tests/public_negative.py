import contextlib,json,pathlib,socket,subprocess,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
# Negative checks must not be skipped because an unrelated IP-check site fails.
import public_transport as p
result={}
for name,host,port in [('server-admin','203.0.113.20',22),('loopback','127.0.0.1',22),('cloud-metadata','169.254.169.254',80),('aliyun-metadata','100.100.100.200',80)]:
    s=None
    try:
        s,_=p.socks(1,host,port);s.settimeout(4);s.sendall(b'HR4-BLOCK-TEST\r\n');data=s.recv(512)
        result[name]=not data
    except (OSError,AssertionError):result[name]=True
    finally:
        if s:s.close()
cfgpath=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/private/sing-box.json')
cfg=json.loads(cfgpath.read_text());cfg['inbounds'][0]['listen_port']=31990;cfg['outbounds'][0]['password']='invalid-owned-test-password'
wrong=cfgpath.with_name('wrong-password.json');wrong.write_text(json.dumps(cfg),'utf-8')
exe='D:/CodexTools/HomeRelayV3.0.2/Connector/engine/sing-box.exe'
with open(cfgpath.with_name('negative-client.log'),'wb') as log:
    process=subprocess.Popen([exe,'run','-c',str(wrong)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        for _ in range(50):
            try:s=socket.create_connection(('127.0.0.1',31990),.2);s.close();break
            except OSError:time.sleep(.1)
        original=p.socket.create_connection
        def wrong_target(address,*args,**kwargs):
            if address==('127.0.0.1',31980):address=('127.0.0.1',31990)
            return original(address,*args,**kwargs)
        p.socket.create_connection=wrong_target
        s,_=p.socks(1,'ip77.net',443);s.settimeout(8)
        try:s.sendall(b'owned-test\r\n');result['wrong-SS-password']=not s.recv(64)
        except OSError:result['wrong-SS-password']=True
        finally:s.close()
    finally:
        if 'original' in locals():p.socket.create_connection=original
        process.terminate();process.wait(timeout=10)
print(json.dumps({'public_negative_tests':result}))
if not all(result.values()):sys.exit(1)
