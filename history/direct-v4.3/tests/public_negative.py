import contextlib,json,pathlib,socket,subprocess,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
# Importing public_probe performs the positive TCP/UDP probe as well.
import public_probe as p
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
        p.PORT=31990;s,_=p.socks(1,'myip.ipip.net',443);s.settimeout(12)
        try:s.sendall(b'owned-test\r\n');result['wrong-SS-password']=not s.recv(64)
        except OSError:result['wrong-SS-password']=True
        finally:s.close()
    finally:process.terminate();process.wait(timeout=10)
print(json.dumps({'public_negative_tests':result}))
if not all(result.values()):sys.exit(1)
