import base64, io, json, pathlib, sys, tarfile
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
root=pathlib.Path(__file__).resolve().parents[1]
out=io.BytesIO()
with tarfile.open(fileobj=out,mode='w:gz') as t:
    for path in list((root/'server').glob('*.py'))+list((root/'tests').glob('*.py')):
        t.add(path,arcname=str(path.relative_to(root)).replace('\\','/'))
payload=base64.b64encode(out.getvalue()).decode()
script='''import base64,io,os,pathlib,subprocess,tarfile,tempfile
w=pathlib.Path(tempfile.mkdtemp(prefix="home-relay-v4-test-",dir="/run"));os.chmod(w,0o700)
with tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD)),mode="r:gz") as t:t.extractall(w,filter="data")
p=subprocess.run(["unshare","--net","sh","-c",'ip link set lo up && ip addr add 203.0.113.10/32 dev lo && python3 "'+str(w/'tests/target_policy.test.py')+'" && python3 "'+str(w/'tests/stability_unit.py')+'" && python3 "'+str(w/'tests/lifecycle_unit.py')+'" && exec python3 "'+str(w/'tests/isolated_integration.py')+'"'],capture_output=True,text=True,timeout=115)
print(p.stdout);print(p.stderr);print("fixture_exit="+str(p.returncode))
'''.replace('PAYLOAD',repr(payload))
result=ssh('sudo -n python3 -',script.encode()).decode()
evidence=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/isolated-integration.txt')
evidence.write_text(result,'utf-8');print(result)
if 'fixture_exit=0' not in result:sys.exit(1)
