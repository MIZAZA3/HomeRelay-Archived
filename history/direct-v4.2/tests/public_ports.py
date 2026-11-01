"""Small expected-port regression of the owned server, not a broad scan."""
import concurrent.futures,json,pathlib,socket
host='203.0.113.20'
expected={22:True,80:True,443:True,24443:True,18321:False,18780:False,18781:False,18782:False,18783:False,23000:False,25000:False}
def test(item):
 port,want=item
 try:
  with socket.create_connection((host,port),timeout=2):opened=True
 except OSError:opened=False
 return {'port':port,'expected_open':want,'tcp_connect_succeeded':opened,'matches':opened==want}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(test,expected.items()))
r={'owned_host':host,'ports':results,'passed':all(x['matches'] for x in results)}
pathlib.Path('D:/CodexTools/HomeRelayDirectV4/evidence/public-ports-v42.json').write_text(json.dumps(r,indent=2),'utf-8')
print(json.dumps(r))
if not r['passed']:raise SystemExit(1)
