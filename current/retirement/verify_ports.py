"""Narrow public port verification of the previously owned relay host."""
import concurrent.futures,json,pathlib,socket
HOST='203.0.113.20'
expected={22:True,80:True,443:True,24443:False,18321:False,18780:False,18781:False,18782:False,18783:False,22000:False,23000:False,25000:False}
def check(item):
    port,wanted=item
    try:
        with socket.create_connection((HOST,port),timeout=2):opened=True
    except OSError:opened=False
    return {'port':port,'expected_open':wanted,'open':opened,'ok':opened==wanted}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(check,expected.items()))
report={'ports':results,'passed':all(x['ok'] for x in results)}
pathlib.Path('D:/CodexWork/HomeRelayRetired/private/port-verification.json').write_text(json.dumps(report,indent=2),'utf-8')
print(json.dumps(report))
assert report['passed']
