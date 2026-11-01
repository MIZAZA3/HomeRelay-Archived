import hashlib,json,pathlib,re,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
output=pathlib.Path('D:/CodexTools/HomeRelayDirectV4')
allow=[root/'.gitignore']+list(root.glob('*.md'))
for folder in ['server','tests','tools','deploy']:
    allow.extend(p for p in (root/folder).rglob('*') if p.is_file() and p.suffix in ['.py','.js','.html','.css','.service','.md'])
private=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/private')
cred=json.loads((private/'standard-node.json').read_text())
secrets=[cred['password'],cred['ss_uri'],cred['sip002_uri'],pathlib.Path('D:/CodexWork/HomeRelayV2/private/panel-password.txt').read_text().strip()]
manifest=[]
for p in sorted(allow):
    b=p.read_bytes();text=b.decode('utf-8')
    assert all(secret not in text for secret in secrets),str(p)
    assert not re.search(r'(?m)^-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----$',text),str(p)
    manifest.append({'path':p.relative_to(root).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
archive=output/'HomeRelayDirectV4-source.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted(allow):z.write(p,p.relative_to(root).as_posix())
    z.writestr('SOURCE-MANIFEST.json',json.dumps(manifest,ensure_ascii=False,indent=2))
with zipfile.ZipFile(archive) as z:
    for row in manifest:assert hashlib.sha256(z.read(row['path'])).hexdigest()==row['sha256']
for name in ['README.md','OPERATIONS.md','SOURCES.md']:(output/name).write_bytes((root/name).read_bytes())
(output/'source-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),'utf-8')
report={'files':len(manifest),'credential_scan':'passed','archive':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
(output/'evidence/source-package.json').write_text(json.dumps(report,indent=2),'utf-8')
print(json.dumps(report))
