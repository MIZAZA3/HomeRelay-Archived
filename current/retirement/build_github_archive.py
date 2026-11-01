"""Build a NEW sanitized source-only tree. Never copies private runtime data.
Private backup and raw evidence remain outside this publish directory.
"""
import hashlib,ipaddress,json,pathlib,re,tarfile,zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
TOOLS=pathlib.Path('D:/CodexTools')
PRIVATE=pathlib.Path('D:/CodexWork/HomeRelayRetired/private')
OUT=TOOLS/'HomeRelay-Archived'
assert not OUT.exists(),'Do not merge with or overwrite an existing archive'
OUT.mkdir()
TEXT={'.py','.js','.cjs','.html','.css','.service','.md','.txt','.cs','.ps1','.h','.cpp','.manifest'}
BLOCKED={'private','identity','runtime','__pycache__','.git','engine','bin','obj'}
secrets=set()

def read(data):
    try:return data.decode('utf-8-sig')
    except UnicodeError:return data.decode('gb18030')
def collect(obj):
    if isinstance(obj,dict):
        for key,value in obj.items():
            if re.search(r'(?:password|secret|token|master|enrollment|passphrase|pw_hash|password_salt)',key,re.I) and isinstance(value,str) and len(value)>=12:
                secrets.add(value)
            collect(value)
    elif isinstance(obj,list):
        for value in obj:collect(value)
with tarfile.open(PRIVATE/'private-server-retirement.tar.gz','r:gz') as archive:
    for member in archive.getmembers():
        if not member.isfile() or member.size>262144 or not member.name.endswith('.json'):continue
        if any(x in member.name for x in ['/tests/','hr4-fixture','/run/','/tmp/']):continue
        if '/etc/' not in '/'+member.name and '/var/lib/' not in '/'+member.name:continue
        try:collect(json.loads(read(archive.extractfile(member).read())))
        except (UnicodeError,ValueError):pass
for p in [pathlib.Path('D:/CodexWork/HomeRelayDirectV4/private/standard-node.json')]:
    if p.exists():collect(json.loads(p.read_text('utf-8-sig')))
password_file=pathlib.Path('D:/CodexWork/HomeRelayV2/private/panel-password.txt')
if password_file.exists():secrets.add(password_file.read_text().strip())
bootstrap=TOOLS/'HomeRelayV2/source/Bootstrap.cs'
for key,value in re.findall(r'const string (\w+)="([^"\r\n]*)"',bootstrap.read_text('utf-8-sig')):
    if re.search('Enrollment|Secret|Token|Password',key,re.I):secrets.add(value)
assert all(len(s)>=12 for s in secrets)
redactions=0

def sanitize(text):
    global redactions
    for value in sorted(secrets,key=len,reverse=True):
        count=text.count(value)
        if count:redactions+=count;text=text.replace(value,'REDACTED_CREDENTIAL_GENERATE_A_NEW_VALUE')
    # A public host key is not a secret, but the old deployment identity should
    # not appear in a reusable archive either.
    text=re.sub(r'(const string KnownHosts=)"[^"\r\n]*"',r'\1"relay.example.invalid ssh-ed25519 REPLACE_WITH_YOUR_HOST_PUBLIC_KEY\\n"',text)
    for old,new in [
        ('203.0.113.20','203.0.113.20'),('relay.example.invalid','relay.example.invalid'),
        ('example.invalid','example.invalid'),('example-site','example-site'),
        ('EXAMPLE_CLOUD_INSTANCE','EXAMPLE_CLOUD_INSTANCE'),
        ('00000000000000000000000000000001','00000000000000000000000000000001'),
        ('EXAMPLE','EXAMPLE'),('example','example'),
        ('C:\\\\Users\\\\mc','C:\\\\Users\\\\YOUR_USER'),
        ('C:\\Users\\YOUR_USER','C:\\Users\\YOUR_USER'),('C:/Users/YOUR_USER','C:/Users/YOUR_USER')]:
        text=text.replace(old,new)
    def residential(match):
        value=match.group()
        if value.startswith(('182.90.','111.85.','220.200.')):return '203.0.113.30'
        return value
    text=re.sub(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',residential,text)
    # Existing ss:// examples with a literal key are not needed in source.
    text=re.sub(r'ss://[A-Za-z0-9+/_=-]{24,}', 'ss://REDACTED_EXAMPLE', text)
    return text

def put(destination,data,origin):
    relative=pathlib.PurePosixPath(destination)
    assert not relative.is_absolute() and '..' not in relative.parts
    assert not any(p.lower() in BLOCKED for p in relative.parts)
    p=OUT/pathlib.Path(*relative.parts);p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(sanitize(read(data)),'utf-8')

def tree(source,prefix):
    for p in source.rglob('*'):
        if not p.is_file() or p.is_symlink() or p.suffix.lower() not in TEXT:continue
        relative=p.relative_to(source)
        if any(part.lower() in BLOCKED for part in relative.parts):continue
        put((pathlib.PurePosixPath(prefix)/relative.as_posix()).as_posix(),p.read_bytes(),str(p))

for folder in ['server','tests','tools','deploy','retirement']:tree(ROOT/folder,'current/'+folder)
for p in ROOT.glob('*.md'):put('current/docs/'+p.name,p.read_bytes(),str(p))
put('current/.gitignore',(ROOT/'.gitignore').read_bytes(),'.gitignore')

for version,name in [('4.0','HomeRelayDirectV4-source.zip'),('4.1','HomeRelayDirectV4.1-source.zip'),('4.2','HomeRelayDirectV4.2-source.zip'),('4.3','HomeRelayDirectV4.3-source.zip'),('4.4','HomeRelayDirectV4.4-source.zip')]:
    with zipfile.ZipFile(TOOLS/'HomeRelayDirectV4'/name) as archive:
        for member in archive.infolist():
            relative=pathlib.PurePosixPath(member.filename)
            if member.is_dir() or relative.suffix.lower() not in TEXT:continue
            if relative.is_absolute() or '..' in relative.parts or any(p.lower() in BLOCKED for p in relative.parts):continue
            put('history/direct-v'+version+'/'+relative.as_posix(),archive.read(member),name)

tree(TOOLS/'HomeRelayV2/source','windows/agent-and-connector-v2/source')
tree(TOOLS/'HomeRelayV2/server','history/v2-server')
tree(TOOLS/'HomeRelayV2/server-web','history/v2-web')
for version,folder in [('3.0','HomeRelayV3'),('3.0.1','HomeRelayV3.0.1'),('3.0.2','HomeRelayV3.0.2')]:
    tree(TOOLS/folder/'source','windows/connector-v'+version+'/source')
    for name in ['README.md','验收报告.md']:
        p=TOOLS/folder/name
        if p.exists():put('windows/connector-v'+version+'/'+name,p.read_bytes(),str(p))
tree(TOOLS/'HomeRelayV3.0.2/licenses','notices')

readme='''# HomeRelay — 私有退役归档

**状态：已停止开发，并于 2026-11-01 从原服务器和网页卸载。**

这是源码与研发记录归档，不是一个已经证明稳定可用的一键部署项目。
此前独立客户端协议测试通过，但用户虚拟机内 SSTap / 游戏登录器仍有真实故障；
不能将 TCP/UDP 探测成功等同于实机体验或长期稳定。

## 内容

| 目录 | 内容 |
|---|---|
| `current/` | 停止时的最后工作树；包含未发布的 V4.5 隧道恢复原型 |
| `history/` | V2 服务端及 V4.0–V4.4 各阶段源码，保留历史而非覆盖 |
| `windows/` | V2 出口端/连接器与 V3 多程序连接器源码 |
| `evidence/` | 明确挑选并脱敏的测试、失败及排查记录 |
| `notices/` | 原有第三方许可证与来源说明 |
| `docs/` | 退役说明、归档范围和隐私处理 |

## 不包含

- 登录私钥、真实密码/令牌、设备身份、运行数据库、生产配置及私人备份。
- 浏览器资料、云账号信息、网站业务数据或其他项目。
- SSTap 安装包、驱动、第三方 EXE/DLL/SYS 或其他二进制安装包。

服务器地址、域名、节点编号和家宽出口信息已替换为文档示例。
旧源码中的注册令牌和主机公钥占位符必须自行重新生成，不能直接使用。
历史发布/回退脚本绑定当时特定前像，不应不经审查直接运行；归档不会自动部署。

**V4.5 原型没有发布到原服务器，也没有经过用户虚拟机的最终验收。**
它完成了隔离/单元回归，但用户随后要求撤销项目；不能把它描述成已上线解决方案。
第三方组件保留原许可证；本次没有额外声明整个项目的新开源许可证。

见 [退役与保留范围](docs/RETIREMENT.md) 和 [脱敏说明](docs/ARCHIVE_SCOPE.md)。
'''
(OUT/'README.md').write_text(readme,'utf-8')
(OUT/'docs').mkdir()
(OUT/'docs/RETIREMENT.md').write_text('''# 退役说明

2026-11-01，根据项目所有者明确要求停止继续修改并卸载。

- 已停止/移除相关 systemd 服务、专用转发账号、应用配置、运行数据库及旧服务备份。
- 已移除网站管理入口和出口端登记/心跳路由，原路径返回404。
- 已移除 Ubuntu 的 TCP/UDP 24443 放行及本项目专用 OUTPUT 链。
- 原网站首页、业务容器和管理 SSH 保持不变；没有操作 FlClash。
- 私有完整备份已转存所有者电脑并校验，服务器上的备份随后清理；不在本仓库。
- 阿里云控制台遗留 TCP/UDP 24443 两条规则的最终状态须以退役验收记录为准。

共享系统日志没有为本项目而整体删除。历史测试通过不是用户虚拟机的最终验收。
最后的隧道恢复方案属于取消前的未发布原型，保留源代码但不继续部署。
''','utf-8')
(OUT/'docs/ARCHIVE_SCOPE.md').write_text('''# 归档范围与脱敏

这是新建的独立发布目录，不沿用可能含运行数据的旧 Git 历史。
采用源码扩展名白名单；不复制私有目录、身份、运行目录、数据库或二进制。
历史版本由已有源码 ZIP 提取后重新脱敏，不直接上传原始压缩包。
对生产配置中已知口令/令牌做精确比对，另检查私钥、SS链接、设备标识和部署地址。
第三方许可证原样保留；对应第三方项目源码和二进制应从各自官方项目取得。

`ARCHIVE-MANIFEST.json` 校验的是脱敏后的归档，不是原生产文件。
真实备份、完整运维清单及未脱敏证据仍在仓库之外的本机私有目录中。
''','utf-8')
(OUT/'.gitignore').write_text('''private/
identity/
runtime/
__pycache__/
*.pyc
*.sqlite*
*.db
*.key
*.pem
*.pfx
*.p12
*.exe
*.dll
*.sys
.env
*.local.json
''','utf-8')

evidence=TOOLS/'HomeRelayDirectV4/evidence'
selected=['lifecycle-v43-before-repro.txt','lifecycle-v44-final-race-fixed.txt','lifecycle-v44-public-pressure-10s.txt',
 'lifecycle-v44-public-final.txt','friend-tunnel-live-stall.json','vm-sstap-new-failure-start.json',
 'vm-sstap-udp-session-states.json','vm-session-new-ssh-link.json','transport-v45-final-isolated-rst-aware.txt']
for name in selected:
    p=evidence/name
    if p.exists():put('evidence/'+name,p.read_bytes(),str(p))

manifest=[]
bad=[]
for p in sorted(OUT.rglob('*')):
    if not p.is_file():continue
    data=p.read_bytes();text=data.decode('utf-8')
    matches=[]
    if any(value in text for value in secrets):matches.append('known_production_credential')
    if re.search(r'(?m)^-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----',text):matches.append('private_key')
    for value in ['203.0.113.20','relay.example.invalid','00000000000000000000000000000001']:
        if value in text:matches.append('production_identifier')
    if matches:bad.append({'path':p.relative_to(OUT).as_posix(),'categories':sorted(set(matches))})
    manifest.append({'path':p.relative_to(OUT).as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
assert not bad, json.dumps(bad)
(OUT/'ARCHIVE-MANIFEST.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n','utf-8')
report={'directory':str(OUT),'files':len(manifest)+1,'source_only':True,'private_data_excluded':True,
        'known_secret_values_checked':len(secrets),'credential_replacements':redactions,'secret_scan':'passed',
        'v45_recovery_prototype_deployed':False,'git_remote_published':False}
(PRIVATE/'github-preparation.json').write_text(json.dumps(report,indent=2),'utf-8')
print(json.dumps(report))
