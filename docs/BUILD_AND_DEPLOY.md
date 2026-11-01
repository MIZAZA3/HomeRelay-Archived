# 下载、测试、构建与部署指南

[首页](../README.md) · [使用手册](USAGE.md)

## 1. 能直接做什么

能下载源码、阅读模块、运行部分不联网单元与静态检查。**没有完整运行EXE、现成凭据或经过新环境冷启动验收的一键安装器。**

`deploy/install*.py`依赖PAYLOAD注入、旧数据库/路径/前像哈希；`tools/remote.py`依赖原作者本机运维模块。它们是定向发布记录，不是执行 `python install.py` 就能建新服务。

## 2. 下载与校验

```bash
git clone https://github.com/MIZAZA3/HomeRelay-Archived.git
cd HomeRelay-Archived
```

无Git可用 **Code→Download ZIP**，没有二进制Release。仓库根目录执行下列Python可核对清单：

```python
import hashlib, json
from pathlib import Path
root = Path.cwd()
for row in json.loads((root/"ARCHIVE-MANIFEST.json").read_text("utf-8")):
    p = root/row["path"]
    assert p.is_file() and p.stat().st_size == row["bytes"], row["path"]
    assert hashlib.sha256(p.read_bytes()).hexdigest() == row["sha256"], row["path"]
print("manifest OK")
```

清单不含自身；它验证收录文件，不证明目录没有额外文件，也不代替代码审查。

## 3. 不联网单元与静态检查

需要Python 3.10+语言特性，未提供完整跨版本矩阵；Node使用支持 `node:assert/strict` 等API的现代版本。以下指定测试用合成数据，不连原服务器、不改系统路由/代理、不注册真实节点：

```bash
python -B current/tests/lifecycle_unit.py
python -B current/tests/transport_health_unit.py
python -B current/tests/stability_unit.py
python -B current/tests/target_policy.test.py
node current/tests/panel_password.test.cjs
node --check current/server/app.js
```

本次整理的实测环境/结果见[公开说明](PUBLICATION.md)。纯单元不要求生产access.json。Python AST检查示例只解析，不导入controller或写pyc：

```python
import ast, json
from pathlib import Path
root = Path.cwd()
names = [r["path"] for r in json.loads((root/"ARCHIVE-MANIFEST.json").read_text("utf-8"))]
for name in names:
    if name.endswith(".py"):
        ast.parse((root/name).read_text("utf-8-sig"), filename=name)
print("Python parse OK")
```

其它测试不一定纯本地：`isolated_integration.py`等需要新Linux网络命名空间、GOST、临时地址及fixture初始化，不能在生产主机网络盲跑；`public_*.py`与部分deploy/tools脚本依赖旧私有目录，不能对示例地址运行并当成验收。测试专用resolver/公网分类注入不能复制到生产目标策略。

## 4. Windows出口端构建

### 依赖

- Windows x64，.NET Framework 4.x的csc，WinForms/DPAPI。
- Windows OpenSSH客户端（ssh、ssh-keygen）。
- [官方GOST](https://github.com/go-gost/gost)；历史基线3.3.2，升级需重测协议/API兼容性，版本号不代表当前安全保证。
- 自编译NetBridge；它仅允许固定服务器SSH端点，不是通用代理。

### 绑定自己的部署

1. `windows/agent-and-connector-v2/source/Bootstrap.cs`：真实IP、证书域名、注册令牌、SSH主机公钥。
2. `NetBridge.cs`：固定允许IP/SSH端口，当前源码默认22；必须与Bootstrap对应。
3. `Common.cs`：拒绝目标里的服务器示例IP/域名；`Verify()`中的GOST与NetBridge哈希。
4. 注册令牌控制分发包报到，不等于管理权限；不要使用仓库占位符。
5. 主机公钥从可信管理通道核验，不关闭StrictHostKeyChecking。

### 编译顺序（仓库根目录PowerShell）

仅构建，不启动转发：

```powershell
$source = Join-Path $PWD 'windows/agent-and-connector-v2/source'
$out = Join-Path $PWD 'build/agent'
$csc = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
New-Item -ItemType Directory -Path $out -Force | Out-Null
& $csc /nologo /target:exe /platform:x64 "/out:$out/NetBridge.exe" "$source/NetBridge.cs"
if ($LASTEXITCODE -ne 0) { throw 'NetBridge build failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath "$out/NetBridge.exe"
```

把核验后的GOST和本次NetBridge SHA-256更新到Common.Verify，再运行：

```powershell
& (Join-Path $source 'Build.ps1')
```

Build.ps1构建到 `windows/agent-and-connector-v2/Agent`、`Connector`、`Admin`，**不自动编译/复制NetBridge或下载GOST**。出口端分发目录至少包含：

```text
干净出口端目录/
  HomeRelayAgent.exe
  gost.exe
  NetBridge.exe
```

检查哈希与许可，不含identity/runtime/个人连接卡，首次运行再生成身份。不要删掉校验绕过依赖错误。

### 历史V3连接器

各版source/Build.ps1还依赖完整包中的ProxyLane、sing-box等程序/载荷与目录，仓库不含这些二进制；需补输出目录、许可与资源。编译成功也不表示旧consumer协议兼容V4，不作为最终V4安装步骤。

## 5. 重建服务端：必须补齐的集成

先在独立测试Ubuntu完成，不把历史1Panel路径和发布脚本直接套到已有网站。源码归档没有完成任意新机器的完整部署验收。

### 5.1 环境与版本

Ubuntu/Linux、Python、SQLite、cryptography（历史验证41.0.7）、OpenSSH、systemd、GOST；网页登录另需自己的域名、HTTPS和Nginx/OpenResty。新部署应核对依赖安全更新，不盲目冻结旧版本。

研究最后上线版可选 `history/direct-v4.4/server/`，研究V4.5用 `current/server/`；不要混搭缺模块的不同版本。不沿用旧生产凭据/数据库/账号，不能把示例UID996当所有服务器通用值。

### 5.2 目录与配置

| 原路径 | 要适配的内容 |
|---|---|
| `/opt/home-relay-v2/` | 同一选定版本的全部Python服务模块 |
| `/etc/home-relay-v2/access.json` | 新master/注册令牌/管理口令哈希/SS配置，root私有 |
| `/var/lib/home-relay-v2/` | 私有状态与新SQLite，代码负责初始化/附加迁移 |
| `/opt/gost-home-relay/gost` | 已核验Linux GOST，或通过direct_binary改路径 |
| `/opt/home-relay-web/` | 所选版本网关和HTML/JS/CSS |
| `/etc/home-relay-web/web.json` | 随机proxy_token，与反向代理注入一致，root私有 |

controller支持RELAY_CONFIG、RELAY_STATE，默认读取systemd LoadCredential或上述路径；无配置不能直接启动。

access.json主要字段（格式说明，不是可直接使用的密钥文件）：

| 字段 | 语义 |
|---|---|
| master | 独立随机32字节hex，参与秘密/密码派生 |
| enrollment | 新注册令牌，与出口端一致 |
| password_salt | 管理口令scrypt盐，hex |
| password_hash | hashlib.scrypt，n=16384/r=8/p=1，默认输出长度，hex |
| max_nodes | 默认32；固定端口/客户端仍有范围限制，不能只改此项扩容 |
| admin_port / agent_port | 默认18780/18781，仅127.0.0.1 |
| direct_server | 真实SS公网IP，同时用于服务器自身目标拒绝 |
| direct_base_port | 默认24443，实际端口加slot |
| direct_open_slots | 明确开通槽位；不代替真实防火墙规则 |
| direct_binary | GOST可执行路径 |

配置/目录按0600/0700管理。交互生成管理口令并存哈希，不把秘密写到命令行/README/仓库。换master会改变既有派生语义，不等于普通重置密码。

### 5.3 SSH授权必不可少

参考[V2授权helper](../history/v2-server/ssh_authorize.py)与[旧运维](../history/v2-server/OPERATIONS.md)重新设计专用账号：

- 禁shell、PTY、agent/X11、本地任意转发、管理命令。
- 只允许自身 `127.0.0.1:22000+slot` 反向监听，校验公钥、启用/闲置状态和新鲜心跳。
- helper/解释器root-owned，查询用户只得必要DB读取能力，不公开整个库。
- 保留管理SSH，sshd -t通过后定向reload，不覆盖整份sshd_config。

只运行controller不会自动建立朋友SSH权限和反向通道。

### 5.4 端口边界

| 原设计端口 | 用途 | 公网策略 |
|---|---|---|
| 22/TCP | 受限朋友SSH与独立管理SSH | 自有管理策略 |
| 443/TCP | HTTPS管理和注册/心跳 | 需要时开放 |
| 80/TCP | 可选跳转/证书签发 | 不是代理必须端口 |
| 24443+slot TCP/UDP | 对应节点SS/SSU | 仅实际批准节点 |
| 18780/TCP | 内部管理controller | 仅loopback |
| 18781/TCP | 内部登记controller | 仅loopback，经HTTPS暴露指定路由 |
| 18782/TCP | 网页网关 | 仅loopback |
| 22000+slot/TCP | SSH反向转发 | 仅loopback |
| 23000+slot/TCP | 节点认证闸门 | 仅loopback |
| 25000+slot/TCP | 内部探测入口 | 仅loopback |
| Unix socket | GOST控制API | 无公网监听，目录/socket私有 |

云与主机防火墙分别设置，不一次放行整段32端口。TCP成功不能代替UDP规则。

### 5.5 网页代理

- `/relay-admin/`→`127.0.0.1:18782/`，核对去前缀语义。
- `/__home_relay_v2/register`与poll→`127.0.0.1:18781/register`与poll，不代理其它内部路径。
- web_gateway.py的ORIGIN、trusted Host与自己域名一致；反向代理固定设置Host、X-Forwarded-Proto=https、可信X-Real-IP、私有X-Relay-Web-Token，不信外部同名头。
- 独立限流、连接/请求体限制、安全响应头；日志不记口令与导出内容。
- 仓库不含完整有效的生产Nginx文件/令牌，需自行生成审查；复制静态panel.html不等于部署面板。
- 只加独立include，nginx -t后reload，不覆盖原网站首页/路由/数据库。

### 5.6 systemd与防直出

适配[controller单元](../current/deploy/home-relay-v2-controller.service)、[UID防火墙脚本](../current/deploy/home-relay-direct-firewall.py)、[web单元](../history/v2-web/home-relay-web.service)，核对用户、路径、systemd能力与端口。

仅对自己的服务UID安装IPv4/IPv6 HR_DIRECT_EGRESS，验证无服务器直出；不清空全局链、不按未核实UID杀进程（可能属于其它服务）。运行用户不应能改源码/敏感配置。

## 6. 完整验收

新设备待审核/错误令牌失败；SSH无shell/任意转发；独立SS公网TCP/UDP与真实目标；错误/旧密码、撤销、闲置、停用、离线拒绝；公网解析后保护与无直出；节点/总限速、并发、空闲、长会话；网页认证/CSRF/跨源负例；真实VM/SSTap/FlClash/游戏；原网站/SSH回归。

纯单元、协议测试或历史成功日志不能代替这套验收，本仓库不声称V4.5解决了真实用户稳定性。

## 7. 停用与卸载

先停节点/撤销凭据，停止专用服务和转发，私有备份自己的配置/库。仅删除本部署路由include、SSH include/账号、服务、主机/云节点端口、UID链。保留共享22/80/443，不整站回滚，不清系统日志或其它数据库。

`current/retirement/`绑定原环境，不可对新部署一键执行。原撤除结果见[退役说明](RETIREMENT.md)。
