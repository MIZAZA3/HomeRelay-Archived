# 运维 / 定向回退

## 生产布局

- `/opt/home-relay-v2/controller.py` + `direct_proxy.py`：原控制 / 登记服务和版本鉴权闸门，监督一个固定 GOST 3.3.2 子进程。
- V4.1 新增 `/opt/home-relay-v2/credential_admin.py`：自定义 / 随机 / 撤销操作，认证和 CSRF 仍由原 HTTP handler 先校验；操作串行化，携带期望版本避免覆盖并发更改。
- V4.2 新增 `/opt/home-relay-v2/node_limits.py`：共享的节点上传 / 下载 token buckets 与全局每方向 256 KiB/s 同时扣费；不按连接单独发额度。`node_limits` 表保存 0–256 的整数、独立 revision 和更新时间；老节点初始 0 / 0，密码 revision 不变。限速变更在 asyncio 数据闸门热应用，无 GOST 重启。
- V4.2 新增 `/opt/home-relay-v2/target_policy.py`：解析 SOCKS5 CONNECT 和 GOST `0xf3` UDP-over-TCP 请求，校验并改写为公网数字地址。允许 GOST UDP tunnel 的 `0xff` 标记，不把它当成 IP 分片；零长度 / 实际分片帧不支持。域名解析最多 4 个在途任务、4 秒等待、256 条 / 30 秒缓存；没有无界任务队列。不能把测试用 resolver / test_addresses 注入生产实例。
- `/opt/home-relay-web/`：既有网站管理网关、HTML/JS/CSS；管理路径 `/relay-admin/`，原 HTTPS Cookie、CSRF、限流、独立管理口令保留。
- `/etc/home-relay-v2/access.json`：root 0600，原 master/enrollment/admin hash 保留，旧 consumer SSH 私钥、known_hosts、旧回调 proof 字段删除。不要读取、打印或分发。
- `/var/lib/home-relay-v2/nodes.sqlite3`：原节点库，仅附加能力，不清空 / 重建。新节点默认 pending。
- V4.1 只增加 `node_access.ss_secret` 空默认列和 `node_password_history` 表。原随机密码保持原派生，迁移不改版本。自定义密码密文用 Fernet；密钥由服务器 master 加上节点 id / slot / revision 派生，原 master 必须保留。运行依赖系统已有 `python3-cryptography` 41.0.7，没有安装新包。
- `/var/lib/home-relay-v2/direct-api.sock`：0700 目录下的 0600 Unix socket，另有 Basic Auth；无公网控制 API。bootstrap 文件 0600。
- `home-relay-v2-controller.service`：非特权 UID 996，整个控制器 / GOST 子进程组 CPU 25%、内存 256 MiB、Tasks 128、FD 2048。总数据并发 64 / 单节点 16，每方向总速率 256 KiB/s。
- `home-relay-direct-firewall.service`：root oneshot，仅针对 UID 996 安装 `HR_DIRECT_EGRESS` OUTPUT 链，IPv4/IPv6；在 controller 前启动。不清空 UFW 或其他链。

## 更改后验证

使用既有严格主机指纹的 `website-prod` SSH 配置，不复制私钥；不要重新运行旧 provision.stage()。

1. 读取当前目标文件 / 哈希、服务状态、节点数量和最新 seen；定向备份。
2. 修改源码应 root-owned；Python compile、JS syntax、隔离命名空间集成先过。
3. 只重启 HomeRelay 对应服务。控制器启动 / 退出由 systemd control-group 管理 GOST，不留孤儿代理。
4. 若更改 UFW / 重新加载防火墙，随后执行 `/usr/bin/python3 /usr/local/sbin/home-relay-direct-firewall.py`，验证 OUTPUT jump 位于其他通用 ACCEPT 之前，再检查 UID 996 不能直连公网。重启 UFW / 切换 iptables 后端属于另一次变更，不可默认规则自动保持。
5. 实际从外部标准 SS 客户端测试 TCP 和 UDP，禁止用服务器自身直连的结果冒充朋友出口。
6. 验证网页 200、nginx -t、sshd -t、原业务容器 healthy、朋友反向连接正常、旧端点失效、敏感配置权限。

## 新节点端口开通

自动登记无须预先名单。每节点独立 SS 密码，GOST 标准 legacy AEAD 单监听器单密钥，所以使用独立端口：`direct_base_port + slot`。当前只放行 24443；不能假称未来其他槽位已可用。

开通指定节点时，核对 slot 和状态，在阿里云与 UFW 仅放行该节点 TCP/UDP 端口，再 root 定向编辑 `direct_open_slots`（不改变 master/enrollment/admin hash），重启控制器并复测。无云 API 凭据时不声称面板能自动修改阿里云安全组。

## 发布与回退记录

正式方向性备份：`/var/backups/home-relay-direct-v4/20261031T194807Z`，UTC 时间，所有敏感备份留服务器 root 私有目录。

V4.1 自定义密码定向备份：`/var/backups/home-relay-custom-password/20261031T211101Z`（北京时间 2026-11-01 05:11:01）。6 个源文件、旧前像和一致性 SQLite 快照留在 root 私有目录；只重启 controller，web / SSH 主 PID 保留。迁移前后生产节点密码版本均为 4。

同目录另记录 `credential_admin.py` 恢复性补丁：损坏的密文不用于认证 / 导出，但不能阻止管理员撤销或替换密码；未改变真实密码版本。对应隔离集成扩展为 48 项。

V4.2 限速与目标校验定向备份：`/var/backups/home-relay-limits/20261101T041013Z`（北京时间 2026-11-01 12:10:13）。7 个既有源文件前像、2 个新增模块、源码后像和停 controller 后的一致 SQLite 快照保存在服务器 root 私有目录。更新 controller + HomeRelay web gateway（增加认证限速路由），SSH PID 2072001 以及三个业务容器的 ID / 启动时间未变。没有 Nginx reload、网站路由 / 防火墙变更。新 controller / gateway PID 为 2153976 / 2154018。

发布取的是最新生产首页 / 路由，而非旧 V4.1 哈希：它们已被其他获准的网站任务更新。发布期间及发布后分别保持 `35334d189c5459dc825b7528e003bf9ed3dd647d26b342c782c8467291ade8a0` / `5441a08f0ba391ff888be183aa52f1df7d943cbc08cceaaeee8afbc953ec03e0`。不要用历史首页或整份公共路由覆盖它们。

V4.2 前端保存继承值 `0 / 0` 已验证，限速配置 revision=2；这不是节点密码 revision，密码仍为 4。后续操作读取实时值，不用验收值覆盖用户新设置。生产全局 256 KiB/s 不提供 mass assignment 接口。

同次补强显式特殊地址范围，避免不同系统 Python 的 `is_global` 分类差异；Ubuntu 实际 Python 的目标策略单元和完整隔离集成均通过。补丁备份 `policy-hardening-20261101T044711Z`（12:47:11），只再重启 controller，最终 PID 2171235；web 2154018 / SSH 2072001 保持。当前 target_policy.py SHA256 `ac96d5f1c51efadb612c2e335aac49aa71d1821d55de5cc3bbf0985fa79b0611`。

补丁前发现其他网站发布已合法改变首页 / 路由，首次哈希守卫中止、没有覆盖。重新读取其最新前像 `e320ce55810b5da84b85fe0e0468ce38dd6b04e2b320c5784e6036bf5666e2bf` / `bf2f76e77956243b85252f722a1851a464ff1a10a96f6cba45f561626d14eec8` 后只更新 HomeRelay 模块，补丁期间保持这两项不变。原发布 manifest 保留第一次前像，`latest_protected` / `supplemental_patches` 另记录最新检查点，不将跨聊天合法变更错误恢复为旧站点。

**V4.2 回退还须保留公网目标解析后校验。旧 V4.1 的静态黑名单存在经域名访问内网的缺口；如新版异常先停用受影响节点 / SS 入口，修复新版后恢复，不为了可用性直接启用旧的无目标固定闸门。限速表不能用旧快照覆盖，密码 / 身份库同样不整库回滚。**

**V4.1 回退约束：用户一旦保存过自定义密码，不能恢复只会派生随机密码的 V4 `direct_proxy.py`，否则导出 / 实际使用的密码会被意外改变。必须保留解密支持、新鉴权与最新版本；不回退密文或历史指纹表，不恢复发布前整库。**

- `before/`：新服务前像、原私有配置和 SSH / 路由前像。
- `nodes.sqlite3`：发布时数据库一致性快照，仅故障取证，不默认整库回滚。
- `retirement-before/`：退役时实时 SSH / 共享路由前像。
- `retired/`：移出有效目录的旧服务、旧认证配置、公钥文件、consumer include。
- `manifest.json`：各阶段哈希与状态。以后发布先核对当前后像，不能无条件用旧包覆盖。

### 回退原则

1. 首选停用新 SS 公网入口并保留登记 / 密码撤销语义，先断流，再排查；不要为了恢复连接而退回无版本鉴权的旧 gate。
2. 发生过换密 / 撤销后，**不可自动恢复旧 node_access 或原整库**，否则旧凭据复活。恢复源码前先检查代码能执行最新权限规则。
3. 如确需回退旧传输，先停止新的 controller/GOST，停止监听 24443；只恢复批准的对应服务 / 配置前像并处理 mask。不要同时让旧、新服务争用 24443。
4. 旧接收器 / 发布者 SSH 权限默认保持撤销，除非用户另行批准恢复；不恢复整份 sshd_config。
5. 共享 Nginx 只能定向恢复旧 consumer 段（若用户确实决定重用）；先取实时前像、nginx -t、只平滑 reload，不重启业务容器。
6. 退役本模块时，仅删除对应 UFW 24443/TCP/UDP 与云规则、对应 UID OUTPUT jump 和 `HR_DIRECT_EGRESS` 链；不能清空全局防火墙，也不能删除服务器 22/80/443 或朋友仍在使用的 SSH 服务。

本源码包的 deploy 脚本记录本次确定前像 / 路径，**不是可重复盲跑的通用安装器**。已有部署不能重新运行 `deploy_release.py`、`retire_legacy.py`。
