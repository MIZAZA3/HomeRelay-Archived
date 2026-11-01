# 运维 / 定向回退

## 生产布局

- `/opt/home-relay-v2/controller.py` + `direct_proxy.py`：原控制 / 登记服务和版本鉴权闸门，监督一个固定 GOST 3.3.2 子进程。
- `/opt/home-relay-web/`：既有网站管理网关、HTML/JS/CSS；管理路径 `/relay-admin/`，原 HTTPS Cookie、CSRF、限流、独立管理口令保留。
- `/etc/home-relay-v2/access.json`：root 0600，原 master/enrollment/admin hash 保留，旧 consumer SSH 私钥、known_hosts、旧回调 proof 字段删除。不要读取、打印或分发。
- `/var/lib/home-relay-v2/nodes.sqlite3`：原节点库，仅附加能力，不清空 / 重建。新节点默认 pending。
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
