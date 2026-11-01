# 现有 Ubuntu 服务器的 V2 运维记录

管理面板：127.0.0.1:18780，仅走管理员原有 SSH 隧道。
Agent API：127.0.0.1:18781；公网仅经网站 HTTPS 的 `/__home_relay_v2/register` 和 `/__home_relay_v2/poll` 两个 POST 路由。
数据路径：连接器 → 受限 SSH 本地转发 → 127.0.0.1:25000+槽位（认证 HTTP/SOCKS5）→ 23000+槽位（启用闸门）→ 22000+槽位（受限反向 SSH）→ 朋友物理网卡。
所有 V2 内部端口仅 loopback，无新的云安全组/UFW规则。旧24443/V1服务保留。

文件：
- `/opt/home-relay-v2/`：root拥有、服务用户只读的控制器/面板/授权辅助程序。
- `/etc/home-relay-v2/`：root-only 配置，含主密钥、管理口令哈希、有限权限的连接端传输密钥。
- `/var/lib/home-relay-v2/nodes.sqlite3`：节点状态与限量审计日志；服务用户私有。
- `/etc/ssh/home-relay-v2.inc`：独立 Match 配置，以 Match all 结束，不改变原管理用户/root/V1出口账号的有效配置。
- `/etc/ssh/home-relay-v2-client.authorized_keys`：只含受限连接端公钥。
- `/opt/1panel/www/sites/example-site/home-relay-v2.conf`：两条独立API路由及兜底404。
- `/var/backups/home-relay-v2/`：本次定向备份。不可把其中旧全量文件覆盖当前并发维护中的站点配置。

服务：`home-relay-v2-controller.service`、`home-relay-v2-proxy.service`。
状态检查：`systemctl status`、`journalctl -u` 对应两个服务；不要重启所有容器。
不要在日志、聊天、源码仓库或普通压缩包内输出 access.json、gost.json、节点JSON或私钥内容。

## 维护边界
新节点默认pending，不能通过SSH授权；enabled/idle且心跳有效的公钥才可绑定自身一个22000+槽位。
停用/拒绝立即关闭本节点的活动数据流；Agent最多一个心跳周期后回收自己的转发子进程。
idle保持隧道和旧流量，不承接新数据流。离线超过45秒不接新数据流；超过90秒不授权新的Agent SSH连接。
心跳报称“通道已就绪”不是对朋友出口的信任证明；面板检测才记录真实HTTPS出口IP及UDP DNS结果。
注册/心跳无远程执行、无软件下发、无网站写权限。SSH服务仍沿用服务器既有防护，保持补丁和监控。

## 定向回退
先读取当前前像并备份：网站可能被其他对话继续维护。
1. 定向停止并禁用两个 V2 systemd 服务，不动 gost-home-relay.service、网站或数据库。
2. 从当前公共路由移除本次独立 home-relay-v2.conf 的 include 行，保留其余新增内容；nginx -t 后仅优雅重载 OpenResty。
3. 从当前主 sshd_config 移除本次独立 V2 include 行；sshd -t 后仅重载 SSH。
4. 保留状态和凭据目录用于复核；账户/密钥/数据库的永久删除须另行确认，不能自动清理。

NodeSlot 固定0–31，当前版本不提供删除/回收生产节点的界面。扩容应同时复核槽位、前端/闸门、SSH PermitOpen、Windows验证和资源限制，不能只改max_nodes。
