# 家宽连接器 3.0.2 — 普通浏览器实际代理修复

## 直接使用
1. 关闭旧版连接器打开的独立代理窗口、旧 HR302 测试窗口，再退出旧连接器。不要关闭普通 Edge 或 FlClash。
2. **正常双击**本机准备版 `HomeRelay-统一连接器-3.0.2/HomeRelayConnector.exe`，不要以管理员身份运行。
3. 输入节点使用密码，连接；选择 Edge，再点击“启动勾选程序并代理”。在本次新窗口内查询出口。
4. 准备版已迁移本机加密连接卡和程序列表。通用 ZIP 不带个人配置；节点使用密码仍不保存。

## 修复
3.0.1 虽能打开独立窗口，但实际普通 Edge 的网络进程没有被接管，曾直接显示本机出口 `203.0.113.30`。3.0.2 对支持的 Chromium 浏览器不再采用进程注入：

- 给新建临时浏览器资料目录指定本机 GOST **HTTP 代理**（SOCKS 基础端口 + 1），不使用系统代理或 PAC，不配置 DIRECT 回退。
- 同时使用启动参数和新建资料目录的 `webrtc.ip_handling_policy=disable_non_proxied_udp`；仅启动参数在本机普通窗口中实测不够。
- 禁用本次窗口的 QUIC，使网页使用 TCP；不安装证书、不关闭沙箱或 TLS 证书校验。
- 保留浏览器默认的 localhost / link-local URL 旁路规则；“不回退直连”的验收针对公网网页请求，不是系统级防火墙保证。
- 以管理员运行连接器时拒绝启动浏览器，避免浏览器降权重启造成进程生命周期不一致。全局模式的权限仍由独立辅助程序在手动启用时申请。
- 检测到冲突的浏览器管理策略时拒绝启动，不修改管理策略。

## 功能边界
- 浏览器模式适用 Edge / Chrome / Brave / Chromium / Vivaldi，网页 HTTP/HTTPS/WebSocket 使用原生代理。浏览器自身的任意 UDP 不通过 HTTP 代理；QUIC 改走 TCP，WebRTC 非代理 UDP 被限制，部分音视频连接可能受限。
- 浏览器不依赖“同路径子进程”注入选项，独立资料目录的浏览器网络进程使用同一原生代理。旧普通浏览器不受接管。
- **其他程序的指定 TCP/UDP、多程序、本机 SOCKS5/HTTP/SS、节点独立密码及手动全局功能保留。**不兼容的应用仍可能无法使用进程代理；Opera / 360Chrome 沿用旧约束。
- 全局 TUN 仍默认关闭。本轮未启用或实网验收 TUN；FlClash、网站、服务器均未修改或重启。
- 临时浏览器不共享普通浏览器的登录、扩展、历史；关闭本次所有浏览器子进程后尽力清理临时目录。不会强制结束用户程序。

## 已验收
采用真实普通 Edge 窗口（不是只测无头模式）：网页 JavaScript 经真实代理取得 `203.0.113.30`；WebRTC API 已实际调用，候选为空、STUN 接收端 0 包；主动停止自建测试代理并切断其旧公网连接后，同一网页新的 IP 请求失败而不直连。详见 `验收报告.md`。

## 复用的开源组件
- GOST 3.3.2：https://github.com/go-gost/gost （本次没有另写转发协议或更换现有服务器）。
- Chromium 原生代理机制：https://github.com/chromium/chromium/blob/main/net/docs/proxy.md
- Chromium WebRTC 首选项：https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/common/pref_names.h
- ProxyLane 1.3.5（仅其他指定程序）、sing-box 1.14.4（仅手动全局）及许可证保持原包内容。`source/Build.ps1` 构建本工具；第三方程序在完整运行包中。
