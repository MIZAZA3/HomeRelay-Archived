# 复用来源 / 验证依据

核对时间：2026-11-01。V4.2 没有重新开发加密协议、购买软件或替换 FlClash；SSTap 安装包此前已按用户要求单独下载到 R 盘，本轮没有安装 / 执行。

1. **GOST 3.3.2**：沿用已经安装并核对版本的官方程序，新增标准 SS / SSU 服务与私有 Unix Web API 控制。
   - https://github.com/go-gost/gost
   - https://github.com/go-gost/gost/blob/master/LICENSE （MIT，Copyright 2016 ginuerzh）
   - https://gost.run/en/tutorials/protocols/ss/ （SS 和 SSU 分别配置 TCP、UDP；SS 仅支持单一 cipher/password）
   - https://gost.run/en/tutorials/api/overview/ （Unix socket、Basic Auth）
   - https://gost.run/en/tutorials/api/config/ （按服务创建 / 删除 / 更新，不整体重启其他节点）
   - 本次仅分发自身源码 / 文档，不在源码包重复分发 GOST 二进制。
2. **SSTap 原作者修改记录**：https://www.sockscap64.com/changelog-of-sstap-zh-hans/
   - 1.0.7.6 已增加 AES-GCM 等 AEAD；1.0.7.8 修复 AEAD SS 链接识别。本轮按用户选择兼容 1.0.9.7，不把“最好”作为技术事实。
   - 这是文档兼容依据，不是 SSTap GUI / TAP 的本机实际验收记录。
3. **独立协议验收客户端**：使用原目录内 sing-box 1.14.4，不装新服务，不开启 TUN。
   - https://github.com/SagerNet/sing-box
   - https://sing-box.sagernet.org/configuration/outbound/shadowsocks/
   - 测试二进制 SHA256：`8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9`。
   - 二进制及其许可 / 对应源码仍在此前原交付目录，本源码包不分发它。
4. **FlClash / mihomo 格式**：
   - https://github.com/chen08209/FlClash
   - https://wiki.metacubex.one/config/proxies/ss/
   - YAML 内使用标准 `type: ss`, `cipher: aes-256-gcm`, `udp: true`，不调用或覆盖 FlClash 的用户配置。
5. 原用户自有 HomeRelay V2/V3 代码用于定向兼容改造；保留现有登录防护、登记协议、朋友账号约束与限速设计。本仓库不包含第三方私钥 / 密码 / Cookie / 节点身份文件。
6. V4.1 自定义密码存储复用 Ubuntu 已安装的 `cryptography 41.0.7`，使用 Fernet，不自行实现密码学；不在源码 ZIP 分发库二进制。
   - https://cryptography.io/en/latest/fernet/
   - https://github.com/pyca/cryptography （Apache-2.0 / BSD-3-Clause 双许可）
   - Fernet 用于本地认证加密存储，不改变公网 Shadowsocks 的 aes-256-gcm 算法。
7. **V4.2 限速与数据闸门**：先核对 GOST 原生 limiter，标准 SS 不直接提供其认证插件客户端标识，因此在已有认证节点闸门按节点聚合 TCP / UDP 配额。token bucket 为本项目实现，时钟使用 Python monotonic；两级额度原子扣费，不复写 GOST 协议或加密。
   - https://gost.run/en/concepts/limiter/
   - https://docs.python.org/3/library/time.html#time.monotonic
   - https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.run_in_executor
8. **解析后目标防护依据**：核对 GOST 3.3.2 实际依赖 `go-gost/x v0.27.2` / `gosocks5 v0.5.0` 的静态 bypass、CONNECT 路由与 UDP tunnel framing；通过独立 namespace marker 复现旧应用组合的解析前黑名单缺口。这里只按已核对协议添加目标校验，未复制或修改第三方二进制。
   - https://github.com/go-gost/gost/blob/v3.3.2/go.mod
   - https://github.com/go-gost/x/blob/v0.27.2/bypass/bypass.go
   - https://github.com/go-gost/x/blob/v0.27.2/handler/socks/v5/connect.go
   - https://github.com/go-gost/x/blob/v0.27.2/internal/util/socks/conn.go
   - https://github.com/go-gost/gosocks5/blob/v0.5.0/socks5.go
9. **安全公告与系统包核对**：仅检查本服务使用路径，未修改系统包，不把“没有公告”作为没有漏洞的证明。
   - https://github.com/go-gost/gost/security/advisories
   - https://github.com/pyca/cryptography/security/advisories
   - https://ubuntu.com/security/notices （发行版补丁以 `dpkg-query` 完整版本为准，不能仅看 OpenSSL 基础版本号）
