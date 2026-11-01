# 复用来源 / 验证依据

核对时间：2026-11-01。没有重新开发加密协议、下载 SSTap、购买软件或替换 FlClash。

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
