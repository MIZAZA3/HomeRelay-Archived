# 家宽连接器 3.0

Windows统一连接器：多个指定程序代理，默认关闭的可选全局模式，节点使用密码认证。
网站管理入口仍是 [家宽出口管理](https://relay.example.invalid/relay-admin/)。

## 使用顺序
管理员设置节点使用密码 → 获取连接卡 → 连接器导入/选择节点 → 输入使用密码 → 连接并检测 → 勾选一个或多个程序启动。
朋友出口端无需升级。现有节点保留旧版兼容，只有管理员设置独立密码后才切换密码验证。

## 实现与边界
- 指定程序沿用经过哈希校验的ProxyLane1.3.5组件，每程序独立会话，不强制结束用户程序。
- 全局采用独立sing-box1.14.4进程，手动开启才请求UAC；默认无全局接管，冲突检测不会关闭FlClash。
- 全局真正接管时会临时配置专用TUN/路由/DNS策略；不能称“全局不改路由”。本轮未在当前FlClash网络上开启TUN。
- 网站口令与节点使用密码分开。节点密码仅服务器scrypt盐哈希保存；成功认证返回受限、可撤销的节点凭据。
- 新连接卡仅含节点标识/备注/服务器/需密码标记，无代理密码或SSH私钥。
- GOST使用认证及目标请求策略回调再次检查节点身份/凭据代数，防止改密前已认证的SOCKS会话延后发CONNECT绕过撤销。
- 后端本机18783只供受保护插件调用；公网只在既有443增加一个密码认证交换POST，不开放公网代理端口。
- 原网站首页/账号数据库/SSH/旧V1和FlClash保留；V2控制/代理及管理网关按用户批准定向更新。

## 验证
22/22本机密码策略，16/16生产密码/新客户端链路，7/7多程序隔离，9/9网站HTTPS回归。
全局通过官方内核配置校验、冲突阻止与非TUN TCP/UDP运行测试；实际TUN创建/接管/回收和具体游戏未在本轮实测。
Windows原生截图接口超时；控件可访问性状态已检查，网页有真实截图，未用离线绘图冒充实机截图。
完整证据见evidence；测试只针对自建临时节点，已清理。现有1个旧版节点保留，测试时它处于离线。

## 源码、许可与重建
source/Build.ps1使用Windows .NET Framework4.x x64编译连接器及手动全局辅助程序。
许可证和sing-box对应版本原始源代码归档随包提供；其go.mod/go.sum及构建脚本保留在源码归档中，可按上游说明获取依赖和重建。
GOST和ProxyLane为保留的未修改发布组件；统一界面复用既有启动/生命周期逻辑。sing-box为外部独立进程，不宣称与上游有从属关系。
- [GOST项目](https://github.com/go-gost/gost)，[认证插件](https://gost.run/concepts/auth/)，[用户身份策略](https://gost.run/concepts/bypass/)
- [ProxyLane 1.3.5](https://github.com/threatexpert/ProxyLane/tree/v1.3.5)
- [sing-box1.14.4](https://github.com/SagerNet/sing-box/tree/v1.14.4)，[TUN配置](https://sing-box.sagernet.org/configuration/inbound/tun/)

不要重跑历史部署脚本；运维与回退见server/OPERATIONS.md。
