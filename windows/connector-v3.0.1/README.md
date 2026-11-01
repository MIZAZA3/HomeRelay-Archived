# 家宽连接器 3.0.1

修复 3.0 对 Edge 后台进程（例如 `--no-startup-window`）的过度拦截。

## 本次变化
- Edge / Chrome / Brave / Chromium / Vivaldi 从连接器启动时，使用本次会话独有的临时资料目录和独立窗口；不用先关闭普通浏览器。
- 代理引擎仍只接管本次启动的进程及勾选的同路径子进程，不接管已有浏览器；浏览器必须保留“同路径子进程”勾选。
- 临时窗口不共享原浏览器的登录、扩展、历史；退出本次浏览器及后台子进程后尽力清理临时资料，不处理普通浏览器资料。异常退出或文件占用可能留下本工具 `sessions` 内的临时文件。
- 检查用户启动参数，拒绝覆盖独立资料目录、代理设置等冲突参数。未添加关闭浏览器沙箱或证书校验的参数。
- 其他程序仍保留 3.0 的已有进程检查；多程序、节点密码、本机 SOCKS5/HTTP/SS、手动全局模式保持原设计。

## 使用
1. 退出旧连接器 3.0，不需要关闭普通 Edge 或 FlClash。
2. 使用本目录中已准备的 `HomeRelay-统一连接器-3.0.1/HomeRelayConnector.exe`，或完整解压通用 ZIP 后运行。
3. 连接节点，选中 Edge，保留“同路径子进程”，点击“启动勾选程序并代理”。在新打开的独立窗口中访问网页。
4. 本机准备版已经迁移当前用户的加密连接卡与程序列表；ZIP 是不含个人配置的通用包。节点使用密码仍需输入，不保存。

## 不变的边界
本轮没有修改或重启服务器、网站、节点服务、普通 Edge、FlClash；没有启用全局 TUN，也没有修改系统代理、物理网卡或路由。全局功能仍默认关闭，沿用 3.0 的冲突检测；本次未实际测试全局 TUN。

## 验证与源码
见 `验收报告.md`、`evidence/`。`source/Build.ps1` 构建连接器与全局辅助程序；第三方组件与许可证同 3.0，完整运行包携带所需组件。

独立浏览器资料目录机制参考 Chromium 官方说明：
https://www.chromium.org/developers/creating-and-using-profiles/
https://chromium.googlesource.com/chromium/src.git/+/HEAD/docs/user_data_dir.md

实测网页截图由 Edge 自身的无头模式生成，使用与 GUI 指定程序相同的 `Session.Start` 路径，不等同于已经对全部浏览器功能或 GUI 交互完成验收：
https://developer.chrome.com/docs/automation-and-testing/headless-cli
