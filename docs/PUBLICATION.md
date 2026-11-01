# 公开范围、隐私和许可

[首页](../README.md)

## 公开范围

所有者于2026-11-01要求补充详细功能与用法，并将 `MIZAZA3/HomeRelay-Archived` 设为公开。公开内容为脱敏源码、历史快照、第三方许可、说明和精选证据，不恢复原部署、不重新开端口或修改FlClash。

不公开管理/设备私钥、密码、注册令牌、master、生产配置、身份、运行数据库、浏览器资料、网站业务数据、云账号页面/截图、完整私有备份、原始未脱敏证据或第三方二进制/驱动。原IP、域名、节点/家宽标识已替换为示例。

## 公开前检查

- 扫描收录工作树和全部本地可达Git提交/对象，不只最后diff。
- 与私有配置收集的42个已知敏感值精确比对，另查私钥、常见GitHub/云令牌、原部署标识、用户路径和家宽地址。
- 核对二进制/数据库/身份/私有目录排除、逐文件SHA-256清单及远端树。
- 本次重新运行纯单元、前端合成测试、Python AST与Markdown本地链接检查；实际版本/结果由验收记录补充在本页。

这属于脱敏/一致性检查，不是完整漏洞审计，不证明未知秘密或运行风险为零。夹具密码、占位符和公开DNS不提供真实服务。

### 本次本地文档整理回归

2026-11-01，Windows环境：Python 3.14.7、Node v24.22.1。生命周期16项、传输健康19项、稳定性14项、目标策略合成测试、密码/限速前端两组及JS语法检查通过。传输健康属于V4.5草稿测试，不代表已上线或用户VM通过。276个Python源文件AST解析、新文档45个本地链接检查均通过；没有重新跑公网/驱动/TUN/游戏测试，也没有重部署服务。

## 历史语境

current/docs和history保留当时的“当前在线/已发布”等描述；以本仓库首页和RETIREMENT_STATUS.json为当前状态入口。current含未发布V4.5；V4.4为最后上线阶段。真实VM/游戏故障和中断记录保留，不用协议测试冒充最终验收。

## 许可

**公开可读不等于自动授予统一开源许可。** 本次没有替所有者给原创代码库新增MIT/GPL等授权或决定商用、再分发条款。

第三方保留原许可证，见[notices](../notices)与[来源](../current/docs/SOURCES.md)。GOST、FlClash、sing-box、ProxyLane、Chromium机制和cryptography等各自许可不能相互替代；仓库没有附带它们的EXE/DLL/SYS。

若后续正式采用开放源代码许可证，需权利人核实原创/第三方边界后另行选择；本次仅公开归档和说明。

## 官方依据

- [GOST](https://github.com/go-gost/gost) · [SS/SSU](https://gost.run/en/tutorials/protocols/ss/)
- [FlClash](https://github.com/chen08209/FlClash) · [mihomo SS字段](https://wiki.metacubex.one/config/proxies/ss/)
- [GitHub可见性说明](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)

历史兼容版本不是对官方项目当前版本的测试结论；新部署需单独核对维护状态、依赖和安全更新。
