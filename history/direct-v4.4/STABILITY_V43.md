# V4.3 稳定性修复交付

2026-11-01，北京时间。针对用户报告 SSTap 浏览器 `ERR_CONNECTION_CLOSED` 和后续偶发转发失败。

## 已上线

1. **DNS有界排队**：12并发原来4成功/8直接拒绝，现14项单元及实际标准SS回归验证排队成功；同时查询数仍4，同名20请求只解析1次。最多64个不同待处理名字，查询总等待8秒，超时后未结束的native工作仍占槽，不向线程池堆无界任务。某个请求取消不会取消其他请求共享的解析。
2. **UDP会话复用**：等待新UDP帧的首字节允许180秒，读到半帧后仍15秒超时，拒绝空 / 分片 / 非公网目标规则保留；GOST SS UDP listener TTL从30改120秒。不是永久保活。
3. **浏览器并发**：认证数据连接每节点16→32，全局64不变。20条同时标准SS TCP连接均能传输数据；上传/下载仍与其他连接共用节点额度和全局256KiB/s，不因并发提高带宽。
4. 保留所有DNS答案公网校验和数字IP固定。按系统DNS顺序优先IPv4，不再用IP字符串字典序排序固定最小值；仍在中转解析，不新增出口侧DNS查询。

## 真实状态保护

- 只定向替换3个服务器源文件，备份 `/var/backups/home-relay-stability/20261101T063121Z`；只重启controller（PID2217643），没有重启网站、SSH、HomeRelay web或FlClash。
- 用户真实自定义密码revision5、限速revision3、身份/密文/历史/配置逐项相同，没有代用户换密、改速、开端口或改任何系统代理/TUN。
- 3个业务容器healthy，ID/启动时间保持；SSH2072001 / web2154018保持；FlClash10280 / Core12364 / Helper3732保持。
- 最新首页e320ce55…与路由bf2f76e7…前后相同。UFW、UID隔离、CPU25%/内存256MiB/FD2048限制不变；复测时控制组约59MiB，NRestarts=0。

## 验证

- **106/106 隔离集成**，包括原密码 / 撤销 / 限速 / 内网防护，并新增20并发、UDP空闲17秒后复用。
- **14/14 稳定性单元**，另保留目标策略合成安全单元、前端密码/限速单元。
- 公网独立标准SS客户端 TCP HTTPS + UDP DNS均通过，检测出口为 `203.0.113.30`（当次结果，不是保证固定）。同一个UDP socket、SOCKS控制关联，空闲35秒后首个查询成功。
- `ip77.net`两轮HTTPS200，约3.42/2.68秒；`myip.ipip.net`两轮HTTPS200，约3.18/3.16秒。
- **未解决的目标访问**：`api.ipify.org`两轮TLS EOF；此前直接朋友数值目标通道对照也失败。`4.ipw.cn`的HTTPS测试也TLS EOF；没有断言该服务一定支持这条HTTPS访问路径，也不把它当成全网稳定性证明。这些失败留原记录，没有标成通过。
- 服务器私有检测前端末次 `probe` 是 TCP失败 / UDP通过（它只尝试myip/api两个查询目标），与外部独立SS客户端当次TCP/UDP均成功的结果并列保留。不能把单个检测API不稳定等同于所有代理流量失败；本轮未改这个检测接口，也不把它标成通过。
- 错误SS密码、服务器管理地址、回环与两类元数据负例通过；11个预期端口回归通过；UID无公网直出保护保留。
- 临时本地31980/31990测试进程已停止，未接管用户任何应用。没有实际启动SSTap TAP / 游戏 / FlClash TUN，不能把标准SS协议测试等同于这些GUI全部通过。

## 没有发布的额外方案

曾隔离测试“出口侧DoH加密DNS”，希望改进跨地域解析；真实朋友路径既有成功也有超时，未达到发布要求。该原型不在生产服务或源码ZIP中；仅实验源保留在私有工作目录，证据保留。没有为了让网站打开而关内网校验、关证书校验或让服务器直接出网。

## 使用

朋友不用换软件或重新报到。用户侧SSTap断开再连接一次，沿用当前参数；可先用 `ip77.net`复测。管理网页如因后端重启提示会话过期，重新登录即可。若某站仍失败，结合该时刻SSTap/浏览器日志区分出口路径、目标站与双代理接管，不反复盲目换密。

证据目录：`D:/CodexTools/HomeRelayDirectV4/evidence/`：
`stability-v43-integration.txt`、`stability-v43-deploy.json`、`stability-v43-public-sites.txt`、`stability-v43-public-udp-idle.json`、`stability-v43-public-negative.txt`、`public-ports-v43.json`、`stability-v43-final-server.json`、`stability-v43-post-public.json`。
