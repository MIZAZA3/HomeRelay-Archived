"""Append only this infrastructure delivery's records; refresh only their manifest rows."""
import hashlib,json,pathlib,subprocess
project=pathlib.Path(r'C:\Users\YOUR_USER\Documents\ChatGPT\网站开发')
marker='<!-- HOME-RELAY-DIRECT-V4-20261101 -->'
status='''

## 家宽标准加密直连 V4（2026-11-01，北京时间）

<!-- HOME-RELAY-DIRECT-V4-20261101 -->
- 用户批准：旧“接收器/连接器”彻底不用，直接改现有 /relay-admin/；SSTap 1.0.9.7、FlClash 直接使用服务器标准加密节点；保留网站、朋友自动报到和 FlClash。云端新增 UDP 24443 已单独在操作时确认，仅此一条；TCP 24443 复用而非遗留。
- 已发布：面板查看/复制标准 SS 参数、SSTap 链接、下载 FlClash YAML、独立随机密码更换/撤销、启用/闲置/停用。旧连接卡、consumer 认证已退出；旧 V1 与旧 V2 proxy 服务 stopped/disabled/masked，旧接收器和 V1 publisher 的 SSH key/forward 权限撤销；保留 gost-home-auto 反向 SSH 和 admin。旧 18783 与未登记节点的空闲 loopback gate/probe 端口不再监听。
- 新结构：保留 controller/web 单元，controller 非特权 UID 996 监督一个 GOST 3.3.2 子进程，Unix API 私有目录0700/socket0600+认证；标准 SS/SSU aes-256-gcm，generation gate 每次新建和数据读写检查节点状态、45秒心跳和凭据版本，改密/撤销主动断本节点连接，无服务器直出回落。新增 UID-only IPv4/IPv6 OUTPUT 隔离，CPU25%/256MiB 控制器+GOST总限额，原限速/并发保留。
- 26/26 隔离命名空间测试，公网独立 sing-box 标准 SS 的 TCP HTTPS/UDP DNS 均通过，出口203.0.113.30；公网错误密码、loopback/服务器管理/元数据目标负例均通过；导出 YAML 解析/字段校验通过。未下载或开启 SSTap TAP，未实际向 FlClash 导入配置/开启 TUN，不将协议测试冒充这两个GUI实测。
- 原生产节点仅1个，id00000000000000000000000000000001/state enabled/密码revision2保留；未为测试换密、撤销、删除或整库恢复真实朋友节点。出口来源IP与目标所见出口IP可不同，不能用历史IP断言失败。
- 当前仅开放 slot0 的24443/TCP+UDP；新节点依然自动报到，但每节点独立端口需单独在云/UFW开通并加入direct_open_slots，未发布前不导出配置。不声称容量32即已开放32节点端口。
- 共享站点仅移除旧consumer独立include，保留其余路由；nginx-t后一次优雅reload、SSH-t后只reload。主页SHA256仍161157e1a9663210f6018c113bdebb2238684a711438c33a9cfead8ad5fe8610，最终路由bbac310526ffc64929f32a1cda0e3ad850e4d938aacac02d7a5d49deb0334f3b；主页/面板/图片工具HTTPS200，旧consumer POST404，3业务容器healthy，SSH主PID2072001保留。
- 本机旧连接器PID15008及其GOST41304已定向停止，11081–11083不再监听；临时测试客户端/31980–31990已停止。未终止Edge工作；FlClash/Core/Helper原PID10280/12364/3732保留，不动系统代理/路由/配置/订阅/驱动。
- 源码：C:/Users/YOUR_USER/Documents/ChatGPT/代理工具；交付文档、源ZIP和证据D:/CodexTools/HomeRelayDirectV4/；生产root-only定向备份/var/backups/home-relay-direct-v4/20261031T194807Z。回退必须保留最新凭据版本/撤销，不恢复旧整库或整站路由/SSH配置复活旧授权。此模块不属于68工具，不改变任务编号/进度。
'''
log='''

<!-- HOME-RELAY-DIRECT-V4-20261101 -->
| 2026-11-01（北京时间） | 本聊天，家宽 Direct V4 定向发布者 | 用户废弃接收器，改原面板为 SSTap/FlClash 标准加密直连并清理旧权限/端口 | GitHub/官方兼容依据、26/26隔离、独立SS公网TCP/UDP及5负例、YAML、真实面板、SSH/nginx与网站健康 | 定向备份/var/backups/home-relay-direct-v4/20261031T194807Z；24443复用为SS，云仅另确认UDP24443；只reload SSH/OpenResty，不重启业务 | 原节点/第2版密码保留，首页哈希不变、3业务healthy、FlClash原3PID保留；旧接收器/V1权限和服务退役，未登记端口无监听 | D:/CodexTools/HomeRelayDirectV4/README.md与OPERATIONS.md；新节点端口另行开通，未实开SSTap/FlClash全局；68工具进度不变 |
'''
for name,addition in [('PROJECT_STATUS.md',status),('MANAGEMENT_WORKLOG.md',log)]:
    p=project/name
    if marker not in p.read_text('utf-8'):
        with p.open('a',encoding='utf-8',newline='') as f:f.write(addition)
manifest=project/'MANIFEST.json';before=manifest.read_bytes();data=json.loads(before)
backup=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/baseline/website-manifest-before-v4.json')
if not backup.exists():backup.write_bytes(before)
changed=[]
for row in data['files']:
    if row['path'] in ['PROJECT_STATUS.md','MANAGEMENT_WORKLOG.md']:
        b=(project/row['path']).read_bytes();row.update(bytes=len(b),sha256=hashlib.sha256(b).hexdigest());changed.append(row['path'])
assert len(changed)==2
assert manifest.read_bytes()==before,'Concurrent manifest edit; retry from latest'
manifest.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n','utf-8')
print('Updated only manifest rows: '+', '.join(changed))
