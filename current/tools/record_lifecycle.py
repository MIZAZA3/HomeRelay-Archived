"""Append this backend delivery only; preserve all other chats' website work."""
import hashlib,json,pathlib

project=pathlib.Path(r'C:\Users\YOUR_USER\Documents\ChatGPT\网站开发')
delivery=pathlib.Path('D:/CodexTools/HomeRelayDirectV4')
package=json.loads((delivery/'evidence/source-package-v4.4.json').read_text('utf-8'))
marker='<!-- HOME-RELAY-LIFECYCLE-V44-20261101 -->'
status='''

## 家宽 V4.4 连接生命周期修复（2026-11-01，北京时间）
<!-- HOME-RELAY-LIFECYCLE-V44-20261101 -->
- 用户明确SSTap/浏览器在虚拟机，不能用宿主FlClash系统代理推断VM双代理；本次不改宿主/VM网卡、路由或TLS。线上抓到32条gate/朋友通道连续30秒满额而公网无活跃TCP；隔离真实GOST复现36次DNS仅32次成功、随后TCP失败。另SQLite事务上下文未close，250次读取在禁用GC时FD增长345；线上约413个DB相关FD，但未证实触顶2048。
- 已定向发布：完成全部响应且无进行中数据的DNS-only UDP在压力下回收，保留TCP/非DNS/半帧/未完成查询，等待handler finally释放容量并最终重检查；SQLite业务事务finally close、无事务WAL anchor；私有0600诊断仅低敏计数，不存域名/内容/密码。保持32节点/64全局连接、双向合计256KiB/s及公网解析后校验固定、UID无直出、CPU/内存/FD限制。
- 112/112隔离集成 +14/14稳定性单元 +16/16生命周期单元、目标策略与密码/限速前端单元通过；含72次GOST DNS会话复用、TCP half-close、rollback及250次DB读取FD增量0。公网最终40/40 DNS、5/5原源socket复用、4/4游戏网址/IP77 HTTPS200，独立标准SS TCP/UDP通过，当次出口203.0.113.30；5负例/11端口通过。真实VM SSTap/游戏最终仍需用户使用确认，不能称所有站长期零故障。
- 首轮公网3秒等待24/40，10秒38/40、两次容量误拒绝促使并发单元先复现再修最后一次容量检查；最终复测曾因朋友关掉出口而中断，用户确认“刚才关了，现在重新启动”，重启后心跳/通道/TCPUDP恢复再完成验收；保留原失败与中断证据，不全部归咎同一bug。
- 初始备份/var/backups/home-relay-lifecycle/20261101T075400Z，最终竞争边界补丁备份/var/backups/home-relay-lifecycle/20261101T080748Z。仅controller.py/target_policy.py及新增flow_lifecycle.py，controller最终2260008；web2154018/SSH2072001、3业务容器ID/启动时间及FlClash10280/12364/3732保持；首页e320ce55…/路由bf2f76e7…、防火墙不变。当前自定义密码rev5、限速rev3、权限/身份/密文/密码历史原样保留；仅成功检测更新展示元数据，不整库回退。
- 源码C:/Users/YOUR_USER/Documents/ChatGPT/代理工具；D:/CodexTools/HomeRelayDirectV4/LIFECYCLE_V44.md和HomeRelayDirectV4.4-source.zip交付，历史V4/V4.1/V4.2/V4.3保留。源码ZIP SHA256：ARCHIVE_SHA。临时测试进程/31980/31990/服务器31870已清理；UI仍V4.2，不需朋友换软件或用户改密码。68工具编号/进度不改。
'''.replace('ARCHIVE_SHA',package['archive_sha256'])
log='''

<!-- HOME-RELAY-LIFECYCLE-V44-20261101 -->
| 2026-11-01（北京时间） | 本聊天，家宽V4.4生命周期定向发布者 | 用户反复不连通，明确运行于VM | 旧DNS占满32槽/DB句柄积累实证；112隔离+14稳定+16生命周期+前端单元；公网40DNS/5复用/4HTTPS和TCPUDP、5负例/11端口 | 3后端源文件，controller定向重启；备份/var/backups/home-relay-lifecycle/20261101T075400Z和080748Z；含末次回收后的竞争检查 | 自定义密码rev5/限速rev3、网站/SSH/FlClash/防火墙均保留；朋友中途关闭出口的离线已确认并重启恢复，历史失败不抹去；VM GUI和长期效果不冒充验收 | D:/CodexTools/HomeRelayDirectV4/LIFECYCLE_V44.md和V4.4源码；0600诊断无目标内容；68工具进度不变 |
'''
backup=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/lifecycle-baseline/website-before-v44')
backup.mkdir(parents=True,exist_ok=True)
for name,addition in [('PROJECT_STATUS.md',status),('MANAGEMENT_WORKLOG.md',log)]:
    p=project/name
    if not (backup/name).exists():(backup/name).write_bytes(p.read_bytes())
    if marker not in p.read_text('utf-8'):
        with p.open('a',encoding='utf-8',newline='') as stream:stream.write(addition)
manifest=project/'MANIFEST.json';before=manifest.read_bytes();data=json.loads(before)
if not (backup/'MANIFEST.json').exists():(backup/'MANIFEST.json').write_bytes(before)
changed={}
for row in data['files']:
    if row['path'] in ['PROJECT_STATUS.md','MANAGEMENT_WORKLOG.md']:
        b=(project/row['path']).read_bytes();changed[row['path']]=b
        row.update(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
assert len(changed)==2
assert manifest.read_bytes()==before,'Concurrent manifest edit; retry from latest'
assert all((project/name).read_bytes()==b for name,b in changed.items()),'Concurrent record edit; retry'
manifest.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n','utf-8')
print('Updated only the two infrastructure records and their manifest rows.')
