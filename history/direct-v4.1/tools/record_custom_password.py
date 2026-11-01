"""Append V4.1 delivery and update only the two edited manifest rows."""
import hashlib,json,pathlib
root=pathlib.Path(r'C:\Users\YOUR_USER\Documents\ChatGPT\网站开发')
marker='<!-- HOME-RELAY-CUSTOM-PASSWORD-V41-20261101 -->'
status='''

## 家宽 V4.1 自定义节点密码（2026-11-01，北京时间）

<!-- HOME-RELAY-CUSTOM-PASSWORD-V41-20261101 -->
- 用户确认想手动输入密码，而非只随机换密；已在原 /relay-admin/ 增加“设置 / 更换节点密码”空白双输入窗口，提供“保存自定义密码”和“随机生成并更换”，参数只读区另有同入口。打开窗口不换密，不代用户输入或保存真实密码。
- 8–128字符/双次一致/无控制字符；后端仍先登录与CSRF，写操作串行、期望revision冲突保护，拒绝当前及本功能记录的近期64条旧密码指纹。新增ss_secret空默认列和node_password_history表，不清库、不改旧版本。自定义密码使用系统已安装cryptography41.0.7的Fernet认证加密，存储密钥绑定节点/slot/revision；随机密码派生、SS aes-256-gcm及朋友Agent协议不变，撤销清空密文，坏密文不回落其他密钥。
- 生产定向备份/var/backups/home-relay-custom-password/20261031T211101Z（北京时间05:11:01）；只更新6个源文件、定向重启controller，web PID1936706/SSH2072001保持，未修改服务单元、云/UFW、Nginx、SSH权限或主站。原唯一节点enabled、第4版密码和updated逐项相同；主页与公共路由哈希分别保持161157e1a9663210f6018c113bdebb2238684a711438c33a9cfead8ad5fe8610 / bbac310526ffc64929f32a1cda0e3ad850e4d938aacac02d7a5d49deb0334f3b。
- 46/46隔离命名空间集成：通过实际鉴权API写入自建节点密码，标准SS TCP/UDP、旧密失效、随机/自定义切换、近期旧密码重用/并发版本拦截、撤销、密文篡改/跨节点绑定、其他节点隔离均通过。前端合成DOM/模拟fetch单元通过。正式浏览器确认两个字段可编辑且为空，保留给用户自行提交；证据custom-password-dialog.png。
- 公网原第4版回归：首次TCP超时而UDP通过，期间真实出口端心跳短暂超45秒；服务器节点检测TCP/UDP通过，节点重新在线后外部独立标准SS客户端重测TCP/UDP均通过，出口203.0.113.30。原始失败与重测证据均保留，未伪造心跳或修改朋友网络。FlClash/Core/Helper原PID10280/12364/3732不变，临时31980测试监听关闭。
- 当前源码/文档与新V4.1 ZIP在D:/CodexTools/HomeRelayDirectV4/，旧V4 ZIP保留；测试未修改真实节点密码。用户保存过自定义密码后不能回退不支持密文的旧V4模块，否则实际密码会被意外改变；保留最新密文、历史指纹与版本，不整库回滚。68工具编号/完成度不变。
'''
log='''

<!-- HOME-RELAY-CUSTOM-PASSWORD-V41-20261101 -->
| 2026-11-01（北京时间） | 本聊天，家宽 V4.1 自定义密码 | 用户明确需要自己填写节点密码 | 46/46隔离/真实鉴权API、前端单元、原随机密钥公网TCP/UDP重测、正式空白可编辑窗口 | 6源文件定向更新，备份/var/backups/home-relay-custom-password/20261031T211101Z；只重启controller，新增密文列/有限HMAC历史，不动网站/SSH/云防火墙 | 生产节点原第4版/updated保留，主页/路由hash不变，web/SSH/FlClash原PID保留；首次出口心跳抖动超时与重测成功均记录 | D:/CodexTools/HomeRelayDirectV4/README.md及V4.1源码ZIP；真实密码交用户输入，不恢复不支持密文的旧模块/旧整库；68工具进度不变 |
'''
for name,addition in [('PROJECT_STATUS.md',status),('MANAGEMENT_WORKLOG.md',log)]:
    p=root/name
    if marker not in p.read_text('utf-8'):
        with p.open('a',encoding='utf-8',newline='') as f:f.write(addition)
p=root/'MANIFEST.json';raw=p.read_bytes();data=json.loads(raw)
backup=pathlib.Path('D:/CodexWork/HomeRelayDirectV4/custom-password-baseline/website-manifest-before-v41.json')
if not backup.exists():backup.write_bytes(raw)
count=0
for row in data['files']:
    if row['path'] in ['PROJECT_STATUS.md','MANAGEMENT_WORKLOG.md']:
        b=(root/row['path']).read_bytes();row.update(bytes=len(b),sha256=hashlib.sha256(b).hexdigest());count+=1
assert count==2 and p.read_bytes()==raw
p.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n','utf-8')
print('Appended V4.1 records and refreshed only their two manifest entries.')
