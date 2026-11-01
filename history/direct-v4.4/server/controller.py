#!/usr/bin/python3
"""HomeRelay Direct V4: bounded enrollment/control plane and loopback data gates.
No shell, cloud API, website writes, or SSH management keys. Fixed GOST child only.
"""
import sys
import direct_proxy
import credential_admin
import node_limits
import target_policy
import flow_lifecycle
import contextlib
import atexit
import asyncio, base64, collections, hashlib, hmac, http.cookies, ipaddress, json, os, pathlib, re, secrets, socket, sqlite3, ssl, struct, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).parent
STATE = pathlib.Path(os.environ.get('RELAY_STATE', '/var/lib/home-relay-v2'))
CONFIG = pathlib.Path(os.environ.get('RELAY_CONFIG', str(pathlib.Path(os.environ.get('CREDENTIALS_DIRECTORY','/etc/home-relay-v2'))/'access.json')))
CFG = json.loads(CONFIG.read_text())
MAX_NODES = int(CFG.get('max_nodes',32))
LOCK=threading.RLock(); SESSIONS={}; LINKS={}; LIMITS={}; LOOP=None; LIVE=collections.defaultdict(set); PW_SLOT=threading.BoundedSemaphore(1)

DB_ANCHOR=None
@contextlib.contextmanager
def db():
 c=sqlite3.connect(STATE/'nodes.sqlite3',timeout=5); c.row_factory=sqlite3.Row
 try:
  with c:yield c
 finally:c.close()
def init():
 global DB_ANCHOR
 STATE.mkdir(parents=True,exist_ok=True)
 with db() as c:
  c.execute('PRAGMA journal_mode=WAL')
  c.execute('CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, pubkey TEXT NOT NULL UNIQUE, slot INTEGER UNIQUE NOT NULL, state TEXT NOT NULL DEFAULT "pending", label TEXT NOT NULL, created REAL, seen REAL, ip TEXT, version TEXT, tunnel INTEGER DEFAULT 0, exit_ip TEXT DEFAULT "", test_time REAL DEFAULT 0, tcp INTEGER DEFAULT 0, udp INTEGER DEFAULT 0)')
  c.execute('CREATE TABLE IF NOT EXISTS audit(time REAL, action TEXT, node TEXT, detail TEXT)')
  c.execute('CREATE TABLE IF NOT EXISTS node_access(node_id TEXT PRIMARY KEY, mode TEXT NOT NULL, salt TEXT NOT NULL DEFAULT "", pw_hash TEXT NOT NULL DEFAULT "", revision INTEGER NOT NULL DEFAULT 1, updated REAL NOT NULL)')
  columns={row[1] for row in c.execute('PRAGMA table_info(node_access)')}
  if 'ss_secret' not in columns:c.execute("ALTER TABLE node_access ADD COLUMN ss_secret TEXT NOT NULL DEFAULT ''")
  c.execute('CREATE TABLE IF NOT EXISTS node_password_history(node_id TEXT NOT NULL,digest TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(node_id,digest))')
  c.execute('CREATE TABLE IF NOT EXISTS node_limits(node_id TEXT PRIMARY KEY,upload_kib INTEGER NOT NULL DEFAULT 0 CHECK(typeof(upload_kib)="integer" AND upload_kib BETWEEN 0 AND 256),download_kib INTEGER NOT NULL DEFAULT 0 CHECK(typeof(download_kib)="integer" AND download_kib BETWEEN 0 AND 256),revision INTEGER NOT NULL DEFAULT 1,updated REAL NOT NULL)')
  c.execute('INSERT OR IGNORE INTO node_limits(node_id,updated) SELECT id,? FROM nodes',(time.time(),))
  # Preserve existing nodes until their administrator deliberately changes access.
  c.execute('INSERT OR IGNORE INTO node_access(node_id,mode,updated) SELECT id,"legacy",? FROM nodes',(time.time(),))
 # Keep WAL open without a read/write transaction; every business connection closes.
 if DB_ANCHOR is None:
  DB_ANCHOR=sqlite3.connect(STATE/'nodes.sqlite3',timeout=5)
  cursor=DB_ANCHOR.execute('SELECT count(*) FROM sqlite_master');cursor.fetchall();cursor.close()
  atexit.register(DB_ANCHOR.close)

def derive(label,slot):return hmac.new(bytes.fromhex(CFG['master']),f'{label}/{slot}'.encode(),hashlib.sha256).hexdigest()
def hashed(secret):return hmac.new(bytes.fromhex(CFG['master']),secret.encode(),hashlib.sha256).hexdigest()
def node(nid):
 with db() as c:return c.execute('SELECT * FROM nodes WHERE id=?',(nid,)).fetchone()
def access(nid):
 with db() as c:return c.execute('SELECT * FROM node_access WHERE node_id=?',(nid,)).fetchone()
def pw_hash(pw,salt):return hashlib.scrypt(pw.encode('utf-8'),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
def rate(key,limit,period):
 with LOCK:
  now=time.time()
  if key not in LIMITS and len(LIMITS)>=4096:return False
  q=LIMITS.setdefault(key,collections.deque())
  while q and q[0]<now-period:q.popleft()
  if len(q)>=limit:return False
  if len(LIMITS)>2048:
   for k in list(LIMITS)[:1024]:
    if not LIMITS[k] or LIMITS[k][-1]<now-3600:LIMITS.pop(k,None)
  q.append(now);return True
def audit(action,nid,detail=''):
 with db() as c:
  c.execute('INSERT INTO audit VALUES(?,?,?,?)',(time.time(),action,nid,detail[:160]))
  c.execute('DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY rowid DESC LIMIT 1000)')
def valid_key(value):
 if not isinstance(value,str) or len(value)>1500:return False
 p=value.split()
 if len(p)!=2 or p[0] not in ('ssh-ed25519','ssh-rsa'):return False
 try:
  b=base64.b64decode(p[1],validate=True);n=int.from_bytes(b[:4],'big')
  return 32<len(b)<1100 and b[4:4+n].decode('ascii')==p[0]
 except Exception:return False
def auth_node(data):
 n=node(str(data.get('id','')))
 if not n or not isinstance(data.get('secret'),str) or not hmac.compare_digest(n['secret_hash'],hashed(data['secret'])):return None
 return n
def public_info(n):
 now=time.time();a=access(n['id']);return {'id':n['id'],'limits':LIMITER.view(n['id']),'label':n['label'],'state':n['state'],'online':now-n['seen']<45,'connection_ip':n['ip'],'last_seen':n['seen'],'created':n['created'],'version':n['version'],'tunnel_ready':bool(n['tunnel']) and now-n['seen']<45,'exit_ip':n['exit_ip'],'test_time':n['test_time'],'tcp':bool(n['tcp']),'udp':bool(n['udp']),'slot':n['slot'],'usage_mode':a['mode'] if a else 'unset','usage_revision':a['revision'] if a else 0,'password_kind':'custom' if a and a['ss_secret'] else 'random','direct_port':direct_proxy.public_port(CFG,n['slot']),'direct_published':n['slot'] in CFG.get('direct_open_slots',[]),'direct_ready':n['id'] in ENGINE.ready}
def agent_info(n):
 r={'id':n['id'],'label':n['label'],'state':n['state'],'interval':10}
 if n['state'] in ('enabled','idle'):
  r.update(remote_port=22000+n['slot'],home_password=derive('home',n['slot']),ssh_user='gost-home-auto')
 return r
def cookie_session(handler):
 try:
  ck=http.cookies.SimpleCookie(handler.headers.get('Cookie',''));s=SESSIONS.get(ck['relay_session'].value)
  return s if s and s['until']>time.time() else None
 except Exception:return None

class BoundedServer(ThreadingHTTPServer):
 daemon_threads=True;allow_reuse_address=True
 def __init__(self,addr,public):self.public=public;self.slots=threading.BoundedSemaphore(24);super().__init__(addr,Handler)
 def process_request(self,req,addr):
  if not self.slots.acquire(False):req.close();return
  super().process_request(req,addr)
 def process_request_thread(self,req,addr):
  try:super().process_request_thread(req,addr)
  finally:self.slots.release()

class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def setup(self):super().setup();self.connection.settimeout(15)
 def log_message(self,*args):pass
 def send(self,obj,status=200,extra=None,kind='application/json; charset=utf-8'):
  b=json.dumps(obj,ensure_ascii=False).encode() if kind.startswith('application/json') else obj
  self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
  for k,v in (extra or {}).items():self.send_header(k,v)
  self.end_headers();self.wfile.write(b)
 def origin_ok(self):
  port=CFG.get('admin_port',18780);allowed={f'127.0.0.1:{port}',f'localhost:{port}'}
  if self.headers.get('Host') not in allowed:return False
  o=self.headers.get('Origin');return not o or o in {f'http://{x}' for x in allowed}
 def do_GET(self):
  if self.server.public:return self.send({'error':'not found'},404)
  if not self.origin_ok():return self.send({'error':'invalid host/origin'},403)
  if self.path.startswith('/login-link?code='):
   token=self.path.removeprefix('/login-link?code=')
   with LOCK:item=LINKS.pop(token,None)
   if not item or item['until']<time.time():return self.send({'error':'登录链接已过期'},403)
   self.send_response(303);self.send_header('Location','/');self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Length','0');self.send_header('Set-Cookie',f'relay_session={item["sid"]}; HttpOnly; SameSite=Strict; Path=/');self.end_headers();return
  files={'/':('panel.html','text/html; charset=utf-8'),'/app.js':('app.js','application/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
  if self.path in files:
   f,t=files[self.path];return self.send((ROOT/f).read_bytes(),kind=t)
  s=cookie_session(self)
  if not s:return self.send({'error':'请先登录'},401)
  if self.path=='/api/nodes':
   with db() as c:rows=c.execute('SELECT * FROM nodes ORDER BY created DESC').fetchall()
   return self.send({'nodes':[public_info(n) for n in rows],'csrf':s['csrf'],'capacity':MAX_NODES,'total_rate_kib':256})
  return self.send({'error':'not found'},404)
 def do_POST(self):
  try:
   if self.headers.get_content_type()!='application/json':return self.send({'error':'json required'},415)
   size=int(self.headers.get('Content-Length','-1'))
   if not 0<size<=8192:return self.send({'error':'body size'},413)
   data=json.loads(self.rfile.read(size))
   if not isinstance(data,dict):raise ValueError('object required')
   if self.server.public:return self.agent(data)
   if not self.origin_ok():return self.send({'error':'invalid host/origin'},403)
   if self.path=='/api/login':
    if not rate('admin-login',10,60):return self.send({'error':'请稍后再试'},429)
    pw=str(data.get('password',''))
    if len(pw)>200:return self.send({'error':'认证失败'},403)
    value=hashlib.scrypt(pw.encode(),salt=bytes.fromhex(CFG['password_salt']),n=16384,r=8,p=1).hex()
    if not hmac.compare_digest(value,CFG['password_hash']):return self.send({'error':'认证失败'},403)
    sid=secrets.token_urlsafe(32);s={'csrf':secrets.token_urlsafe(24),'until':time.time()+28800}
    with LOCK:
     for k in list(SESSIONS):
      if SESSIONS[k]['until']<time.time():SESSIONS.pop(k,None)
     if len(SESSIONS)>=16:SESSIONS.pop(next(iter(SESSIONS)))
     SESSIONS[sid]=s
    return self.send({'ok':True,'csrf':s['csrf']},extra={'Set-Cookie':f'relay_session={sid}; HttpOnly; SameSite=Strict; Path=/'})
   s=cookie_session(self)
   if not s:return self.send({'error':'请先登录'},401)
   if not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),s['csrf']):return self.send({'error':'csrf'},403)
   if self.path=='/api/link':
    ck=http.cookies.SimpleCookie(self.headers.get('Cookie',''));token=secrets.token_urlsafe(32)
    with LOCK:
     for k in list(LINKS):
      if LINKS[k]['until']<time.time():LINKS.pop(k,None)
     if len(LINKS)>32:LINKS.pop(next(iter(LINKS)))
     LINKS[token]={'sid':ck['relay_session'].value,'until':time.time()+30}
    return self.send({'url':'http://127.0.0.1:'+str(CFG.get('admin_port',18780))+'/login-link?code='+token})
   if self.path=='/api/logout':
    ck=http.cookies.SimpleCookie(self.headers.get('Cookie',''));SESSIONS.pop(ck['relay_session'].value,None);return self.send({'ok':True},extra={'Set-Cookie':'relay_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/'})
   m=re.fullmatch(r'/api/nodes/([a-f0-9]{32})/(state|label|test|credentials|limits)',self.path)
   if not m:return self.send({'error':'not found'},404)
   nid,action=m.groups();n=node(nid)
   if not n:return self.send({'error':'node missing'},404)
   if action=='credentials':
    result,status=credential_admin.handle(sys.modules[__name__],nid,data)
    return self.send(result,status)
   if action=='limits':
    result,status=LIMITER.update(nid,data)
    return self.send(result,status)
   if action=='state':
    state=data.get('state')
    if state not in ('enabled','idle','rejected'):return self.send({'error':'invalid state'},400)
    with db() as c:c.execute('UPDATE nodes SET state=? WHERE id=?',(state,nid))
    audit('state',nid,state)
    if state!='enabled' and LOOP:asyncio.run_coroutine_threadsafe(close_node(nid),LOOP).result(timeout=5)
    try:ENGINE.sync()
    except Exception:return self.send({'error':'节点状态已保存；入口正在重新同步'},503)
    return self.send({'ok':True})
   if action=='label':
    label=str(data.get('label','')).strip()
    if not 1<=len(label)<=64 or any(ord(x)<32 for x in label):return self.send({'error':'备注长度应为1-64字符'},400)
    with db() as c:c.execute('UPDATE nodes SET label=? WHERE id=?',(label,nid))
    audit('label',nid);return self.send({'ok':True})
   if action=='test':
    if n['state']!='enabled' or time.time()-n['seen']>45:return self.send({'error':'请先启用在线节点'},409)
    if not rate('test/'+nid,2,60):return self.send({'error':'请稍后再检测'},429)
    r=probe(n)
    with db() as c:c.execute('UPDATE nodes SET exit_ip=?,test_time=?,tcp=?,udp=? WHERE id=?',(r.get('exit_ip',''),time.time(),int(r.get('tcp',False)),int(r.get('udp',False)),nid))
    audit('test',nid);return self.send(r)
  except (ValueError,KeyError,TypeError,json.JSONDecodeError):self.send({'error':'bad request'},400)
  except (BrokenPipeError,ConnectionError,TimeoutError):pass
  except Exception:self.send({'error':'request failed'},500)
 def agent(self,data):
  if self.path=='/consumer':return self.send({'error':'旧接收器已退役，请使用标准 Shadowsocks'},410)
  if self.path not in ('/register','/poll'):return self.send({'error':'not found'},404)
  if not hmac.compare_digest(self.headers.get('X-Enrollment-Key',''),CFG['enrollment']):return self.send({'error':'not authorized'},403)
  try:ip=str(ipaddress.ip_address(self.headers.get('X-Real-IP',self.client_address[0])))
  except ValueError:return self.send({'error':'bad source'},400)
  if not rate('agent/'+ip,180,60):return self.send({'error':'rate limited'},429)
  nid=data.get('id','');secret=data.get('secret','')
  if not isinstance(nid,str) or not re.fullmatch('[a-f0-9]{32}',nid) or not isinstance(secret,str) or not re.fullmatch('[A-Za-z0-9_-]{43,90}',secret):return self.send({'error':'bad identity'},400)
  if self.path=='/register':
   key=data.get('pubkey','')
   if not valid_key(key):return self.send({'error':'bad public key'},400)
   with LOCK,db() as c:
    n=c.execute('SELECT * FROM nodes WHERE id=?',(nid,)).fetchone()
    if not n:
     count=c.execute('SELECT COUNT(*) FROM nodes').fetchone()[0]
     if count>=MAX_NODES:return self.send({'error':'节点数已达管理员设定上限'},409)
     if not rate('new/'+ip,6,3600):return self.send({'error':'new node limit'},429)
     version=str(data.get('version',''))[:32];now=time.time()
     try:
      c.execute('INSERT INTO nodes(id,secret_hash,pubkey,slot,state,label,created,seen,ip,version) VALUES(?,?,?,?,?,?,?,?,?,?)',(nid,hashed(secret),key,count,'pending','节点 '+nid[:6].upper(),now,now,ip,version))
      c.execute('INSERT OR IGNORE INTO node_access(node_id,mode,updated) VALUES(?,"unset",?)',(nid,now))
      c.execute('INSERT OR IGNORE INTO node_limits(node_id,updated) VALUES(?,?)',(nid,now))
     except sqlite3.IntegrityError:return self.send({'error':'identity conflict'},409)
     c.commit();audit('register',nid)
   n=auth_node(data)
   if not n or n['pubkey']!=key:return self.send({'error':'identity mismatch'},403)
  else:n=auth_node(data)
  if not n:return self.send({'error':'identity mismatch'},403)
  with db() as c:c.execute('UPDATE nodes SET seen=?,ip=?,tunnel=? WHERE id=?',(time.time(),ip,int(data.get('tunnel_ready') is True),nid))
  return self.send(agent_info(node(nid)))

GATE_GLOBAL_LIMIT=64;GATE_NODE_LIMIT=32
ACTIVE=collections.Counter()
async def close_node(nid):
 for w in list(LIVE[nid]):w.close()
async def gate(reader,writer,slot):
 await flow_lifecycle.gate(sys.modules[__name__],reader,writer,slot)

def recv(s,n):
 b=b''
 while len(b)<n:
  q=s.recv(n-len(b))
  if not q:raise ConnectionError('upstream unavailable')
  b+=q
 return b
def socks(n,cmd,host,port):
 s=socket.create_connection(('127.0.0.1',25000+n['slot']),timeout=9);s.settimeout(9)
 try:
  s.sendall(b'\x05\x01\x02');assert recv(s,2)==b'\x05\x02';u=f'probe{n["slot"]+1:03}'.encode();p=derive('probe',n['slot']).encode();s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);assert recv(s,2)==b'\x01\x00';h=host.encode();s.sendall(bytes([5,cmd,0,3,len(h)])+h+struct.pack('!H',port));r=recv(s,4);assert r[1]==0
  if r[3]==1:ip=socket.inet_ntoa(recv(s,4))
  elif r[3]==4:ip=socket.inet_ntop(socket.AF_INET6,recv(s,16))
  else:recv(s,recv(s,1)[0]);ip='127.0.0.1'
  p=int.from_bytes(recv(s,2),'big');return s,('127.0.0.1' if ip in ('0.0.0.0','::') else ip,p)
 except Exception:s.close();raise
def probe(n):
 r={'tcp':False,'udp':False}
 for host in ['myip.ipip.net','api.ipify.org']:
  try:
   s,_=socks(n,1,host,443)
   with ssl.create_default_context().wrap_socket(s,server_hostname=host) as t:
    t.sendall(f'GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode());data=b''
    while len(data)<16384:
     b=t.recv(2048)
     if not b:break
     data+=b
   head,body=data.split(b'\r\n\r\n',1);assert b' 200 ' in head.split(b'\r\n')[0];m=re.search(rb'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',body);assert m;r['exit_ip']=str(ipaddress.ip_address(m[0].decode()));r['tcp']=True;break
  except Exception:r['tcp_error']='出口 HTTPS 请求未成功'
 try:
  s,bound=socks(n,3,'0.0.0.0',0)
  with s,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
   u.settimeout(8);q=bytes.fromhex('5a7101000001000000000000')+b'\x07example\x03com\x00\x00\x01\x00\x01';u.sendto(bytes.fromhex('00000001df0505050035')+q,bound);a=u.recv(2048);off=10 if a[3]==1 else 22 if a[3]==4 else 7+a[4];assert a[off:off+2]==b'\x5a\x71' and a[off+2]&128 and a[off+3]&15==0;r['udp']=True
 except Exception:r['udp_error']='出口 UDP DNS 请求未成功'
 return r

async def main():
 global LOOP;init();LOOP=asyncio.get_running_loop()
 for port,public in [(CFG.get('admin_port',18780),False),(CFG.get('agent_port',18781),True)]:
  server=BoundedServer(('127.0.0.1',port),public);threading.Thread(target=server.serve_forever,daemon=True).start()
 threading.Thread(target=ENGINE.run,daemon=True).start()
 gates={}
 while True:
  with db() as c:slots=[row[0] for row in c.execute('SELECT slot FROM nodes')]
  for i in slots:
   if i not in gates:gates[i]=await asyncio.start_server(lambda r,w,i=i:gate(r,w,i),'127.0.0.1',23000+i)
  FLOW_REGISTRY.snapshot(sys.modules[__name__])
  await asyncio.sleep(2)
FLOW_REGISTRY=flow_lifecycle.Registry()
ENGINE=direct_proxy.Engine(sys.modules[__name__])
LIMITER=node_limits.Manager(sys.modules[__name__])
TARGETS=target_policy.Policy(blocked_ips=[CFG.get('direct_server','203.0.113.20')])
if __name__=='__main__':asyncio.run(main())
