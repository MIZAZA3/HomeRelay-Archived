#!/usr/bin/python3
"""Isolated HTTPS administration gateway. Existing controller/data plane is unchanged."""
import collections,hmac,http.client,http.cookies,json,os,pathlib,re,secrets,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

ROOT=pathlib.Path(__file__).parent
CFG=json.loads((pathlib.Path(os.environ.get('CREDENTIALS_DIRECTORY','/etc/home-relay-web'))/'web.json').read_text())
ORIGIN='https://relay.example.invalid';PREFIX='/relay-admin/';COOKIE='__Secure-home_relay_web'
LOCK=threading.RLock();SESSIONS={};LIMITS={};LOGIN=threading.BoundedSemaphore(1)

def rate(key,n,seconds):
 with LOCK:
  now=time.monotonic()
  if len(LIMITS)>512:
   for k,q in list(LIMITS.items()):
    if not q or q[-1]<now-120:LIMITS.pop(k,None)
  if key not in LIMITS and len(LIMITS)>=1024:return False
  q=LIMITS.setdefault(key,collections.deque())
  while q and q[0]<now-seconds:q.popleft()
  if len(q)>=n:return False
  q.append(now);return True

def upstream(method,path,data=None,session=None):
 h={'Host':'127.0.0.1:18780','Content-Type':'application/json','Connection':'close'}
 if session:h.update({'Cookie':'relay_session='+session['backend_cookie'],'X-CSRF-Token':session['backend_csrf']})
 c=http.client.HTTPConnection('127.0.0.1',18780,timeout=50)
 try:
  c.request(method,path,None if data is None else json.dumps(data).encode(),h);r=c.getresponse();b=r.read(131073)
  if len(b)>131072:raise ValueError('response bound')
  return r.status,json.loads(b),r.getheader('Set-Cookie','')
 finally:c.close()

class Server(ThreadingHTTPServer):
 daemon_threads=True;allow_reuse_address=True
 def __init__(self):self.slots=threading.BoundedSemaphore(12);super().__init__(('127.0.0.1',18782),Handler)
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
 def trusted(self):
  return self.client_address[0]=='127.0.0.1' and self.headers.get('Host')=='relay.example.invalid' and self.headers.get('X-Forwarded-Proto')=='https' and hmac.compare_digest(self.headers.get('X-Relay-Web-Token',''),CFG['proxy_token'])
 def origin_ok(self,post=False):
  o=self.headers.get('Origin');return o==ORIGIN if post else not o or o==ORIGIN
 def cookie(self,value='',expire=False):
  return f'{COOKIE}={value}; Secure; HttpOnly; SameSite=Strict; Path={PREFIX}; Max-Age={0 if expire else 7200}'
 def send(self,data,status=200,kind='application/json; charset=utf-8',cookie=None):
  b=json.dumps(data,ensure_ascii=False).encode() if kind.startswith('application/json') else data
  self.send_response(status)
  for k,v in {'Content-Type':kind,'Content-Length':str(len(b)),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",'Permissions-Policy':'camera=(), microphone=(), geolocation=()'}.items():self.send_header(k,v)
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(b)
 def session(self):
  try:
   ck=http.cookies.SimpleCookie(self.headers.get('Cookie',''));sid=ck[COOKIE].value
   with LOCK:
    s=SESSIONS.get(sid);now=time.monotonic()
    if not s or s['until']<now or s['seen']<now-1800:SESSIONS.pop(sid,None);return None,None
    s['seen']=now;return sid,s
  except Exception:return None,None
 def relay(self,sid,s,method,path,data=None):
  code,r,_=upstream(method,path,data,s)
  if code==401:
   with LOCK:SESSIONS.pop(sid,None)
   return self.send({'error':'会话已过期，请重新登录'},401,cookie=self.cookie(expire=True))
  if isinstance(r,dict) and 'csrf' in r:r['csrf']=s['csrf']
  if code>=500:return self.send({'error':'管理服务暂不可用，请稍后重试'},503)
  return self.send(r,code)
 def do_GET(self):
  try:
   if not self.trusted() or not self.origin_ok():return self.send({'error':'访问上下文无效'},403)
   assets={'/':('panel.html','text/html; charset=utf-8'),'/app.js':('app.js','application/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
   if self.path in assets:
    f,t=assets[self.path];return self.send((ROOT/f).read_bytes(),kind=t)
   if self.path!='/api/nodes':return self.send({'error':'not found'},404)
   sid,s=self.session()
   if not s:return self.send({'error':'请先登录'},401)
   return self.relay(sid,s,'GET',self.path)
  except (BrokenPipeError,ConnectionError,TimeoutError):pass
  except Exception:self.send({'error':'管理服务暂不可用，请稍后重试'},503)
 def do_POST(self):
  try:
   if not self.trusted() or not self.origin_ok(True):return self.send({'error':'请求来源无效'},403)
   if self.headers.get_content_type()!='application/json':return self.send({'error':'json required'},415)
   size=int(self.headers.get('Content-Length','-1'))
   if not 0<size<=8192:return self.send({'error':'body size'},413)
   data=json.loads(self.rfile.read(size))
   if not isinstance(data,dict):return self.send({'error':'bad request'},400)
   if self.path=='/api/login':return self.login(data)
   if self.path!='/api/logout' and not re.fullmatch('/api/nodes/[a-f0-9]{32}/(state|label|test|connect)',self.path):return self.send({'error':'not found'},404)
   sid,s=self.session()
   if not s:return self.send({'error':'请先登录'},401)
   if not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),s['csrf']):return self.send({'error':'csrf'},403)
   if self.path=='/api/logout':
    try:upstream('POST','/api/logout',{},s)
    finally:
     with LOCK:SESSIONS.pop(sid,None)
    return self.send({'ok':True},cookie=self.cookie(expire=True))
   return self.relay(sid,s,'POST',self.path,data)
  except (ValueError,TypeError,KeyError):self.send({'error':'bad request'},400)
  except (BrokenPipeError,ConnectionError,TimeoutError):pass
  except Exception:self.send({'error':'管理服务暂不可用，请稍后重试'},503)
 def login(self,data):
  ip=self.headers.get('X-Real-IP','')
  if not re.fullmatch('[0-9a-fA-F:.]{3,64}',ip):return self.send({'error':'bad source'},403)
  if not rate('ip/'+ip,4,60) or not rate('global',6,60):return self.send({'error':'登录尝试过多，请一分钟后再试'},429)
  pw=data.get('password')
  if not isinstance(pw,str) or not 1<=len(pw)<=200:return self.send({'error':'认证失败'},403)
  if not LOGIN.acquire(False):return self.send({'error':'正在处理登录，请稍后再试'},429)
  try:code,r,ck=upstream('POST','/api/login',{'password':pw})
  finally:LOGIN.release()
  if code!=200:return self.send({'error':'登录尝试过多，请稍后再试' if code==429 else '认证失败'},429 if code==429 else 403)
  cookies=http.cookies.SimpleCookie(ck);backend=cookies['relay_session'].value
  if not re.fullmatch('[A-Za-z0-9_-]{32,90}',backend) or not isinstance(r.get('csrf'),str):raise ValueError('unexpected login response')
  now=time.monotonic();sid=secrets.token_urlsafe(32);s={'backend_cookie':backend,'backend_csrf':r['csrf'],'csrf':secrets.token_urlsafe(24),'seen':now,'until':now+7200}
  with LOCK:
   for k in list(SESSIONS):
    if SESSIONS[k]['until']<now or SESSIONS[k]['seen']<now-1800:SESSIONS.pop(k,None)
   if len(SESSIONS)>=8:SESSIONS.pop(min(SESSIONS,key=lambda k:SESSIONS[k]['seen']))
   SESSIONS[sid]=s
  return self.send({'ok':True,'csrf':s['csrf']},cookie=self.cookie(sid))

if __name__=='__main__':Server().serve_forever()
