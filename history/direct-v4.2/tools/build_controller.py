"""Build the narrowly modified controller from an audited production preimage."""
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
source = pathlib.Path('D:/CodexWork/HomeRelayDirectV4/baseline/opt/home-relay-v2/controller.py').read_text('utf-8')
source = source.replace('import asyncio,', 'import sys\nimport direct_proxy\nimport credential_admin\nimport node_limits\nimport target_policy\nimport asyncio,', 1)
schema_marker="  # Preserve existing nodes until their administrator deliberately changes access."
source = source.replace(schema_marker, "  columns={row[1] for row in c.execute('PRAGMA table_info(node_access)')}\n  if 'ss_secret' not in columns:c.execute(\"ALTER TABLE node_access ADD COLUMN ss_secret TEXT NOT NULL DEFAULT ''\")\n  c.execute('CREATE TABLE IF NOT EXISTS node_password_history(node_id TEXT NOT NULL,digest TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(node_id,digest))')\n" + schema_marker)
source = source.replace(schema_marker, "  c.execute('CREATE TABLE IF NOT EXISTS node_limits(node_id TEXT PRIMARY KEY,upload_kib INTEGER NOT NULL DEFAULT 0 CHECK(typeof(upload_kib)=\"integer\" AND upload_kib BETWEEN 0 AND 256),download_kib INTEGER NOT NULL DEFAULT 0 CHECK(typeof(download_kib)=\"integer\" AND download_kib BETWEEN 0 AND 256),revision INTEGER NOT NULL DEFAULT 1,updated REAL NOT NULL)')\n  c.execute('INSERT OR IGNORE INTO node_limits(node_id,updated) SELECT id,? FROM nodes',(time.time(),))\n" + schema_marker)
start = source.index('def usage_token(')
end = source.index('def pw_hash(', start)
source = source[:start] + source[end:]
start = source.index(' def consumer(self,data):')
end = source.index('class Rate:', start)
source = source[:start] + '\n' + source[end:]
source = source.replace("if self.path=='/consumer':return self.consumer(data)", "if self.path=='/consumer':return self.send({'error':'旧接收器已退役，请使用标准 Shadowsocks'},410)")
source = source.replace('(state|label|test|connect|password)', '(state|label|test|credentials|limits)')
start = source.index("   if action=='password':")
end = source.index("   if action=='state':", start)
source = source[:start] + '''   if action=='credentials':
    result,status=credential_admin.handle(sys.modules[__name__],nid,data)
    return self.send(result,status)
   if action=='limits':
    result,status=LIMITER.update(nid,data)
    return self.send(result,status)
''' + source[end:]
start = source.index("   if action=='connect':")
end = source.index('  except (ValueError', start)
source = source[:start] + source[end:]
source = source.replace("if state=='rejected' and LOOP:asyncio.run_coroutine_threadsafe(close_node(nid),LOOP)", "if state!='enabled' and LOOP:asyncio.run_coroutine_threadsafe(close_node(nid),LOOP).result(timeout=5)\n    try:ENGINE.sync()\n    except Exception:return self.send({'error':'节点状态已保存；入口正在重新同步'},503)")
source = source.replace("'usage_revision':a['revision'] if a else 0}", "'usage_revision':a['revision'] if a else 0,'direct_port':direct_proxy.public_port(CFG,n['slot']),'direct_published':n['slot'] in CFG.get('direct_open_slots',[]),'direct_ready':n['id'] in ENGINE.ready}")
source = source.replace("'usage_revision':a['revision'] if a else 0,", "'usage_revision':a['revision'] if a else 0,'password_kind':'custom' if a and a['ss_secret'] else 'random',")
source = source.replace("return {'id':n['id'],'label':n['label'],'state'", "return {'id':n['id'],'limits':LIMITER.view(n['id']),'label':n['label'],'state'",1)
source = source.replace("      c.execute('INSERT OR IGNORE INTO node_access(node_id,mode,updated) VALUES(?,\"unset\",?)',(nid,now))", "      c.execute('INSERT OR IGNORE INTO node_access(node_id,mode,updated) VALUES(?,\"unset\",?)',(nid,now))\n      c.execute('INSERT OR IGNORE INTO node_limits(node_id,updated) VALUES(?,?)',(nid,now))")
start = source.index('class Rate:')
end = source.index('async def close_node(', start)
source = source[:start] + 'ACTIVE=collections.Counter()\n' + source[end:]
start = source.index('async def gate(')
end = source.index('\ndef recv(', start)
source = source[:start] + '''async def gate(reader,writer,slot):
 nid=None;peer=None
 async def exact(r,n):return await asyncio.wait_for(r.readexactly(n),8)
 def permitted(n,user,password):
  if not n or n['state']!='enabled' or time.time()-n['seen']>45:return False
  if user==f'probe{slot+1:03}':return hmac.compare_digest(password,derive('probe',slot))
  a=access(n['id'])
  return bool(user==f'direct{slot+1:03}' and a and a['mode']=='password' and slot in CFG.get('direct_open_slots',[]) and hmac.compare_digest(password,direct_proxy.gate_password(derive,n,a)))
 try:
  with db() as c:n=c.execute('SELECT * FROM nodes WHERE slot=?',(slot,)).fetchone()
  if not n or n['state']!='enabled' or time.time()-n['seen']>45 or ACTIVE['all']>=64 or ACTIVE[n['id']]>=16:return
  nid=n['id'];ACTIVE['all']+=1;ACTIVE[nid]+=1;LIVE[nid].add(writer)
  ver,count=await exact(reader,2)
  if ver!=5 or count<1 or count>8:return
  methods=await exact(reader,count)
  if 2 not in methods:return
  writer.write(b'\\x05\\x02');await writer.drain()
  ver,length=await exact(reader,2)
  if ver!=1 or not length:return
  user=(await exact(reader,length)).decode('ascii');length=(await exact(reader,1))[0]
  password=(await exact(reader,length)).decode('ascii')
  if not permitted(node(nid),user,password):return
  r2,peer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',22000+slot),5);LIVE[nid].add(peer)
  peer.write(b'\\x05\\x01\\x02');await peer.drain()
  if await exact(r2,2)!=b'\\x05\\x02':return
  home=b'home';pw=derive('home',slot).encode()
  peer.write(b'\\x01'+bytes([len(home)])+home+bytes([len(pw)])+pw);await peer.drain()
  if await exact(r2,2)!=b'\\x01\\x00' or not permitted(node(nid),user,password):return
  writer.write(b'\\x01\\x00');await writer.drain()
  udp_mode,request=await TARGETS.request(reader)
  await LIMITER.write(peer,request,nid,'upload',lambda:permitted(node(nid),user,password))
  async def pump(r,w,direction):
   while True:
    # Revalidate after every read, including delayed CONNECT/UDP after rotation.
    if udp_mode and direction=='upload':b=await TARGETS.datagram(r)
    else:b=await asyncio.wait_for(r.read(16384),180)
    if not b or not permitted(node(nid),user,password):break
    await LIMITER.write(w,b,nid,direction,lambda:permitted(node(nid),user,password))
   try:w.write_eof()
   except Exception:pass
  jobs=[asyncio.create_task(pump(reader,peer,'upload')),asyncio.create_task(pump(r2,writer,'download'))]
  try:await asyncio.gather(*jobs)
  finally:
   for j in jobs:j.cancel()
   await asyncio.gather(*jobs,return_exceptions=True)
 except Exception:pass
 finally:
  writer.close()
  if peer:peer.close()
  if nid:
   LIVE[nid].discard(writer);LIVE[nid].discard(peer);ACTIVE['all']-=1;ACTIVE[nid]-=1
''' + source[end:]
source = source.replace(" server=AuthServer();threading.Thread(target=server.serve_forever,daemon=True).start()", " threading.Thread(target=ENGINE.run,daemon=True).start()")
source = source.replace(" gates=[]\n for i in range(MAX_NODES):gates.append(await asyncio.start_server(lambda r,w,i=i:gate(r,w,i),'127.0.0.1',23000+i))\n await asyncio.Event().wait()", " gates={}\n while True:\n  with db() as c:slots=[row[0] for row in c.execute('SELECT slot FROM nodes')]\n  for i in slots:\n   if i not in gates:gates[i]=await asyncio.start_server(lambda r,w,i=i:gate(r,w,i),'127.0.0.1',23000+i)\n  await asyncio.sleep(2)")
source = source.replace("if __name__=='__main__':asyncio.run(main())", "ENGINE=direct_proxy.Engine(sys.modules[__name__])\nLIMITER=node_limits.Manager(sys.modules[__name__])\nTARGETS=target_policy.Policy(blocked_ips=[CFG.get('direct_server','203.0.113.20')])\nif __name__=='__main__':asyncio.run(main())")
source = source.replace('HomeRelay V2: bounded', 'HomeRelay Direct V4: bounded')
source = source.replace('No shell commands, cloud API, website writes, or SSH management keys.', 'No shell, cloud API, website writes, or SSH management keys. Fixed GOST child only.')
(root/'server/controller.py').write_text(source, 'utf-8')
web = pathlib.Path('D:/CodexWork/HomeRelayDirectV4/baseline/opt/home-relay-web/web_gateway.py').read_text('utf-8')
web = web.replace('(state|label|test|connect|password)', '(state|label|test|credentials|limits)')
# Preserve explicit fail-closed mutation outcomes without exposing arbitrary errors.
web = web.replace("  if code>=500:return self.send({'error':'管理服务暂不可用，请稍后重试'},503)", "  if code>=500:\n   safe={'新授权已保存、旧凭据已失效；入口同步失败，正在自动重试，请稍后查看参数','限速已保存，等待数据闸门准备','限速已保存，实时应用未确认，请重新检查配置'}\n   message=r.get('error') if isinstance(r,dict) else None\n   return self.send({'error':message if message in safe else '管理服务暂不可用，请稍后重试'},503)")
(root/'server/web_gateway.py').write_text(web, 'utf-8')
css = pathlib.Path('D:/CodexWork/HomeRelayDirectV4/baseline/opt/home-relay-web/style.css').read_text('utf-8')
(root/'server/style.css').write_text(css + '\n.credential-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}dialog textarea{width:100%;height:110px;padding:10px;border:1px solid #cad3e0;border-radius:7px;resize:vertical;overflow-wrap:anywhere;font:12px monospace}dialog input[readonly]{background:#f6f8fb}dialog .wide{grid-column:1/-1}#credentialError{color:#aa3e42}dialog{max-height:90vh;overflow:auto}code{overflow-wrap:anywhere}.direct-status{font-size:13px;color:#48617f}@media(max-width:500px){.credential-grid{grid-template-columns:1fr}}\n', 'utf-8')
print('Built controller, gateway and styles; no private configuration copied.')
with (root/'server/style.css').open('a',encoding='utf-8') as stream:stream.write('\n#passwordFormError,#limitsError{color:#aa3e42}\n')
