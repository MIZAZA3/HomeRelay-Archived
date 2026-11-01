#!/usr/bin/python3
"""OpenSSH calls this root-owned helper as the unprivileged registry user."""
import base64,sqlite3,sys,time
try:
 key=sys.argv[1]
 if len(key)>1500:raise ValueError()
 base64.b64decode(key,validate=True)
 c=sqlite3.connect('file:/var/lib/home-relay-v2/nodes.sqlite3?mode=ro',uri=True,timeout=3)
 r=c.execute('SELECT pubkey,slot,state,seen FROM nodes WHERE pubkey IN (?,?)',('ssh-ed25519 '+key,'ssh-rsa '+key)).fetchone()
 if r and r[2] in ('enabled','idle') and time.time()-r[3]<90 and 0<=r[1]<32:
  print('restrict,port-forwarding,command="/usr/sbin/nologin",permitlisten="127.0.0.1:%d" %s'%(22000+r[1],r[0]))
except Exception:pass
