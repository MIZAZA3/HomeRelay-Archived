"""Authenticated admin operations. The HTTP handler enforces login and CSRF first.

Custom passwords must be recoverable for SS and profile export, so use an existing
authenticated encryption implementation, never password hashes as encryption.
"""
import asyncio
import hmac
import threading
import time

LOCK = threading.RLock()


def handle(c, nid, data):
    mode = data.get('mode', 'show')
    if mode not in ('show', 'set', 'rotate', 'revoke'):
        return {'error': 'invalid action'}, 400
    if not c.rate('credentials/' + nid, 20, 60):
        return {'error': '操作过于频繁'}, 429
    with LOCK:
        n, a = c.node(nid), c.access(nid)
        if not n or not a:
            return {'error': 'node missing'}, 404
        if mode != 'show':
            expected = data.get('expected_revision')
            if type(expected) is not int or expected != a['revision']:
                return {'error': '节点密码版本已更新，请关闭设置并重新打开，避免覆盖他人的修改'}, 409
            current_password = None
            if a['mode'] == 'password':
                try:
                    current_password = c.direct_proxy.password_value(c.derive, n, a)
                except RuntimeError:
                    # A damaged stored key must not prevent revoke / replacement.
                    # There is no fallback authentication with another secret.
                    pass
            password = data.get('password')
            if mode == 'set':
                if not isinstance(password, str) or not 8 <= len(password) <= 128 or len(password.encode('utf-8')) > 512 or not password.strip() or any(ord(x) < 32 or ord(x) == 127 for x in password):
                    return {'error': '自定义密码需为 8–128 个字符，不能包含换行或控制字符'}, 400
                confirm = data.get('confirmation')
                if not isinstance(confirm, str) or not hmac.compare_digest(password.encode('utf-8'), confirm.encode('utf-8')):
                    return {'error': '两次输入的密码不一致'}, 400
                digest = c.hashed('ss-history/' + nid + '/' + password)
                with c.db() as db:
                    old = db.execute('SELECT 1 FROM node_password_history WHERE node_id=? AND digest=?', (nid, digest)).fetchone()
                same = current_password is not None and hmac.compare_digest(password.encode('utf-8'), current_password.encode('utf-8'))
                if old or same:
                    return {'error': '不能重复使用当前或近期旧密码，请换一个新密码'}, 409
            revision = a['revision'] + 1
            sealed = c.direct_proxy.seal_password(c.derive, n, revision, password) if mode == 'set' else ''
            prior = c.hashed('ss-history/' + nid + '/' + current_password) if current_password is not None else None
            with c.db() as db:
                if prior:
                    db.execute('INSERT OR IGNORE INTO node_password_history VALUES(?,?,?)', (nid, prior, time.time()))
                    db.execute('DELETE FROM node_password_history WHERE node_id=? AND rowid NOT IN (SELECT rowid FROM node_password_history WHERE node_id=? ORDER BY created DESC LIMIT 64)', (nid, nid))
                db.execute('UPDATE node_access SET mode=?,salt="",pw_hash="",ss_secret=?,revision=?,updated=? WHERE node_id=?', ('revoked' if mode == 'revoke' else 'password', sealed, revision, time.time(), nid))
            # Database generation changes before closing flows / replacing listeners.
            # If GOST synchronization fails, old internal keys still fail at the gate.
            if c.LOOP:
                asyncio.run_coroutine_threadsafe(c.close_node(nid), c.LOOP).result(timeout=5)
            c.audit('direct-' + ('custom-password' if mode == 'set' else mode), nid)
            try:
                c.ENGINE.sync()
            except Exception:
                return {'error': '新授权已保存、旧凭据已失效；入口同步失败，正在自动重试，请稍后查看参数'}, 503
            if mode == 'revoke':
                return {'ok': True}, 200
            n, a = c.node(nid), c.access(nid)
            if n['state'] != 'enabled' or n['slot'] not in c.CFG.get('direct_open_slots', []):
                return {'ok': True, 'ready': False, 'message': '新密码已保存；请启用节点并单独开通本节点端口，再查看配置'}, 200
        if a['mode'] != 'password':
            return {'error': '请先设置节点密码'}, 409
        if n['slot'] not in c.CFG.get('direct_open_slots', []):
            return {'error': '本节点公网端口尚未开通，暂不导出配置'}, 409
        if n['state'] != 'enabled':
            return {'error': '请先启用节点'}, 409
        if nid not in c.ENGINE.ready:
            return {'error': '标准入口准备中，请稍后重试'}, 503
        c.audit('direct-credentials', nid)
        return c.direct_proxy.credential(c.CFG, c.derive, n, a), 200
