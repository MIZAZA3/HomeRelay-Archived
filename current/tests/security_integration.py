"""Non-destructive application negative tests, isolated fixture only."""
import asyncio
import base64
import http.client
import json
import secrets
import socket
import struct


async def run(c, nodes, cookie, csrf, check):
    def request(method, path, body=None, *, port=18780, extra=None, authenticated=True):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            headers.update(Cookie=cookie, **{'X-CSRF-Token': csrf})
        headers.update(extra or {})
        payload = json.dumps(body) if isinstance(body, (dict, list)) else body
        conn.request(method, path, payload, headers)
        r = conn.getresponse();data = r.read();head = dict(r.getheaders());code = r.status;conn.close()
        return code, data, head

    async def req(*args, **kwargs):
        return await asyncio.to_thread(request, *args, **kwargs)

    nid = nodes[0]
    before = dict(c.access(nid));limits_before = c.LIMITER.view(nid)
    code, _, _ = await req('GET', '/api/nodes', extra={'Host': 'attacker.invalid'})
    check('admin rejects DNS-rebinding Host headers', code == 403)
    code, _, _ = await req('POST', '/api/nodes/' + nid + '/limits',
                           {'upload_kib': 1, 'download_kib': 1, 'expected_revision': limits_before['revision']}, extra={'Origin': 'https://attacker.invalid'})
    check('cross-origin mutation denied even with a valid cookie', code == 403 and c.LIMITER.view(nid) == limits_before)
    code, _, _ = await req('POST', '/api/nodes/' + nid + '/credentials', {'mode': 'rotate'})
    check('credential mutation without expected revision cannot replay stale requests', code == 409 and dict(c.access(nid)) == before)
    for payload, label in [([], 'non-object JSON'), ('x' * 8193, 'oversized body')]:
        code, _, _ = await req('POST', '/api/nodes/' + nid + '/limits', payload)
        check('request validation rejects ' + label, code == (400 if isinstance(payload, list) else 413))
    code, _, _ = await req('POST', '/api/nodes/' + nid + '/limits', '{}', extra={'Content-Type': 'text/plain'})
    check('simple-content-type CSRF bypass rejected', code == 415)
    code, _, headers = await req('GET', '/api/nodes')
    check('sensitive API responses have no-store and anti-framing headers', code == 200 and headers.get('Cache-Control') == 'no-store' and headers.get('X-Frame-Options') == 'DENY')
    code, body, _ = await req('GET', '/../../etc/home-relay-v2/access.json')
    check('path traversal cannot read production configuration', code == 404 and b'master' not in body)
    code, _, _ = await req('POST', '/api/nodes/' + 'f' * 32 + '/limits', {'upload_kib': 1, 'download_kib': 1, 'expected_revision': 0})
    check('unknown node ID cannot create a limits record', code == 404)

    original = c.node(nid)['label'];hostile = '<img src=x onerror=alert(1)>'
    code, _, _ = await req('POST', '/api/nodes/' + nid + '/label', {'label': hostile})
    code, result, _ = await req('GET', '/api/nodes');listed = json.loads(result)
    check('stored label stays data in JSON rather than executable markup', code == 200 and next(x for x in listed['nodes'] if x['id'] == nid)['label'] == hostile)
    exported = c.direct_proxy.credential(c.CFG, c.derive, c.node(nid), c.access(nid))
    check('untrusted labels are URL-escaped in proxy links', '<' not in exported['ss_uri'] and '%3C' in exported['ss_uri'])
    await req('POST', '/api/nodes/' + nid + '/label', {'label': original})

    c.CFG['enrollment'] = secrets.token_urlsafe(32)
    public_headers = {'X-Enrollment-Key': c.CFG['enrollment'], 'X-Real-IP': '203.0.113.11'}
    code, _, _ = await req('POST', '/api/nodes/' + nid + '/limits', {}, port=18781, extra=public_headers, authenticated=False)
    check('agent enrollment token gives no admin privileges', code == 404)
    code, _, _ = await req('POST', '/poll', {'id': nid, 'secret': 'z'*43}, port=18781, extra=public_headers, authenticated=False)
    check('node identity requires its own secret in addition to enrollment key', code == 403)
    prior_capacity = c.MAX_NODES;c.MAX_NODES = 3
    wire = struct.pack('!I', 11) + b'ssh-ed25519' + struct.pack('!I', 32) + secrets.token_bytes(32)
    pubkey = 'ssh-ed25519 ' + base64.b64encode(wire).decode()
    new = {'id': secrets.token_hex(16), 'secret': secrets.token_urlsafe(32), 'pubkey': pubkey,
           'state': 'enabled', 'slot': 0, 'remote_port': 22, 'version': 'audit-fixture'}
    code, body, _ = await req('POST', '/register', new, port=18781, extra=public_headers, authenticated=False)
    registered = json.loads(body)
    check('new agents cannot self-approve or choose a privileged slot', code == 200 and registered['state'] == 'pending' and c.node(new['id'])['slot'] == 2 and 'home_password' not in registered and 'remote_port' not in registered)
    c.MAX_NODES = prior_capacity

    def wrong_udp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(1.5);udp.sendto(b'wrong-key-owned-test', ('127.0.0.1', 31101))
            try:udp.recv(128);return False
            except TimeoutError:return True
    check('wrong Shadowsocks UDP password produces no forwarded response', await asyncio.to_thread(wrong_udp))
    check('security audit does not alter the original node password', dict(c.access(nid)) == before)
