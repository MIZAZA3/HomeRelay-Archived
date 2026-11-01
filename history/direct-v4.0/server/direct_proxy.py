"""GOST standard Shadowsocks ingress, controlled through a private Unix socket.

No management key, shell, public control API or direct-out fallback. The controller
must authenticate every chain at its generation-aware loopback SOCKS gate.
"""
import base64
import http.client
import json
import os
import socket
import subprocess
import threading
import time
import urllib.parse


PRIVATE_TARGETS = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128',
    '::ffff:0:0/96', '64:ff9b::/96', 'fc00::/7', 'fe80::/10', 'ff00::/8',
    '203.0.113.20', 'localhost', '*.localhost', '*.local',
    'metadata.google.internal', 'metadata.aliyun.com', '100.100.100.200',
]


def public_port(cfg, slot):
    return int(cfg.get('direct_base_port', 24443)) + slot


def gate_password(derive, n, a):
    return derive('direct-gate/' + n['id'] + '/' + str(a['revision']), n['slot'])


def credential(cfg, derive, n, a):
    password = derive('ss/' + n['id'] + '/' + str(a['revision']), n['slot'])
    server = cfg.get('direct_server', '203.0.113.20')
    port = public_port(cfg, n['slot'])
    name = n['label']
    # Legacy whole-URI encoding for SSTap; SIP002 for modern clients.
    legacy = base64.b64encode(f'aes-256-gcm:{password}@{server}:{port}'.encode()).decode()
    userinfo = base64.urlsafe_b64encode(f'aes-256-gcm:{password}'.encode()).decode().rstrip('=')
    suffix = '#' + urllib.parse.quote(name, safe='')
    proxy_name = 'HR-' + n['id'][:6] + ' ' + name
    proxy = {'name': proxy_name, 'type': 'ss', 'server': server, 'port': port,
             'cipher': 'aes-256-gcm', 'password': password, 'udp': True}
    # JSON is valid YAML, but format familiar YAML with JSON-quoted scalar values.
    q = lambda s: json.dumps(s, ensure_ascii=False)
    yaml = '\n'.join([
        '# HomeRelay: independent profile; importing does not enable TUN.',
        'mixed-port: 7890', 'allow-lan: false', 'mode: rule', 'log-level: warning',
        'ipv6: false', 'tun:', '  enable: false', 'proxies:',
        '  - ' + json.dumps(proxy, ensure_ascii=False), 'proxy-groups:',
        '  - name: HomeRelay', '    type: select', '    proxies: [' + q(proxy_name) + ']',
        'rules:', '  - MATCH,HomeRelay', '',
    ])
    return {'server': server, 'port': port, 'method': 'aes-256-gcm',
            'password': password, 'username': '', 'udp': True,
            'ss_uri': 'ss://' + legacy + suffix,
            'sip002_uri': f'ss://{userinfo}@{server}:{port}' + suffix,
            'flclash_yaml': yaml, 'revision': a['revision']}


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        self.socket_path = str(path)
        super().__init__('localhost', timeout=4)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class Engine:
    def __init__(self, controller):
        self.c = controller
        self.lock = threading.RLock()
        self.process = None
        self.installed = {}
        self.ready = set()
        self.socket = controller.STATE / 'direct-api.sock'
        self.token = controller.derive('direct-api', 0)
        self.log = None

    def call(self, method, path, value=None):
        h = {'Authorization': 'Basic ' + base64.b64encode(('controller:' + self.token).encode()).decode(),
             'Content-Type': 'application/json'}
        conn = UnixHTTP(self.socket)
        try:
            conn.request(method, '/config/' + path, None if value is None else json.dumps(value), h)
            r = conn.getresponse()
            body = r.read(131073)
            if r.status != 200 or len(body) > 131072:
                raise RuntimeError('GOST control operation failed: ' + str(r.status))
            data = json.loads(body)
            if data.get('code', 0) != 0:
                raise RuntimeError('GOST rejected control operation')
            return data
        finally:
            conn.close()

    def start(self):
        if self.process and self.process.poll() is None:
            return
        self.ready.clear()
        self.installed.clear()
        self.socket.unlink(missing_ok=True)
        config = {'api': {'addr': 'unix://' + str(self.socket), 'accesslog': False,
                          'auth': {'username': 'controller', 'password': self.token}},
                  'services': [], 'log': {'level': 'fatal'},
                  'bypasses': [{'name': 'private-targets', 'matchers': PRIVATE_TARGETS}]}
        path = self.c.STATE / 'direct-bootstrap.json'
        path.write_text(json.dumps(config))
        os.chmod(path, 0o600)
        # Never log credentials / requests; keep the child's bounded fatal log only.
        if self.log:
            self.log.close()
        self.log = open(self.c.STATE / 'direct-engine.log', 'wb')
        binary = self.c.CFG.get('direct_binary', '/opt/gost-home-relay/gost')
        self.process = subprocess.Popen([binary, '-C', str(path)], stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log, close_fds=True)
        for _ in range(50):
            if self.process.poll() is not None:
                raise RuntimeError('GOST child did not start')
            if self.socket.exists():
                os.chmod(self.socket, 0o600)
                self.call('GET', 'services')
                return
            time.sleep(.1)
        self.process.terminate()
        self.process.wait(timeout=5)
        raise RuntimeError('GOST control socket not ready')

    def chain(self, name, n, username, password):
        return {'name': name, 'hops': [{'name': name + '-hop', 'nodes': [{
            'name': name + '-gate', 'addr': f'127.0.0.1:{23000+n["slot"]}',
            'connector': {'type': 'socks5', 'auth': {'username': username, 'password': password},
                          'metadata': {'notls': True, 'udpBufferSize': 65535}},
            'dialer': {'type': 'tcp'},
        }]}]}

    def resource_names(self, kind):
        data = self.call('GET', kind).get('data')
        items = data.get('list') if isinstance(data, dict) else data
        if data is None or (items is None and isinstance(data, dict) and data.get('count') == 0):
            items = []
        if not isinstance(items, list):
            raise RuntimeError('Unexpected GOST resource response: ' + str(list(data) if isinstance(data, dict) else type(data).__name__))
        return {x['name'] for x in items}

    def put_chain(self, value):
        name = value['name']
        exists = name in self.resource_names('chains')
        self.call('PUT' if exists else 'POST', 'chains/' + name if exists else 'chains', value)

    def sync(self):
        """Idempotent, serialized, per-node replacement. No shared-engine restart."""
        with self.lock:
            self.start()
            with self.c.db() as db:
                rows = db.execute('SELECT * FROM nodes ORDER BY slot').fetchall()
            allowed = set(self.c.CFG.get('direct_open_slots', []))
            for n in rows:
                a = self.c.access(n['id'])
                # Probe is local only, independent of consumer key revocation.
                pk = ('probe', n['id'])
                if pk not in self.installed:
                    chain = 'probe-' + n['id']
                    self.put_chain(self.chain(chain, n, f'probe{n["slot"]+1:03}', self.c.derive('probe', n['slot'])))
                    value = {
                        'name': chain, 'addr': f'127.0.0.1:{25000+n["slot"]}',
                        'handler': {'type': 'socks5', 'chain': chain,
                                    'auth': {'username': f'probe{n["slot"]+1:03}', 'password': self.c.derive('probe', n['slot'])},
                                    'metadata': {'udp': True, 'notls': True, 'bind': False, 'udpBufferSize': 65535}},
                        'listener': {'type': 'tcp'}, 'bypasses': ['private-targets'],
                        'metadata': {'limiter.conn.in': 16}}
                    if chain not in self.resource_names('services'):
                        self.call('POST', 'services', value)
                    self.installed[pk] = True
                signature = (a['revision'], a['mode'], n['state'], n['slot'] in allowed)
                key = ('direct', n['id'])
                if self.installed.get(key) == signature:
                    if n['state'] == 'enabled' and n['slot'] in allowed and a['mode'] == 'password':
                        self.ready.add(n['id'])
                    continue
                self.ready.discard(n['id'])
                names = ['ss-tcp-' + n['id'], 'ss-udp-' + n['id']]
                # Delete idempotently, even after an earlier partial API failure.
                found = self.resource_names('services')
                for name in names:
                    if name in found:
                        self.call('DELETE', 'services/' + name)
                if n['state'] == 'enabled' and n['slot'] in allowed and a['mode'] == 'password':
                    chain = 'direct-' + n['id']
                    value = self.chain(chain, n, f'direct{n["slot"]+1:03}', gate_password(self.c.derive, n, a))
                    self.put_chain(value)
                    credentials = credential(self.c.CFG, self.c.derive, n, a)
                    for name, handler, listener in zip(names, ['ss', 'ssu'], ['tcp', 'udp']):
                        self.call('POST', 'services', {
                            'name': name, 'addr': f'0.0.0.0:{credentials["port"]}',
                            'handler': {'type': handler, 'chain': chain,
                                        'auth': {'username': credentials['method'], 'password': credentials['password']},
                                        'metadata': {'readTimeout': '10s', 'udpBufferSize': 65535}},
                            'listener': {'type': listener, 'metadata': {'ttl': '30s', 'readBufferSize': 65535}},
                            'bypasses': ['private-targets'], 'metadata': {'limiter.conn.in': 16}})
                    self.ready.add(n['id'])
                self.installed[key] = signature

    def run(self):
        while True:
            try:
                self.sync()
            except Exception:
                # Revocation still enforced at the generation-aware data gate.
                self.ready.clear()
            time.sleep(2)
