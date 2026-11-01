"""Shared per-node, per-direction byte budgets, composed with the global cap.

Runs data-plane accounting only on the controller asyncio loop. Quota is charged
atomically to BOTH buckets before each write; never reserve one bucket and then
sleep on another. Connections and TCP/UDP transports share the same node bucket.
"""
import asyncio
import threading
import time

TOTAL_KIB = 256
MAX_CHUNK = 4096


class Bucket:
    def __init__(self, rate, now=None):
        self.rate = rate
        self.capacity = min(MAX_CHUNK, max(256, int(rate / 10)))
        self.tokens = 0.0
        self.updated = time.monotonic() if now is None else now

    def refill(self, now):
        self.tokens = min(self.capacity, self.tokens + max(0, now - self.updated) * self.rate)
        self.updated = now

    def configure(self, rate, now):
        self.refill(now)
        old_rate = self.rate
        self.rate = rate
        self.capacity = min(MAX_CHUNK, max(256, int(rate / 10)))
        # Lower limits take effect without retaining a burst from the old rate.
        self.tokens = 0.0 if rate < old_rate else min(self.tokens, self.capacity)


class Manager:
    def __init__(self, controller):
        self.c = controller
        self.globals = {key: Bucket(TOTAL_KIB * 1024) for key in ('upload', 'download')}
        self.nodes = {}
        self.admin_lock = threading.RLock()

    def config(self, nid):
        with self.c.db() as db:
            row = db.execute('SELECT upload_kib,download_kib,revision FROM node_limits WHERE node_id=?', (nid,)).fetchone()
        values = dict(row) if row else {'upload_kib': 0, 'download_kib': 0, 'revision': 0}
        for key in ('upload_kib', 'download_kib'):
            if type(values[key]) is not int or not 0 <= values[key] <= TOTAL_KIB:
                raise ValueError('Invalid stored speed limit')
        return values

    def view(self, nid):
        cfg = self.config(nid)
        return {**cfg, 'effective_upload_kib': cfg['upload_kib'] or TOTAL_KIB,
                'effective_download_kib': cfg['download_kib'] or TOTAL_KIB}

    def pair(self, nid):
        if nid not in self.nodes:
            cfg = self.config(nid)
            self.nodes[nid] = {key: Bucket((cfg[key + '_kib'] or TOTAL_KIB) * 1024) for key in ('upload', 'download')}
        return self.nodes[nid]

    async def apply(self, nid):
        cfg = self.config(nid)
        pair = self.pair(nid)
        now = time.monotonic()
        for key in ('upload', 'download'):
            pair[key].configure((cfg[key + '_kib'] or TOTAL_KIB) * 1024, now)

    async def reserve(self, nid, direction, wanted):
        global_bucket = self.globals[direction]
        node_bucket = self.pair(nid)[direction]
        while True:
            now = time.monotonic()
            global_bucket.refill(now)
            node_bucket.refill(now)
            amount = min(wanted, global_bucket.capacity, node_bucket.capacity)
            wait = max((amount - global_bucket.tokens) / global_bucket.rate,
                       (amount - node_bucket.tokens) / node_bucket.rate, 0)
            if wait <= 0:
                # No await between checking both budgets and charging both.
                global_bucket.tokens -= amount
                node_bucket.tokens -= amount
                return amount
            await asyncio.sleep(min(wait, .1))

    async def write(self, writer, data, nid, direction, permitted):
        position = 0
        while position < len(data):
            if writer.is_closing() or not permitted():
                raise ConnectionError('Node access no longer active')
            amount = await self.reserve(nid, direction, len(data) - position)
            # Password/state can change while waiting for quota.
            if writer.is_closing() or not permitted():
                raise ConnectionError('Node access no longer active')
            writer.write(data[position:position + amount])
            await writer.drain()
            position += amount

    def update(self, nid, data):
        allowed = {'upload_kib', 'download_kib', 'expected_revision'}
        if set(data) != allowed:
            return {'error': '请同时提交上传、下载限速和当前配置版本'}, 400
        for key in ('upload_kib', 'download_kib'):
            if type(data[key]) is not int or not 0 <= data[key] <= TOTAL_KIB:
                return {'error': f'限速需为 0–{TOTAL_KIB} 的整数 KiB/s；0 表示继承总上限，不是无限速'}, 400
        if type(data['expected_revision']) is not int:
            return {'error': '配置版本无效，请重新打开限速设置'}, 400
        if not self.c.rate('limits/' + nid, 30, 60):
            return {'error': '限速修改过于频繁，请稍后再试'}, 429
        with self.admin_lock:
            old = self.config(nid)
            if old['revision'] != data['expected_revision']:
                return {'error': '限速配置已更新，请关闭窗口后重新打开，避免覆盖其他修改'}, 409
            with self.c.db() as db:
                db.execute('INSERT INTO node_limits(node_id,upload_kib,download_kib,revision,updated) VALUES(?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET upload_kib=excluded.upload_kib,download_kib=excluded.download_kib,revision=excluded.revision,updated=excluded.updated',
                           (nid, data['upload_kib'], data['download_kib'], old['revision'] + 1, time.time()))
            self.c.audit('node-limits', nid, f'upload={data["upload_kib"]};download={data["download_kib"]}')
            if not self.c.LOOP:
                return {'error': '限速已保存，等待数据闸门准备'}, 503
            try:
                asyncio.run_coroutine_threadsafe(self.apply(nid), self.c.LOOP).result(timeout=5)
            except Exception:
                return {'error': '限速已保存，实时应用未确认，请重新检查配置'}, 503
            return {'ok': True, 'limits': self.view(nid), 'total_rate_kib': TOTAL_KIB,
                    'connections_unchanged': True}, 200
