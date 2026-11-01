"""No network/production config: DNS eligibility and bounded admission races."""
import asyncio
import collections
import json
import pathlib
import struct
import sys
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'server'))
from flow_lifecycle import Flow, Registry
from target_policy import encode, read_udp_frame, frame_parts

RESULTS = []

def check(name, value):
    assert value, name
    RESULTS.append(name)

def packet(tx=1, response=False, port=53, payload=None):
    if payload is None:
        payload = struct.pack('!HHHHHH', tx, 0x8180 if response else 0x100, 1, 0, 0, 0)+b'\x01x\x00\x00\x01\x00\x01'
    return struct.pack('!HB', len(payload), 255)+encode('8.8.8.8', port)+payload

class Writer:
    def __init__(self):self.closed=False
    def close(self):self.closed=True

async def run():
    f=Flow('a',Writer());f.udp=True
    f.dns(packet());check('outstanding DNS cannot be reclaimed',not f.reclaimable())
    f.dns(packet(response=True),True)
    check('only completed DNS is eligible',f.reclaimable())
    f.busy=1;check('partial/new frame or draining response blocks reclaim',not f.reclaimable());f.busy=0
    f.dns(packet(2));check('another outstanding query blocks reclaim',not f.reclaimable())
    f.dns(packet(2,True),True);check('all replies restore eligibility',f.reclaimable())
    f.dns(packet(port=443,payload=b'game'))
    check('mixed/non-DNS UDP stays protected permanently',not f.reclaimable() and not f.pending)
    for mode in ['tcp','unmatched','query-overflow']:
        f=Flow('a',Writer());f.udp=mode!='tcp'
        if mode=='unmatched':f.dns(packet(response=True),True)
        elif mode=='query-overflow':
            for tx in range(65):f.dns(packet(tx))
        else:f.dns(packet());f.dns(packet(response=True),True)
        check(mode+' is never a reclaim victim',not f.reclaimable())
    reader=asyncio.StreamReader();started=[]
    job=asyncio.create_task(read_udp_frame(reader,1,lambda:started.append(True)))
    await asyncio.sleep(.01);check('waiting for UDP first byte remains idle',not started)
    reader.feed_data(packet()[:1]);await asyncio.sleep(.01)
    check('first frame byte protects the in-progress frame',bool(started) and not job.done())
    reader.feed_data(packet()[1:]);frame=await job
    check('UDP frame parser preserves exact wire bytes',frame==packet() and frame_parts(frame)[1]==53)
    c=types.SimpleNamespace(ACTIVE=collections.Counter(),LIVE=collections.defaultdict(set),GATE_NODE_LIMIT=2,GATE_GLOBAL_LIMIT=4)
    r=Registry()
    first=await r.admit(c,'a',Writer());second=await r.admit(c,'a',Writer())
    check('full active TCP capacity is bounded, not evicted',await r.admit(c,'a',Writer()) is None and not first.writer.closed)
    second.udp=True;second.dns(packet());second.dns(packet(response=True),True)
    async def release_victim():
        while not second.writer.closed:await asyncio.sleep(0)
        r.release(c,second)
    close_job=asyncio.create_task(release_victim())
    arrivals=await asyncio.gather(*(r.admit(c,'a',Writer()) for _ in range(8)))
    await close_job
    check('concurrent arrivals cannot exceed node cap or double-release a victim',sum(v is not None for v in arrivals)==1 and c.ACTIVE['all']==2 and r.metrics['reclaimed_dns']==1)
    for f in list(r.flows):r.release(c,f)
    check('final counters and live-writer sets are empty',not r.flows and not c.LIVE['a'] and c.ACTIVE['all']==0 and c.ACTIVE['a']==0)
    # Another arrival can win the first reclaimed slot. The second release
    # must still receive a final capacity check rather than false rejection.
    victims=[await r.admit(c,'a',Writer()) for _ in range(2)]
    for f in victims:
        f.udp=True;f.dns(packet());f.dns(packet(response=True),True)
    async def competing_arrival():
        for index,f in enumerate(victims):
            while not f.writer.closed:await asyncio.sleep(0)
            r.release(c,f)
            if index==0:assert await r.admit(c,'a',Writer()) is not None
    rival=asyncio.create_task(competing_arrival())
    admitted=await r.admit(c,'a',Writer());await rival
    check('capacity is rechecked after the last awaited reclaim despite a competing arrival',admitted is not None and c.ACTIVE['a']==2)
    for f in list(r.flows):r.release(c,f)
    print(json.dumps({'lifecycle_unit_passed':RESULTS,'count':len(RESULTS)}))

if __name__=='__main__':asyncio.run(run())
