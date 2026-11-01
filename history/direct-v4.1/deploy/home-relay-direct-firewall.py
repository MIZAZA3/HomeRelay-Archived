#!/usr/bin/python3
"""Root-only idempotent, narrowly scoped OUTPUT containment; no global flush."""
import pwd, subprocess
UID=str(pwd.getpwnam('home-relay-v2').pw_uid)
CHAIN='HR_DIRECT_EGRESS'
def run(binary,*args,check=True):
    return subprocess.run([binary,'-w','10',*args],check=check,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
for binary,loopback in [('/usr/sbin/iptables','127.0.0.0/8'),('/usr/sbin/ip6tables','::1/128')]:
    if run(binary,'-S',CHAIN,check=False).returncode:
        run(binary,'-N',CHAIN)
    rules=[['-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','RETURN'],
           ['-d',loopback,'-j','RETURN'],['-j','REJECT']]
    for rule in rules:
        if run(binary,'-C',CHAIN,*rule,check=False).returncode:run(binary,'-A',CHAIN,*rule)
    jump=['-m','owner','--uid-owner',UID,'-j',CHAIN]
    if run(binary,'-C','OUTPUT',*jump,check=False).returncode:run(binary,'-I','OUTPUT','1',*jump)
print('HomeRelay UID-only outbound containment verified (IPv4/IPv6).')
