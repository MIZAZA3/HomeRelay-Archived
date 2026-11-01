"""Explicit localhost test client only. No actions at import, system proxy or TUN."""
import socket
import ssl
import struct


def exact(s, n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part:raise EOFError('test proxy closed')
        data+=part
    return data


def socks(command,host,port):
    s=socket.create_connection(('127.0.0.1',31980),6);s.settimeout(8)
    try:
        s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
        h=host.encode();s.sendall(bytes([5,command,0,3,len(h)])+h+struct.pack('!H',port))
        response=exact(s,4);assert response[1]==0
        if response[3]==1:bound=socket.inet_ntoa(exact(s,4))
        elif response[3]==4:bound=socket.inet_ntop(socket.AF_INET6,exact(s,16))
        else:bound=exact(s,exact(s,1)[0]).decode()
        target_port=int.from_bytes(exact(s,2),'big')
        return s,('127.0.0.1' if bound in ('0.0.0.0','::') else bound,target_port)
    except BaseException:s.close();raise


def https(host):
    s,_=socks(1,host,443)
    try:
        with ssl.create_default_context().wrap_socket(s,server_hostname=host) as tls:
            tls.sendall(('GET / HTTP/1.0\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
            data=b''
            while b'\r\n' not in data and len(data)<4096:
                part=tls.recv(1024)
                if not part:break
                data+=part
            return {'ok':data.startswith(b'HTTP/'),'response':data.split(b'\r\n')[0].decode('ascii','replace')}
    finally:s.close()
