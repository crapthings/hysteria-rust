#!/usr/bin/env python3
"""Private DNS and TCP/UDP echo fixtures for the namespace acceptance runner."""
import socket,struct,threading,time

def recvn(s,n):
 data=b''
 while len(data)<n:
  chunk=s.recv(n-len(data))
  if not chunk: raise EOFError()
  data+=chunk
 return data

def question(name,kind):
 return struct.pack('!6H',1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)

def qend(q):
 n=12
 while q[n]: n+=q[n]+1
 return n+5

def reply(q):
 e=qend(q);kind=struct.unpack('!H',q[e-4:e-2])[0]
 if kind==1:data=socket.inet_pton(socket.AF_INET,'192.0.2.2')
 elif kind==28:data=socket.inet_pton(socket.AF_INET6,'fd42:5000::2')
 elif kind==16:data=b'\7fixture'
 else:data=None
 return q[:2]+struct.pack('!5H',0x8180,1,int(data is not None),0,0)+q[12:e]+(b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(data))+data if data else b'')

def fixture():
 def serve_tcp(family,addr,port,dns=False):
  s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  s.bind((addr,port));s.listen()
  def handle(c):
   try:
    with c:
     c.settimeout(15)
     if dns:
      q=recvn(c,struct.unpack('!H',recvn(c,2))[0]);r=reply(q);c.sendall(struct.pack('!H',len(r))+r)
     else:
      while True:
       d=c.recv(65535)
       if not d:break
       c.sendall(d)
   except (OSError,EOFError):pass
  while True:
   c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
 def serve_udp(family,addr):
  s=socket.socket(family,socket.SOCK_DGRAM)
  if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  s.bind((addr,50081))
  while True:
   d,a=s.recvfrom(65535);s.sendto(d,a)
 for fam,addr in [(socket.AF_INET,'192.0.2.2'),(socket.AF_INET6,'fd42:5000::2')]:
  threading.Thread(target=serve_tcp,args=(fam,addr,50080),daemon=True).start()
  threading.Thread(target=serve_udp,args=(fam,addr),daemon=True).start()
 threading.Thread(target=serve_tcp,args=(socket.AF_INET,'192.0.2.2',50053,True),daemon=True).start()
 print('FIXTURE_READY',flush=True)
 while True:time.sleep(1)

def echo(ip,udp=False,fail=False):
 family=socket.AF_INET6 if ':' in ip else socket.AF_INET
 with socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
  s.settimeout(3)
  try:
   s.connect((ip,50081 if udp else 50080));s.sendall(b'tun-real-kernel-acceptance');r=s.recv(4096)
   if fail:
    assert not r,'unexpected reachable rejected/proxy target';return
   assert r==b'tun-real-kernel-acceptance',r
  except (OSError,TimeoutError):
   if not fail:raise
