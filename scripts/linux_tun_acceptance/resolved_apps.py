#!/usr/bin/env python3
"""Real resolved inside private mount, PID and network namespaces; never operate host D-Bus."""
import os,sys,json,time,socket,struct,subprocess,threading,signal,pathlib,hashlib,pwd,re
P=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(P))
import fixture_base as base

def run(*args,timeout=20,check=True):
 r=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError(str(args)+'\n'+r.stdout+'\n'+r.stderr)
 return r.stdout if check else r

def snapshot():
 routes={str(args):[{k:v for k,v in item.items() if k!='expires'} for item in json.loads(run('ip',*args))] for args in [('-j','rule'),('-j','-6','rule'),('-j','route','show','table','all'),('-j','-6','route','show','table','all')]}
 ports=[]
 for line in run('ss','-H','-lntup').splitlines():
  if 'hysteria-rust' in line or 'snell-server' in line:
   fields=line.split();ports.append((fields[0],fields[4],re.findall(r'pid=(\d+)',line)))
 return {'routes':routes,'dns':hashlib.sha256(pathlib.Path('/etc/resolv.conf').read_bytes()).hexdigest(),'resolved_pid':run('systemctl','show','systemd-resolved','--property=MainPID','--value').strip(),'ports':sorted(ports),'netns':run('ip','netns','list')}

def outer():
 before=snapshot();(P/'host-before.json').write_text(json.dumps(before,indent=2))
 try:
  command=['unshare','--mount','--net','--pid','--fork','--kill-child=KILL','--mount-proc','--propagation','private','python3',str(P/'resolved_apps.py'),'inner']
  result=subprocess.run(command,timeout=240)
  assert result.returncode==0,'isolated fixture failed'
 finally:
  after=snapshot();(P/'host-after.json').write_text(json.dumps(after,indent=2))
  assert after==before,'host baseline changed; inspect captured snapshots'
  print('PASS HOST BASELINE: routes/rules, resolver PID, resolv.conf, existing business listeners and netns unchanged',flush=True)

def dns_fixture():
 threading.Thread(target=base.fixture,daemon=True).start()
 from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
 class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
   data=json.dumps({'peer':self.client_address[0],'path':self.path}).encode()
   self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
  def log_message(self,*args):pass
 class V6Server(ThreadingHTTPServer):address_family=socket.AF_INET6
 for server_type,address in [(ThreadingHTTPServer,'192.0.2.2'),(V6Server,'fd42:5000::2')]:
  server=server_type((address,50082),Handler)
  threading.Thread(target=server.serve_forever,daemon=True).start()
 ready_tcp=threading.Event();ready_udp=threading.Event()
 def tcp53():
  listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('192.0.2.2',53));listener.listen();ready_tcp.set()
  def answer(c):
   try:
    with c:
     c.settimeout(10);q=base.recvn(c,struct.unpack('!H',base.recvn(c,2))[0]);r=base.reply(q);c.sendall(struct.pack('!H',len(r))+r)
   except (OSError,EOFError):pass
  while True:
   c,_=listener.accept();threading.Thread(target=answer,args=(c,),daemon=True).start()
 def udp53():
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.2',53));ready_udp.set()
  while True:
   q,peer=s.recvfrom(65535)
   try:s.sendto(base.reply(q),peer)
   except (ValueError,IndexError,struct.error):pass
 threading.Thread(target=tcp53,daemon=True).start();threading.Thread(target=udp53,daemon=True).start()
 assert ready_tcp.wait(3) and ready_udp.wait(3)
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.2',50053))
 print('DNS_FIXTURE_READY',flush=True)
 while True:
  q,peer=s.recvfrom(65535)
  try:s.sendto(base.reply(q),peer)
  except (ValueError,IndexError,struct.error):pass

def skip_name(data,pos):
 while data[pos]:
  if data[pos]&0xc0==0xc0:return pos+2
  pos+=1+data[pos]
 return pos+1

def answer_ips(data):
 _,flags,qd,an,_,_=struct.unpack('!6H',data[:12]);assert flags&15==0,('DNS error',flags&15)
 pos=12
 for _ in range(qd):pos=skip_name(data,pos)+4
 values=[]
 for _ in range(an):
  pos=skip_name(data,pos);kind,_,_,size=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
  if kind in [1,28]:values.append(socket.inet_ntop(socket.AF_INET if kind==1 else socket.AF_INET6,data[pos:pos+size]))
  pos+=size
 assert values,'no DNS address answers'
 return values

def stub_query(name,kind,tcp=False):
 q=base.question(name,kind)
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(5);s.connect(('127.0.0.53',53))
  if tcp:s.sendall(struct.pack('!H',len(q))+q);r=base.recvn(s,struct.unpack('!H',base.recvn(s,2))[0])
  else:s.send(q);r=s.recv(65535)
 return answer_ips(r)

def probe(mode):
 result={}
 for name in ['direct.test','proxy.test']:
  for kind,family in [(1,socket.AF_INET),(28,socket.AF_INET6)]:
   addresses=stub_query(name,kind);ip=addresses[0]
   expected=('198.18.' if kind==1 else 'fd00:198:18:') if mode=='tun' else ('192.0.2.2' if kind==1 else 'fd42:5000::2')
   assert ip.startswith(expected),(mode,name,ip)
   result[name+str(kind)]=ip
   if mode=='tun':
    assert stub_query(name,kind,True)[0]==ip
    addresses={entry[4][0] for entry in socket.getaddrinfo(name,50080,family,socket.SOCK_STREAM)}
    assert addresses=={ip},('libc DNS mismatch',addresses,ip)
    base.echo(ip);base.echo(ip,True)
    print('PASS stub UDP/TCP + libc DNS + TCP/UDP forwarding',name,kind,flush=True)
 print('MAPPINGS '+json.dumps(result),flush=True)

def inner():
 os.umask(0o077)
 # This code runs ONLY after unshare. Refuse to operate in the host PID namespace.
 assert os.getpid()==1,('expected private PID namespace init',os.getpid())
 assert len(json.loads(run('ip','-j','link')))==1,'expected empty network namespace'
 run('mount','-t','tmpfs','-o','mode=755','tmpfs','/run')
 run('mount','-t','tmpfs','-o','mode=755','tmpfs','/etc/systemd')
 pathlib.Path('/run/dbus').mkdir(mode=0o755);pathlib.Path('/run/dbus').chmod(0o755)
 pathlib.Path('/run/systemd/resolve').mkdir(mode=0o755,parents=True);pathlib.Path('/run/systemd').chmod(0o755)
 user=pwd.getpwnam('systemd-resolve');os.chown('/run/systemd/resolve',user.pw_uid,user.pw_gid)
 pathlib.Path('/etc/systemd/resolved.conf').write_text('[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nDNSStubListener=yes\nReadEtcHosts=no\nCache=yes\n')
 pathlib.Path('/etc/systemd/resolved.conf').chmod(0o644)
 os.environ['DBUS_SYSTEM_BUS_ADDRESS']='unix:path=/run/dbus/system_bus_socket'
 os.environ['SYSTEMD_LOG_TARGET']='console';os.environ['SYSTEMD_LOG_LEVEL']='info'
 os.environ['SYSTEMD_PAGER']='cat';os.environ['SYSTEMD_COLORS']='0'
 children=[];logs=[];created=False
 def launch(tag,*args):
  log=(P/(tag+'.log')).open('w');logs.append(log)
  p=subprocess.Popen(args,stdout=log,stderr=log);children.append(p);return p
 def ready(p,tag,text):
  for _ in range(100):
   data=(P/(tag+'.log')).read_text()
   if p.poll() is not None:raise RuntimeError(tag+' exited: '+data)
   if text in data:return
   time.sleep(.1)
  raise RuntimeError(tag+' not ready: '+data)
 def stop(p):
  if p.poll() is None:p.terminate();p.wait(timeout=15)
 def ctl(*args):return run('resolvectl',*args)
 def rules():return [json.loads(run('ip','-j',family,'rule')) for family in ['-4','-6']]
 def routes():return [json.loads(run('ip','-j',family,'route','show','table','main')) for family in ['-4','-6']]
 def current_links():return sorted(x['ifname'] for x in json.loads(run('ip','-j','link')))
 try:
  run('ip','link','set','lo','up');run('ip','netns','add','qa-server');created=True
  run('ip','link','add','qa0','type','veth','peer','name','qa1','netns','qa-server')
  for prefix,iface,ip,v6 in [([], 'qa0','192.0.2.1/24','fd42:5000::1/64'),(['-n','qa-server'],'qa1','192.0.2.2/24','fd42:5000::2/64')]:
   run('ip',*prefix,'link','set','lo','up');run('ip',*prefix,'addr','add',ip,'dev',iface);run('ip',*prefix,'-6','addr','add',v6,'dev',iface,'nodad');run('ip',*prefix,'link','set',iface,'up')
  time.sleep(1.1)
  baseline_rules=rules();baseline_routes=routes();baseline_links=current_links()
  bus=launch('bus','dbus-daemon','--system','--nofork','--nopidfile','--address=unix:path=/run/dbus/system_bus_socket')
  for _ in range(50):
   if pathlib.Path('/run/dbus/system_bus_socket').exists():break
   time.sleep(.1)
  resolved=launch('resolved','/usr/lib/systemd/systemd-resolved')
  for _ in range(50):
   if resolved.poll() is not None:raise RuntimeError((P/'resolved.log').read_text())
   if run('resolvectl','status',check=False).returncode==0:break
   time.sleep(.1)
  else:raise RuntimeError('private resolved D-Bus not ready')
  assert pathlib.Path('/etc/resolv.conf').resolve()==pathlib.Path('/run/systemd/resolve/stub-resolv.conf')
  assert '127.0.0.53' in pathlib.Path('/etc/resolv.conf').read_text()
  fx=launch('fixture','ip','netns','exec','qa-server','python3',str(P/'resolved_apps.py'),'fixture');ready(fx,'fixture','DNS_FIXTURE_READY')
  ctl('dns','qa0','192.0.2.2');ctl('default-route','qa0','yes');ctl('dnssec','qa0','no');ctl('dnsovertls','qa0','no')
  baseline_status=ctl('status','qa0');(P/'resolved-baseline.txt').write_text(baseline_status)
  print(run('python3',str(P/'resolved_apps.py'),'probe','baseline'),flush=True)
  print('PASS independent resolved baseline (real A/AAAA)',flush=True)
  run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(P/'key.pem'),'-out',str(P/'cert.pem'),'-subj','/CN=proxy.test','-addext','subjectAltName=DNS:proxy.test','-addext','basicConstraints=critical,CA:FALSE')
  auth=os.urandom(24).hex()
  server={'listen':'192.0.2.2:50000','auth':{'type':'password','password':auth},'tls':{'cert':str(P/'cert.pem'),'key':str(P/'key.pem')},'resolver':{'type':'tcp','tcp':{'addr':'192.0.2.2:50053'}}}
  client={'server':'192.0.2.2:50000','auth':auth,'tls':{'sni':'proxy.test','ca':str(P/'cert.pem')},'routing':{'version':1,'default':'proxy','rules':['direct(direct.test)','reject(reject.test)']},'tun':{'name':'hytunqa','mtu':1400,'route':{'strict':True},'egress':{'interface':'qa0','mark':4741426,'resolver':'192.0.2.2:50053'},'dns':{'cache':str(P/'fake.json'),'maxEntries':8192}}}
  (P/'direct-domains.txt').write_text('# Direct domain set\ndirect.test\n')
  client['routing']['ruleSets']={'direct_domains':{'file':'direct-domains.txt'}}
  client['routing']['rules']=['direct(set:direct_domains)','reject(reject.test)']
  for name,c in [('server',server),('client',client)]:
   f=P/(name+'.json');f.write_text(json.dumps(c));f.chmod(0o600)
  doc=json.loads(run(str(P/'hysteria'),'doctor','client','-c',str(P/'client.json'),'--output','json'))
  assert doc['passed'],doc
  assert not (P/'fake.json').exists() and not (P/'fake.json.lock').exists()
  assert rules()==baseline_rules and current_links()==baseline_links
  (P/'doctor.json').write_text(json.dumps(doc,indent=2));print('PASS read-only doctor before TUN; cache/rules/links unchanged',flush=True)
  # Start near the old 4096-entry limit, then exercise explicit expansion with real applications.
  (P/'fake.json').write_text(json.dumps({'version':1,'names':[f'seed-{i}.test' for i in range(4090)]}))
  print('PASS seeded 4090 entries after read-only doctor; configured capacity 8192',flush=True)
  srv=launch('server','ip','netns','exec','qa-server',str(P/'hysteria'),'server','--disable-update-check','-c',str(P/'server.json'));ready(srv,'server','Hysteria server listening')
  def start(tag):
   c=launch(tag,str(P/'hysteria'),'client','--disable-update-check','-c',str(P/'client.json'));ready(c,tag,'TUN proxy listening');return c
  def capture_probe(tag,expected):
   before=(P/'fake.json').read_bytes()
   result=run(str(P/'hysteria'),'doctor','client','--dns','direct.test','--timeout','5s','--output','json','-c',str(P/'client.json'),timeout=15,check=False)
   data=json.loads(result.stdout);(P/(tag+'.json')).write_text(json.dumps(data,indent=2))
   checks={item['id']:item for item in data['checks']}
   assert checks['system_resolution']['status']=='pass',data
   assert checks['dns_capture']['details']['outcome']==expected,data
   assert result.returncode==(0 if expected=='matched_cache' else 3),data
   assert all(item not in checks for item in ['tun_capabilities','tun_policy','server_connection']),data
   after=(P/'fake.json').read_bytes()
   if expected=='matched_cache':
    before_names=json.loads(before)['names'];after_names=json.loads(after)['names']
    assert after_names[:len(before_names)]==before_names and len(after_names)==len(before_names)+1
    assert checks['dns_capture']['details']['query']==after_names[-1]
   else:assert before==after
   assert 'hy2-probe-' in checks['system_resolution']['details']['query']
   print('PASS live DNS probe '+tag+': '+expected+'; '+str(checks['system_resolution']['details']['addresses']),flush=True)
  c=start('client1');ctl('flush-caches')
  # Without a TUN DNS route, the physical-interface-bound stub path may fail.
  before=time.monotonic()
  try:q=run('resolvectl','query','--cache=no','unconfigured.test',timeout=12,check=False)
  except subprocess.TimeoutExpired:q=subprocess.CompletedProcess([],124,'','query deadline exceeded')
  (P/'unconfigured-query.txt').write_text(q.stdout+q.stderr)
  print('OBSERVE DNS before TUN per-link setup: '+('query failed/timed out' if q.returncode else 'Fake-IP' if '198.18.' in q.stdout else 'real IP'),flush=True)
  capture_probe('dns-probe-before','non_fake_answers')
  (P/'rules-active.json').write_text(json.dumps(rules(),indent=2))
  ctl('dns','hytunqa','198.18.0.1');ctl('domain','hytunqa','~.');ctl('dnssec','hytunqa','no');ctl('dnsovertls','hytunqa','no');ctl('flush-caches')
  (P/'resolved-tun.txt').write_text(ctl('status'))
  print(run('python3',str(P/'resolved_apps.py'),'probe','tun',timeout=45),flush=True)
  q=ctl('query','--cache=no','direct.test');assert '198.18.' in q or 'fd00:198:18:' in q
  print('PASS private resolvectl D-Bus query uses TUN',flush=True)
  capture_probe('dns-probe-active','matched_cache')
  print(run('python3',str(P/'resolved_apps.py'),'apps','tun',timeout=60),flush=True)
  print(run('python3',str(P/'resolved_apps.py'),'apps','burst',timeout=60),flush=True)
  stop(srv)
  print(run('python3',str(P/'resolved_apps.py'),'apps','offline',timeout=30),flush=True)
  srv=launch('server-restart','ip','netns','exec','qa-server',str(P/'hysteria'),'server','--disable-update-check','-c',str(P/'server.json'));ready(srv,'server-restart','Hysteria server listening')
  time.sleep(1.2)
  print(run('python3',str(P/'resolved_apps.py'),'apps','tun',timeout=60),flush=True)
  mapping=(P/'fake.json').read_bytes()
  assert len(json.loads(mapping)['names'])>4096

  stop(c)
  for _ in range(50):
   if 'hytunqa' not in current_links():break
   time.sleep(.1)
  assert rules()==baseline_rules and routes()==baseline_routes and current_links()==baseline_links
  # First check automatic link teardown without manually flushing the resolver.
  print(run('python3',str(P/'resolved_apps.py'),'probe','after-stop',timeout=30),flush=True)
  assert ctl('dns','qa0').strip().endswith('192.0.2.2')
  print('PASS SIGTERM restores ordinary DNS without manual resolver flush; per-link physical DNS retained',flush=True)
  c=start('client2');ctl('dns','hytunqa','198.18.0.1');ctl('domain','hytunqa','~.');ctl('dnssec','hytunqa','no');ctl('dnsovertls','hytunqa','no');ctl('flush-caches')
  print(run('python3',str(P/'resolved_apps.py'),'probe','tun',timeout=45),flush=True);assert (P/'fake.json').read_bytes()==mapping
  print(run('python3',str(P/'resolved_apps.py'),'apps','retained',timeout=60),flush=True)
  assert (P/'fake.json').read_bytes()==mapping
  print('PASS all cached mappings unchanged after real application traffic and restart',flush=True)
  # Explicit revert while the interface still exists is also supported.
  ctl('revert','hytunqa');stop(c);ctl('flush-caches')
  print(run('python3',str(P/'resolved_apps.py'),'probe','after-stop',timeout=30),flush=True)
  assert rules()==baseline_rules and routes()==baseline_routes and current_links()==baseline_links
  print('PASS persistent mappings on restart; explicit resolvectl revert + stop restores DNS',flush=True)
 finally:
  for p in reversed(children):
   if p.poll() is None:
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
  if created:run('ip','netns','delete','qa-server')
  for log in logs:log.close()
  print('Isolated fixture processes stopped; namespace init exiting',flush=True)

def apps(mode):
 # Run a real curl process with its normal system resolver; bypass inherited proxy environment.
 def request(name,family,retained=None,fail=False):
  args=['curl','--noproxy','*','--silent','--show-error','--connect-timeout','3','--max-time','6','--write-out','\n%{remote_ip}','-'+str(family)]
  if retained:
   address=retained if family==4 else '['+retained+']'
   args+=['--resolve',f'{name}:50082:{address}']
  result=run(*args,f'http://{name}:50082/application-check',timeout=8,check=False)
  if fail:
   assert result.returncode!=0 and not result.stdout.rsplit('\n',1)[0].strip(),(name,'unexpected successful route',result.stdout)
   return
  assert result.returncode==0,(name,result.returncode,result.stderr)
  body,remote_ip=result.stdout.rsplit('\n',1)
  import ipaddress
  assert ipaddress.ip_address(remote_ip).version==family,(name,family,remote_ip)
  assert remote_ip.startswith('198.18.' if family==4 else 'fd00:198:18:'),(name,remote_ip)
  data=json.loads(body);assert data['path']=='/application-check',data
  proxy=name!='direct.test'
  expected={'192.0.2.2','fd42:5000::2'} if proxy else {'192.0.2.1','fd42:5000::1'}
  assert data['peer'] in expected,(name,family,data,expected)
 if mode=='burst':
  from concurrent.futures import ThreadPoolExecutor
  before=len(json.loads((P/'fake.json').read_text())['names'])
  with ThreadPoolExecutor(max_workers=8) as pool:
   list(pool.map(lambda i:request(f'cold-{i}.proxy.test',4 if i%2==0 else 6),range(128)))
  after=len(json.loads((P/'fake.json').read_text())['names'])
  assert after==before+128,(before,after)
  print('PASS 128 concurrent curl cold domains through proxy; unique mappings grew by 128',flush=True)
 elif mode=='offline':
  for family in [4,6]:
   request('direct.test',family)
   request('proxy.test',family,fail=True)
  print('PASS server offline: real curl direct remains available, proxy fails without direct fallback',flush=True)
 else:
  retained=json.loads((P/'application-addresses.json').read_text()) if mode=='retained' else {}
  for name in ['direct.test','proxy.test']:
   for family in [4,6]:
    key=f'{name}/{family}'
    request(name,family,retained.get(key))
    if mode=='tun':retained[key]=stub_query(name,1 if family==4 else 28)[0]
  if mode=='tun':
   (P/'application-addresses.json').write_text(json.dumps(retained))
   for family in [4,6]:request('reject.test',family,fail=True)
  print('PASS real curl IPv4/IPv6 direct and proxy with verified target peer; '+('retained Fake-IP after restart' if mode=='retained' else 'system DNS and reject rule'),flush=True)

if __name__=='__main__':
 if sys.argv[1]=='outer':outer()
 elif sys.argv[1]=='inner':inner()
 elif sys.argv[1]=='fixture':dns_fixture()
 elif sys.argv[1]=='probe':probe(sys.argv[2])
 elif sys.argv[1]=='apps':apps(sys.argv[2])
