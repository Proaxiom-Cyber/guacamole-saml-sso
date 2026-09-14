"""Local, internal-network-only Patroni/etcd fixture. No credentials or host fencing."""
import subprocess as sp,json,time,pathlib,datetime
R=pathlib.Path(__file__).resolve().parent
D=['docker','--context','desktop-linux']; P='guac-ha-patroni-20260915'; created=[]; results=[]
PG='guac-ha-patroni-research:20260915'; ETCD='quay.io/coreos/etcd:v3.6.0'
def cmd(*a,check=True,timeout=30):
 p=sp.run(D+list(a),text=True,capture_output=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError(a[0]+': '+p.stderr[:500])
 return p

def rec(test,**values):
 r={'test':test,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**values};results.append(r);print(json.dumps(r),flush=True);(R/'results.json').write_text(json.dumps(results,indent=2)+'\n')
def start(n,*a):
 cmd('run','-d','--name',n,'--network',P,*a);created.append(n)
def state(n):
 code="import urllib.request,json; d=json.load(urllib.request.urlopen('http://localhost:8008/patroni',timeout=2)); print(json.dumps({k:d.get(k) for k in ['state','role','timeline','xlog','dcs_last_seen','patroni']}))"
 p=cmd('exec',n,'python3','-c',code,check=False,timeout=5)
 try:return json.loads(p.stdout)
 except:return {'state':'unreachable','role':None}
def sql(n,q):return cmd('exec',n,'psql','-h','127.0.0.1','-U','postgres','-d','postgres','-At','-v','ON_ERROR_STOP=1','-c',q,check=False,timeout=8)
def wait_roles(nodes,timeout=120):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  states={n:state(n) for n in nodes}
  leaders=[n for n,s in states.items() if s['role'] in ['primary','master'] and s['state']=='running']
  replicas=[n for n,s in states.items() if s['role']=='replica' and s['state']=='running']
  if len(leaders)==1 and len(replicas)==len(nodes)-1:return leaders[0],replicas,states
  time.sleep(2)
 raise RuntimeError('healthy role timeout '+json.dumps(states))
try:
 cmd('network','create','--internal',P)
 rec('environment',docker=cmd('info','--format','{{.ServerVersion}} {{.Architecture}}').stdout.strip(),images={i:cmd('image','inspect',i,'--format','{{.Id}}').stdout.strip() for i in [PG,ETCD]},policy={'synchronous_mode':False,'synchronous_commit':'on','ttl':20,'loop_wait':2,'retry_timeout':3,'failsafe_mode':False,'watchdog':'off'})
 etcds=[P+'-e'+str(i) for i in range(1,4)]
 cluster=','.join(n+'=http://'+n+':2380' for n in etcds)
 for n in etcds:
  start(n,'--tmpfs','/etcd-data',ETCD,'/usr/local/bin/etcd','--name',n,'--data-dir','/etcd-data','--listen-client-urls','http://0.0.0.0:2379','--advertise-client-urls','http://'+n+':2379','--listen-peer-urls','http://0.0.0.0:2380','--initial-advertise-peer-urls','http://'+n+':2380','--initial-cluster',cluster,'--initial-cluster-state','new','--initial-cluster-token',P)
 for _ in range(30):
  p=cmd('exec',etcds[0],'/usr/local/bin/etcdctl','--endpoints='+','.join('http://'+n+':2379' for n in etcds),'endpoint','health',check=False)
  if p.returncode==0:break
  time.sleep(1)
 else:raise RuntimeError('etcd health timeout')
 rec('etcd_healthy',health=p.stdout+p.stderr)
 nodes=[P+'-p1',P+'-p2']
 for n in nodes:
  config={'scope':P,'namespace':'/service/','name':n,'restapi':{'listen':'0.0.0.0:8008','connect_address':n+':8008'},'etcd3':{'hosts':','.join(x+':2379' for x in etcds)},'bootstrap':{'dcs':{'ttl':20,'loop_wait':2,'retry_timeout':3,'synchronous_mode':False,'failsafe_mode':False,'postgresql':{'use_pg_rewind':True,'parameters':{'wal_level':'replica','hot_standby':'on','max_wal_senders':5,'max_replication_slots':5,'wal_log_hints':'on','synchronous_commit':'on'}}},'initdb':[{'encoding':'UTF8'},{'auth':'trust'}]},'postgresql':{'listen':'0.0.0.0:5432','connect_address':n+':5432','data_dir':'/var/lib/postgresql/data','bin_dir':'/usr/local/bin','authentication':{'superuser':{'username':'postgres'},'replication':{'username':'replicator'}},'pg_hba':['local all all trust','host all all 0.0.0.0/0 trust','host replication all 0.0.0.0/0 trust']},'watchdog':{'mode':'off'}}
  (R/(n+'.json')).write_text(json.dumps(config,indent=2)+'\n')
  start(n,'--tmpfs','/var/lib/postgresql','--tmpfs','/tmp','-e','PATRONI_CONFIGURATION='+json.dumps(config),'--entrypoint','sh',PG,'-c','mkdir -p /var/lib/postgresql/data; chown postgres:postgres /var/lib/postgresql/data; chmod 700 /var/lib/postgresql/data; exec gosu postgres /opt/patroni/bin/patroni')
 leader,replicas,states=wait_roles(nodes)
 assert sql(leader,"CREATE TABLE ha_managed(id int primary key); INSERT INTO ha_managed VALUES(1);").returncode==0
 for _ in range(30):
  if sql(replicas[0],'SELECT count(*) FROM ha_managed;').stdout.strip()=='1':break
  time.sleep(1)
 else:raise RuntimeError('replication catchup timeout')
 rec('initial_cluster',states=states,postgres_version=sql(leader,'SHOW server_version;').stdout.strip(),replica_row_count=1)
 t=time.monotonic();cmd('kill','--signal','KILL',leader)
 target=replicas[0]
 for _ in range(60):
  s=state(target)
  if s['role'] in ['primary','master'] and s['state']=='running':break
  time.sleep(1)
 else:raise RuntimeError('promotion timeout')
 elapsed=round(time.monotonic()-t,2)
 p=sql(target,'INSERT INTO ha_managed VALUES(2); SELECT count(*) FROM ha_managed;')
 assert p.returncode==0
 rec('automatic_promotion',killed=leader,promoted=target,seconds_until_observed=elapsed,state=s,write_exit=p.returncode,write_result=p.stdout.strip(),manual_promotion_used=False)
 # tmpfs is empty after stop; Patroni rebuilds this node from the surviving primary.
 cmd('start',leader)
 leader2,replicas2,states2=wait_roles(nodes)
 rec('replica_rebuilt_after_restart',states=states2)
 cmd('stop','-t','1',etcds[1]);cmd('stop','-t','1',etcds[2])
 t=time.monotonic();observations=[]
 while time.monotonic()-t<45:
  observations.append({'seconds':round(time.monotonic()-t,2),'states':{n:state(n) for n in nodes}})
  time.sleep(2)
 p=cmd('exec',etcds[0],'/usr/local/bin/etcdctl','--endpoints=http://127.0.0.1:2379','--command-timeout=3s','endpoint','health',check=False)
 final=observations[-1]['states'];writes={n:{'exit_code':(q:=sql(n,'INSERT INTO ha_managed VALUES(3);')).returncode,'output':q.stdout.strip(),'error':q.stderr.strip()} for n in nodes}
 assert all(s['role'] not in ['primary','master'] for s in final.values())
 assert all(x['exit_code']!=0 for x in writes.values())
 rec('quorum_loss',stopped_etcd=etcds[1:],observation_seconds=round(time.monotonic()-t,2),remaining_etcd_health_exit=p.returncode,final_states=final,write_attempts=writes,observations=observations)
 cmd('kill','--signal','KILL',leader2)
 remaining=replicas2[0];observations=[];t=time.monotonic()
 while time.monotonic()-t<30:
  observations.append({'seconds':round(time.monotonic()-t,2),'state':state(remaining)})
  time.sleep(2)
 assert all(x['state']['role'] not in ['primary','master'] for x in observations)
 rec('no_promotion_without_quorum_after_primary_container_killed',killed=leader2,remaining=remaining,observations=observations)
finally:
 for n in created:
  p=cmd('logs',n,check=False);(R/(n+'.log')).write_text(p.stdout+p.stderr)
 for n in reversed(created):cmd('rm','-f','-v',n,check=False)
 cmd('network','rm',P,check=False)
 rec('cleanup',containers=cmd('ps','-a','--filter','name='+P,'--format','{{.Names}}').stdout.strip(),networks=cmd('network','ls','--filter','name='+P,'--format','{{.Name}}').stdout.strip())
