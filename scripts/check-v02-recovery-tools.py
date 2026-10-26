#!/usr/bin/env python3
"""Local stopped-devnet recovery checks; no CI, mining, proving or submissions."""
import argparse,pathlib,subprocess,os,socket,time,json,urllib.request,tomllib,tempfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('run_dir',type=pathlib.Path)
parser.add_argument('--ckb',default=os.environ.get('TACTUS_V02_CKB_BIN','ckb'))
args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];run=args.run_dir.resolve()
manifest=json.loads((run/'deployment.json').read_text())
assert manifest['schema']=='tactus-v02-devnet-manifest-v1' and manifest['production_ready'] is False
config=tomllib.loads((run/'node/ckb.toml').read_text())
assert config['chain']['spec']=={'file':'specs/dev.toml'}
address=config['rpc']['listen_address'];assert address.startswith('127.0.0.1:')
listeners=config['network']['listen_addresses'];assert len(listeners)==1 and listeners[0].startswith('/ip4/127.0.0.1/tcp/')
ports=[int(address.split(':')[1]),int(listeners[0].rsplit('/',1)[1])];assert len(set(ports))==2
nodebin=args.ckb
assert subprocess.check_output([nodebin,'--version'],text=True).startswith('ckb 0.210.0 ')
out=pathlib.Path(tempfile.mkdtemp(prefix='v02-recovery-tools-',dir=root/'artifacts'))
print(out,flush=True)
node=None;observer=None
for port in ports:
 with socket.socket() as sock:
  sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind(('127.0.0.1',port));sock.listen(1)
env=os.environ.copy();env['TACTUS_CKB_RPC_ADDR']=address
def start():
 global node
 node=subprocess.Popen([nodebin,'run','-C',str(run/'node'),'--indexer'],stdout=open(out/'node.log','ab'),stderr=subprocess.STDOUT)
 for _ in range(200):
  try:
   req=urllib.request.Request('http://'+address,data=b'{"id":1,"jsonrpc":"2.0","method":"get_tip_header","params":[]}',headers={'Content-Type':'application/json'})
   with urllib.request.urlopen(req,timeout=1) as response:
    if json.load(response).get('result'):return
  except (OSError,ValueError):pass
  if node.poll() is not None:raise RuntimeError('node stopped')
  time.sleep(.1)
 raise RuntimeError('node startup timeout')
def stop():
 global node
 if node is not None:node.terminate();node.wait(timeout=20);node=None
def wait_snapshot(predicate):
 for _ in range(1000):
  try:
   v=json.loads((out/'observer.json').read_text())
   if predicate(v):return v
  except (OSError,ValueError):pass
  if observer.poll() is not None:raise RuntimeError('observer terminated')
  time.sleep(.1)
 raise RuntimeError('observer check timeout')
try:
 start()
 manifest=str(run/'deployment.json');recover=str(root/'services/v02-lab/target/debug/recover-v02')
 r=subprocess.run([recover,manifest,str(out/'report.json'),'report'],env=env,capture_output=True,text=True);assert r.returncode==0,r.stderr
 report=json.loads((out/'report.json').read_text());assert report['settled_batches']==0 and report['published_batches']==2
 assert [b['phase'] for b in report['lifecycle']['batches']]==['Ordered','Ordered']
 assert report['lifecycle']['payments']==[] and report['lifecycle']['control']['confirmations']>0
 assert report['lifecycle']['phases']['Soft']['observation']=='unobserved'
 request={'owner':'0x'+'21'*20,'recipient_lock_hash':'0x'+'95'*32,'id':'1','amount_shannons':'100000000'}
 (out/'request.json').write_text(json.dumps(request));rejections=[]
 for mode in ['release','escape']:
  destination=out/(mode+'.json');destination.write_text('{"sentinel":"old file"}\n');before=destination.read_bytes()
  r=subprocess.run([recover,manifest,str(destination),mode,str(out/'request.json')],env=env,capture_output=True,text=True)
  assert r.returncode!=0 and 'no settled state' in r.stderr,(mode,r)
  assert destination.read_bytes()==before
  rejections.append({'mode':mode,'exit':r.returncode,'error':r.stderr.strip(),'old_output_unchanged':True})
 observer=subprocess.Popen([str(root/'services/v02-lab/target/debug/observe-v02'),manifest,str(out/'observer.json'),'2000'],env=env,stdout=open(out/'observer.log','w'),stderr=subprocess.STDOUT)
 good=wait_snapshot(lambda v:v.get('refresh_succeeded') is True)
 stop()
 bad=wait_snapshot(lambda v:v.get('consecutive_failures',0)>0)
 assert bad['snapshot_is_current_at_check'] is False and bad['snapshot']['pinned_hash']==good['snapshot']['pinned_hash']
 start()
 resumed=wait_snapshot(lambda v:v.get('refresh_succeeded') is True and v.get('last_success_unix_ms',0)>bad['checked_at_unix_ms'])
 assert resumed['consecutive_failures']==0 and resumed['snapshot']['pinned_hash']==good['snapshot']['pinned_hash']
 (out/'result.json').write_text(json.dumps({'schema':'tactus-v02-recovery-tool-check-v1','canonical_source_run':str(run), 'pin':report['pinned_hash'],'unsettled_claim_rejections':rejections,'observer_success':good,'observer_failure':bad,'observer_resumed':resumed,'real_settlement':False,'transactions_submitted':False,'proof_generated':False},indent=2)+'\n')
 print('canonical unsettled claims rejected; observer recovered after real node outage')
finally:
 if observer is not None:observer.terminate();observer.wait(timeout=20)
 stop()
