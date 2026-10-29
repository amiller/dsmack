#!/usr/bin/env python3
"""Two-stage Playwright sandbox journey; the recorder receives encrypted credentials only."""
import argparse
import json
from pathlib import Path
import time
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--url',default='http://127.0.0.1:18481')
p.add_argument('--config',default='/harness/public/config.json')
p.add_argument('--out',type=Path,default=Path('/evidence'))
p.add_argument('--credential-wait',type=int,default=300)
args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True)
errors=[];network=[]
try:
  with sync_playwright() as driver:
      browser=driver.chromium.launch(headless=True,args=['--no-sandbox'])
      context=browser.new_context(viewport={'width':1280,'height':900},record_video_dir=str(args.out/'video'))
      page=context.new_page();errors=[];network=[]
      page.on('pageerror',lambda error:errors.append(str(error)))
      def record(request):
          item={'method':request.method,'url':request.url,'resource':request.resource_type}
          path=urlsplit(request.url).path
          if request.method=='POST' and (path=='/rpc' or path.endswith('/grant') or path.endswith('/sandbox/jobs')):
              item.update(body=request.post_data,headers=request.headers)
          network.append(item)
      page.on('request',record)
      page.goto(args.url,wait_until='domcontentloaded')
      page.set_content('<title>Browser sandbox journey</title><style>body{background:#10202e;color:#e7f0f4;font:20px system-ui;padding:48px}pre{white-space:pre-wrap;font:16px monospace;background:#1a3142;padding:24px;border-radius:12px}</style><h1>Attested browser sandbox</h1><pre id="progress"></pre><pre id="patch"></pre>')
      page.evaluate('window.progress = text => document.querySelector("#progress").textContent += text + "\\n"')
      request=page.evaluate('''async configUrl => {
        const m=await import('/applications/compute-node/browser/sandbox.mjs');
        const config=await (await fetch(configUrl)).json(),p=config.policy;
        const bytes=async url=>new Uint8Array(await(await fetch(url)).arrayBuffer());
        const policy={...p,manifest:await bytes(p.manifestUrl),enrollment:{attestation:await bytes(p.enrollmentUrl),clientData:await bytes(p.clientDataUrl),keyId:(await(await fetch(p.keyIdUrl)).text()).trim()}};
        const broker=config.broker.replace(/\\/$/,''),client=await m.createClient(),jobId=m.hex(crypto.getRandomValues(new Uint8Array(16)));
        progress('Browser Ed25519 identity generated; fresh P-256 output key will stay in memory.');
        const awaitHash=m.hex(new Uint8Array(await crypto.subtle.digest('SHA-256',policy.manifest)));
        const discovery=await m.jsonRequest(broker+'/nodes');
        const candidate=discovery.find(n=>n.kind==='compute'&&n.manifest_sha256===awaitHash);
        if(!candidate)throw Error('no matching warm compute node');
        const challenge=m.hex(crypto.getRandomValues(new Uint8Array(32)));
        const live=await m.jsonRequest(broker+'/sandbox/nodes/'+encodeURIComponent(candidate.relay_peer)+'/attestation'+(candidate.payments?'?challenge='+challenge:''));
        if(live.payments)policy.challenge=challenge;
        const node=await m.verifyNode(live,policy);
        progress('Verified live Apple assertion, enrolled key, approved registry build, compose/image and node keys.');
        progress('Enrollment mode: '+node.enrollmentMode+'; run '+node.run);
        if(live.payments)throw Error('this no-transaction harness requires a pre-confirmed paid grant adapter or a local free-grant broker');
        const fields={client_peer:client.peer,relay_peer:live.relay_peer,unit:'seconds',amount:config.seconds??180,nonce:m.hex(crypto.getRandomValues(new Uint8Array(16)))};
        const grant=await m.jsonRequest(broker+'/grant',await m.signBrokerRequest(client,fields));
        progress('Broker signed compute allowance verified before sealing.');
        window.sandboxJourney={m,config,node,client,jobId,grant,repoTar:await bytes(config.repoTarUrl)};
        return {jobId,node:live,grant,clientPeer:client.peer,enrollmentMode:node.enrollmentMode};
      }''',args.config)
      (args.out/'credential-request.json').write_text(json.dumps(request,indent=2)+'\n')
      page.screenshot(path=str(args.out/'node-verified.png'),full_page=True)
      deadline=time.monotonic()+args.credential_wait
      while True:
          ready=page.evaluate('''async()=>{const r=await fetch(window.sandboxJourney.config.credentialUrl,{cache:'no-store'});if(r.status===404)return false;if(!r.ok)throw Error('credential envelope HTTP '+r.status);window.sandboxCredential=await r.json();return true;}''')
          if ready:break
          if time.monotonic()>deadline:raise TimeoutError('encrypted credential envelope did not arrive')
          time.sleep(1)
      result=page.evaluate('''async()=>{
        const {m,config,node,client,jobId,grant,repoTar}=window.sandboxJourney;
        progress('Received node-sealed delegated credential; sealing repository and prompt in browser.');
        const job=await m.sealJob(node,{client,grant,jobId,credential:window.sandboxCredential,repoTar,prompt:config.prompt});
        delete window.sandboxCredential;
        progress('Signed encrypted bundle and grant hashes; forwarding through broker/libp2p.');
        const result=await m.receive(await m.submitJob(config.broker,job));
        const receipt=await m.verifyReceipt(node,result,job),outputs=await m.openOutputs(job,result),text=new TextDecoder();
        progress('Verified per-job Apple assertion, signed receipt, all decrypted output hashes.');
        document.querySelector('#patch').textContent=text.decode(outputs.patch);
        progress('PASS — '+result.statement.seconds_used+' sandbox seconds; broker received ciphertext.');
        return {sealed:job.sealed,result,receipt,outputs:Object.fromEntries(Object.entries(outputs).map(([name,raw])=>[name,text.decode(raw)])),enrollmentMode:node.enrollmentMode,run:node.run};
      }''')
      for name in ['patch','transcript','verdict']:(args.out/name).write_text(result['outputs'][name])
      (args.out/'sealed-input.json').write_text(json.dumps(result['sealed'])+'\n')
      (args.out/'result.json').write_text(json.dumps(result['result'])+'\n')
      markers=page.evaluate('window.sandboxJourney.config.markers ?? []')
      forwarding='\n'.join(json.dumps(item) for item in network if urlsplit(item['url']).path.endswith('/sandbox/jobs'))
      marker_hits=[marker for marker in markers if marker in forwarding]
      if marker_hits:raise AssertionError('private marker appeared in broker network request')
      summary={key:result[key] for key in ['receipt','enrollmentMode','run']};summary.update(status='passed',errors=errors,network_markers={'tested':len(markers),'hits':len(marker_hits)})
      (args.out/'browser-e2e.json').write_text(json.dumps(summary,indent=2)+'\n')
      (args.out/'network.json').write_text(json.dumps(network,indent=2)+'\n')
      page.screenshot(path=str(args.out/'job-complete.png'),full_page=True)
      context.close();browser.close()
      print(json.dumps(summary))
finally:
    (args.out/'network.json').write_text(json.dumps(network,indent=2)+'\n')
    (args.out/'browser-errors.json').write_text(json.dumps(errors,indent=2)+'\n')
