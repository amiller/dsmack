#!/usr/bin/env python3
"""Check the deployed UI with a fresh operator allowance; preserve paid profiles."""
import argparse
import base64
import json
from pathlib import Path
import time
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='https://pod.dstack.soc1024.com/private-agent/')
parser.add_argument('--policy', type=Path)
parser.add_argument('--repo', type=Path)
parser.add_argument('--prompt', default='Change greet.txt to say Hello from the private agent. Make the smallest edit.')
parser.add_argument('--seconds', type=int, default=60)
parser.add_argument('--out', type=Path, default=Path('/evidence'))
parser.add_argument('--inspect-credit-profile', type=Path)
parser.add_argument('--grant-wait', type=int, default=180)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
if not args.inspect_credit_profile and (not args.policy or not args.repo):
    parser.error('diagnostic execution requires --policy and --repo')
report = {'url': args.url, 'mode': 'paid-credit-inspection' if args.inspect_credit_profile else 'operator-diagnostic',
          'paid_credit_consumed': False, 'requests': [], 'errors': []}

with sync_playwright() as runtime:
    browser = None
    if args.inspect_credit_profile:
        context = runtime.chromium.launch_persistent_context(str(args.inspect_credit_profile), headless=True,
                    args=['--no-sandbox'], viewport={'width': 1440, 'height': 1100})
    else:
        browser = runtime.chromium.launch(headless=True, args=['--no-sandbox'])
        context = browser.new_context(viewport={'width': 1440, 'height': 1100}, record_video_dir=str(args.out/'video'))
    page = context.pages[0] if context.pages else context.new_page()

    def boundary(route):
        request = route.request
        if request.method == 'POST':
            try:
                body = request.post_data_json
            except Exception:
                body = None
            values = body if isinstance(body, list) else [body]
            if any(isinstance(item, dict) and item.get('method', '').startswith(('eth_send', 'eth_sign', 'personal_sign', 'wallet_')) for item in values):
                report['errors'].append('unexpected wallet transaction/signature request refused')
                route.abort()
                return
            if args.inspect_credit_profile and '/relay-broker/' in urlsplit(request.url).path:
                report['errors'].append('unexpected broker POST during credit inspection refused')
                route.abort()
                return
        route.continue_()
    context.route('**/*', boundary)
    page.on('pageerror', lambda error: report['errors'].append(str(error)))

    def record(request):
        path = urlsplit(request.url).path
        if '/relay-broker/' in path:
            item = {'method': request.method, 'path': path}
            if request.method == 'POST' and path.endswith(('/sandbox/jobs', '/sandbox/capability')):
                item['body'] = request.post_data
            report['requests'].append(item)
    page.on('request', record)
    try:
        page.goto(args.url, wait_until='domcontentloaded')
        page.wait_for_function('document.documentElement.dataset.ready === "true"')
        page.wait_for_function('document.querySelector("#service").textContent.includes("Broker connected")')
        if args.inspect_credit_profile:
            report.update(status='passed', credit=page.locator('#purchases').inner_text())
            page.screenshot(path=str(args.out/'credit-preserved.png'), full_page=True)
        else:
            policy = json.loads(args.policy.read_text())
            page.locator('#policy').set_input_files(str(args.policy))
            page.wait_for_function('document.querySelector("#node-status").textContent.includes("Trusted policy loaded")')
            page.locator('#discover').click()
            page.wait_for_function('!document.querySelector("#discover").disabled')
            if not page.locator('#node-status').inner_text().startswith('Node verified'):
                raise RuntimeError(page.locator('#alert').inner_text())
            page.locator('#repo').set_input_files(str(args.repo))
            page.locator('#job-prompt').fill(args.prompt)
            request = page.evaluate('''async ({raw,prompt,repo,seconds}) => {
              const m=await import(new URL('sandbox-client.js',location.href).href);
              const config=await(await fetch('./config.json',{cache:'no-store'})).json();
              const client=await new Promise((resolve,reject)=>{const open=indexedDB.open('dsmack-private-agent',1);open.onerror=()=>reject(open.error);open.onsuccess=()=>{const db=open.result,tx=db.transaction('wallet','readonly'),get=tx.objectStore('wallet').get('client');get.onsuccess=()=>resolve(get.result);get.onerror=()=>reject(get.error);tx.oncomplete=()=>db.close();};});
              const registration=JSON.parse(document.querySelector('#node-evidence').textContent);
              const policy={...raw,manifest:m.unhex(raw.manifest),enrollment:{...raw.enrollment,attestation:m.unhex(raw.enrollment.attestation),clientData:m.unhex(raw.enrollment.clientData)},...(registration.payments?{challenge:registration.payments.challenge}:{})};
              const node=await m.verifyNode(registration,policy),jobId=m.hex(crypto.getRandomValues(new Uint8Array(16)));
              if(node.policy.provider?.schema!=='dsmack-broker-model/1')throw Error('diagnostic node must use the measured broker TEE provider');
              const banner=document.createElement('p');banner.id='operator-diagnostic';banner.textContent='Operator diagnostic allowance. Existing paid credit is unchanged. NEAR TEE model via broker CVM; broker handles plaintext.';document.querySelector('.sandbox').prepend(banner);
              window.sandboxDiagnostic={m,config,client,node,jobId,prompt,repo};
              return {client_peer:client.peer,node_peer:registration.relay_peer,amount:seconds,job_id:jobId};
            }''', {'raw': policy, 'prompt': args.prompt, 'repo': base64.b64encode(args.repo.read_bytes()).decode(), 'seconds': args.seconds})
            temporary = args.out/'operator-grant-request.tmp'
            temporary.write_text(json.dumps(request)+'\n')
            temporary.rename(args.out/'operator-grant-request.json')
            page.screenshot(path=str(args.out/'node-verified.png'), full_page=True)
            deadline = time.monotonic()+args.grant_wait
            grant_path = args.out/'grant.json'
            while not grant_path.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError('operator allowance was not delivered')
                time.sleep(1)
            grant = json.loads(grant_path.read_text())
            result = page.evaluate('''async grant => {
              const d=window.sandboxDiagnostic,{m,node,client,jobId}=d;
              const credential=await m.requestCapability(d.config.broker,{node,client,grant,jobId});
              const repoTar=Uint8Array.from(atob(d.repo),c=>c.charCodeAt(0));
              const job=await m.sealJob(node,{grant,jobId,credential,repoTar,prompt:d.prompt,client});
              document.querySelector('#job-status').textContent='Operator diagnostic: sealed job submitted; verifying the TEE result…';
              const result=await m.receive(await m.submitJob(d.config.broker,job)),outputs=await m.openOutputs(job,result),text=new TextDecoder();
              document.querySelector('#diff').textContent=text.decode(outputs.patch);
              document.querySelector('#transcript').textContent=text.decode(outputs.transcript);
              document.querySelector('#job-evidence').textContent=JSON.stringify({statement:result.statement,attestation:result.attestation,receipt:result.receipt},null,2);
              document.querySelector('#job-status').textContent='Operator diagnostic passed: node/job assertions, receipt, signed provider evidence and output hashes verified. Existing paid credit unchanged.';
              return {sealed:job.sealed,result,outputs:Object.fromEntries(Object.entries(outputs).map(([name,raw])=>[name,text.decode(raw)])),model:node.policy.model,enrollmentMode:node.enrollmentMode,privacy:m.INFERENCE_PRIVACY};
            }''', grant)
            for name in ['patch', 'transcript', 'verdict']:
                (args.out/name).write_text(result['outputs'][name])
            for name, value in [('sealed-input', result['sealed']), ('result', result['result'])]:
                (args.out/(name+'.json')).write_text(json.dumps(value)+'\n')
            report.update(status='passed', seconds_used=result['result']['statement']['seconds_used'],
                          model=result['model'], enrollmentMode=result['enrollmentMode'], privacy=result['privacy'])
            page.screenshot(path=str(args.out/'sandbox-complete.png'), full_page=True)
        if report['errors']:
            raise RuntimeError('browser or network boundary errors occurred')
    except Exception as error:
        report.update(status='failed', error=str(error))
        page.screenshot(path=str(args.out/'failure.png'), full_page=True)
        raise
    finally:
        (args.out/'live-browser.json').write_text(json.dumps(report, indent=2)+'\n')
        context.close()
        if browser:
            browser.close()
print(json.dumps({k:v for k,v in report.items() if k!='requests'}))
