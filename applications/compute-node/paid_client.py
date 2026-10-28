"""Paid run-remote: fresh buyer, confirmed escrow, attested job, settlement and refund."""
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

import client as free
from client import canonical, require, request


class PaymentTool:
    def __init__(self, config, service=None):
        self.config = config.resolve()
        self.service = service
        if service:
            endpoint=urlsplit(service)
            require(endpoint.scheme=='http' and endpoint.hostname=='127.0.0.1', 'payment service must use SSH-forwarded loopback')

    def run(self, command, path, *args):
        if self.service:
            payload={'command':command,'stateId':hashlib.sha256(str(path.resolve()).encode()).hexdigest()}
            if command in ('inspect','check-grant'):
                payload['value']=json.loads(path.read_bytes())
            elif command=='buy':
                payload.update(node=json.loads(Path(args[1]).read_bytes()),buyerKey=args[2],amount=str(args[3]))
            elif command=='confirm':
                pass
            elif command=='finish':
                payload['value']=json.loads(Path(args[1]).read_bytes())
            else:
                raise ValueError('unsupported remote payment command')
            req=Request(self.service,data=canonical(payload),headers={'Content-Type':'application/json'})
            with urlopen(req,timeout=3700) as response:
                return json.load(response)
        raw = subprocess.check_output(['deno', 'run', '--allow-read', '--allow-write', '--allow-net', '--allow-env',
                                      str(free.ROOT/'applications/payments/client.mjs'), command, str(self.config), str(path),
                                      *map(str, args)])
        return json.loads(raw)


class PaidPolicy(free.Policy):
    def verify_registration(self, node):
        require(node['kind'] == 'compute' and node['cdhash'] == self.cdhash, 'node build is not approved')
        require(node['manifest_sha256'] == self.measurement and node['os_image_hash'] == self.image, 'node measurements')
        require(node['relay_maddr'].endswith('/p2p-circuit/p2p/' + node['relay_peer']), 'node circuit target')
        require(node['payments']['grantSigner'].lower() == self.payment_config['grantSigner'].lower(), 'measured grant signer')
        checked = self.payment_tool.run('inspect', self.node_file(node))
        approval = checked['approval']; key = approval['key']
        require(approval['category'] == 3 and approval['rpIdHash'] == hashlib.sha256(free.APP_ID.encode()).hexdigest(), 'approved registry build')
        require(not approval['burnedBuild'] and not approval['burnedImage'], 'burned build/image')
        require(key['enrolled'] and key['expires'] >= time.time(), 'live Apple enrollment')
        registered = bytes(key['x']) + bytes(key['y'])
        require(registered == free.unb64(self.key)[1:], 'on-chain enrolled Apple key')
        require(node['payments']['enrollmentKeyId'][2:] == free.unb64(self.kid).hex(), 'payment enrollment key')
        peer = free.peer_bytes(node['relay_peer'])
        legacy = hashlib.sha256(b'dsmack-compute-node/1' + peer + bytes.fromhex(node['secret_key']) + bytes.fromhex(node['receipt_key'])).digest() + bytes(32)
        rd = bytes.fromhex(checked['binding'][2:]) + hashlib.sha256(legacy + bytes.fromhex(node['payments']['challenge'])).digest()
        proof = node['proof'] if 'proof' in node else node['attestation']
        return self.verify(proof, rd, key['counter'])

    def node_file(self, node):
        self.payment_node_path.write_bytes(canonical(node))
        return self.payment_node_path


class PaidClient(free.Client):
    def discover(self, peer=None):
        deadline=time.monotonic()+90
        while True:
            nodes = request(self.broker + '/payments/nodes')
            candidates = [n for n in nodes if n['kind'] == 'compute' and n['manifest_sha256'] == self.policy.measurement and (peer is None or n['relay_peer'] == peer)]
            if candidates:
                break
            require(time.monotonic()<deadline, 'launched compute node did not become ready')
            time.sleep(1)
        node = candidates[0]
        self.policy.verify_registration(node)
        challenge = secrets.token_hex(32)
        direct = json.loads(subprocess.check_output([str(self.binary), 'paid-discover', node['relay_maddr'], str(self.key)],
                                                   input=canonical({'challenge': challenge}), timeout=45))
        require(direct['payments']['challenge'] == challenge, 'fresh buyer challenge')
        for field in ('relay_peer', 'relay_maddr', 'secret_key', 'receipt_key', 'manifest_sha256', 'os_image_hash', 'cdhash'):
            require(direct[field] == node[field], 'paid node changed ' + field)
        for field in ('node', 'runId', 'escrow', 'receiptSigner', 'runNonce', 'enrollmentKeyId', 'operator', 'runExpires', 'buildId'):
            require(direct['payments'][field] == node['payments'][field], 'paid run changed ' + field)
        self.policy.verify_registration(direct)
        return direct

    def grant_id(self, grant):
        return grant['grant']['purchaseId']

    def grant_seconds(self, grant):
        return int(grant['grant']['amount'])

    def check_grant(self, node, grant):
        path = self.state_dir/'paid-grant.json'; path.write_bytes(canonical(grant))
        g = self.tool.run('check-grant', path)
        require(g['node'] == node['payments']['node'] and g['runId']==node['payments']['runId'] and g['buyerKey'] == '0x' + free.peer_bytes(self.peer)[6:].hex(), 'paid grant node/buyer')
        require(g['purchaseId'] == self.purchase['purchaseId'] and g['amount'] == str(self.purchased_seconds) and g['unit'] == 1, 'paid grant allowance')
        require(g['issuedAt'] <= time.time() < g['serviceUntil'] <= min(g['issuedAt'] + 600, node['payments']['runExpires']), 'paid grant expiry')
        require(g['destinationPolicyHash'] == self.policy.payment_config['destinationPolicyHash'], 'paid destination policy')
        b=grant['nodeBinding']['binding']
        require(b['node']==g['node'] and b['runId']==g['runId'] and b['receiptSigner'].lower()==node['payments']['receiptSigner'].lower(), 'run receipt binding')
        require(b['operator'].lower()==node['payments']['operator'].lower() and b['composeHash']=='0x'+node['manifest_sha256'] and b['imageHash']=='0x'+node['os_image_hash'], 'run class binding')
        require(g['serviceUntil']<=b['expires'], 'binding expiry')
        return g

    def grant(self, node, seconds):
        self.purchased_seconds = seconds
        fields = dict(client_peer=self.peer, purchaseId=self.purchase['purchaseId'], txHash=self.purchase['txHash'], runId=node['payments']['runId'])
        signed = json.loads(subprocess.check_output([str(self.binary), 'sign', str(self.key)], input=canonical(fields)))
        grant=request(self.broker+'/payments/grant',signed)
        self.check_grant(node,grant)
        self.grant_envelope=grant
        return grant

    def confirm_at_broker(self):
        fields=dict(client_peer=self.peer,purchaseId=self.purchase['purchaseId'],txHash=self.purchase['txHash'])
        signed=json.loads(subprocess.check_output([str(self.binary),'sign',str(self.key)],input=canonical(fields)))
        deadline=time.monotonic()+3600
        while True:
            try:
                return request(self.broker+'/payments/confirm',signed)
            except HTTPError as e:
                error=json.loads(e.read(4096)).get('error','')
                waiting=any(t in error for t in ('not finalized','RPC quorum','finalized RPC quorum','stale/future finalized head'))
                if e.code!=403 or not waiting or time.monotonic()>=deadline:
                    raise
                print('waiting for broker finalized purchase confirmation: '+error,file=sys.stderr)
                time.sleep(10)

    def on_receipt(self, result, out):
        require('payment_receipt' in result, 'guest returned no paid usage receipt')
        envelope={**result['payment_receipt'], 'nodeBinding':self.grant_envelope['nodeBinding']}
        path = out/'payment-receipt.json'; path.write_bytes(canonical(envelope))
        request(self.broker + '/payments/receipts', envelope)


def run_paid(args):
    require(args.send_payments and (args.funding_key is not None or args.payment_service), 'paid run requires a funding key or loopback payment service and --send-payments')
    if args.resume_payment or args.finish_only:
        require(args.out.is_dir(), 'prepared payment output missing')
    else:
        require(not args.out.exists(), 'paid output directory must be new')
        args.out.mkdir(parents=True, mode=0o700)
    state = args.out/'payment-state'; state.mkdir(mode=0o700,exist_ok=True)
    tool = PaymentTool(args.payments_config,args.payment_service)
    funding=args.funding_key.resolve() if args.funding_key else None
    def finish():
        summary=tool.run('finish',state/'buyer.json',funding,args.out/'job/payment-receipt.json','--send')
        (args.out/'job/payments.json').write_bytes(canonical(summary))
        print(json.dumps(summary,indent=2)); return summary
    if args.finish_only:
        return finish()
    selected = PaidPolicy(args.manifest.read_bytes(), args.enrollment, args.cdhash, args.rpc, args.attest, args.canary, args.model)
    selected.payment_tool = tool
    selected.payment_config = json.loads(args.payments_config.read_bytes())
    selected.payment_node_path = state/'node.json'
    env = selected.service['environment']
    measured = json.loads(env['PAYMENTS_CONFIG'])
    require(measured['grantSigner'].lower() == selected.payment_config['grantSigner'].lower(), 'compose grant signer')
    require(measured['destinationPolicyHash'] == selected.payment_config['destinationPolicyHash'], 'compose destination policy')
    c = PaidClient(args.binary, state/'buyer-libp2p.key', args.broker, args.broker_key, selected)
    c.tool, c.state_dir, c.state_path, c.funding = tool, state, state/'buyer.json', funding
    prepared=state/'purchase.json'
    if not args.resume_payment:
        target=state/'class.json'; target.write_bytes(canonical({'node':measured['node']}))
        purchase=tool.run('buy',c.state_path,funding,target,'0x'+free.peer_bytes(c.peer)[6:].hex(),args.seconds,'--send')
        prepared.write_bytes(canonical(purchase))
        purchase=tool.run('confirm',c.state_path)
        purchase['amount']=str(args.seconds); prepared.write_bytes(canonical(purchase))
    c.purchase=json.loads(prepared.read_bytes())
    if 'amount' not in c.purchase:
        c.purchase=tool.run('confirm',c.state_path)
        c.purchase['amount']=str(args.seconds); prepared.write_bytes(canonical(c.purchase))
    require(c.purchase['amount']==str(args.seconds), 'prepared amount changed')
    if not c.purchase.get('brokerConfirmation'):
        c.purchase['brokerConfirmation']=c.confirm_at_broker()
        prepared.write_bytes(canonical(c.purchase))
    if args.prepare_only:
        return c.purchase
    if not args.defer_settlement:
        require(args.launch_node and args.stop_node,'paid loop requires launch/stop commands, or operator-managed --defer-settlement')
    if args.launch_node:
        subprocess.run(shlex.split(args.launch_node),check=True)
    error=None; turn=None
    try:
        turn=c.run(args.repo.resolve(), args.prompt, args.credential, args.out/'job', args.seconds, args.node_peer)
    except Exception as exc:
        error=exc
    finally:
        if args.stop_node:
            # This command returns only after the VM exits. Finality waits follow it.
            subprocess.run(shlex.split(args.stop_node),check=True)
    if not args.defer_settlement and (args.out/'job/payment-receipt.json').exists():
        finish()
    if error:
        raise error
    return turn
