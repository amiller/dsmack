"""Paid run-remote: fresh buyer, confirmed escrow, attested job, settlement and refund."""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
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
        nodes = request(self.broker + '/payments/nodes')
        candidates = [n for n in nodes if n['kind'] == 'compute' and n['manifest_sha256'] == self.policy.measurement and (peer is None or n['relay_peer'] == peer)]
        require(candidates, 'no paid compute node with approved compose')
        node = candidates[0]
        self.policy.verify_registration(node)
        challenge = secrets.token_hex(32)
        direct = json.loads(subprocess.check_output([str(self.binary), 'paid-discover', node['relay_maddr'], str(self.key)],
                                                   input=canonical({'challenge': challenge}), timeout=45))
        require(direct['payments']['challenge'] == challenge, 'fresh buyer challenge')
        for field in ('relay_peer', 'relay_maddr', 'secret_key', 'receipt_key', 'manifest_sha256', 'os_image_hash', 'cdhash'):
            require(direct[field] == node[field], 'paid node changed ' + field)
        for field in ('node', 'escrow', 'receiptSigner', 'runNonce', 'enrollmentKeyId', 'operator', 'runExpires', 'buildId'):
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
        require(g['node'] == node['payments']['node'] and g['buyerKey'] == '0x' + free.peer_bytes(self.peer)[6:].hex(), 'paid grant node/buyer')
        require(g['purchaseId'] == self.purchase['purchaseId'] and g['amount'] == str(self.purchased_seconds) and g['unit'] == 1, 'paid grant allowance')
        require(g['issuedAt'] <= time.time() < g['serviceUntil'] <= min(g['issuedAt'] + 600, node['payments']['runExpires']), 'paid grant expiry')
        require(g['destinationPolicyHash'] == self.policy.payment_config['destinationPolicyHash'], 'paid destination policy')
        return g

    def grant(self, node, seconds):
        self.purchased_seconds = seconds
        path = self.policy.node_file(node)
        self.purchase = self.tool.run('buy', self.state_path, self.funding, path,
                                     '0x' + free.peer_bytes(self.peer)[6:].hex(), seconds, '--send')
        fields = dict(client_peer=self.peer, purchaseId=self.purchase['purchaseId'], txHash=self.purchase['txHash'])
        signed = json.loads(subprocess.check_output([str(self.binary), 'sign', str(self.key)], input=canonical(fields)))
        deadline = time.monotonic() + 3600
        while True:
            try:
                grant = request(self.broker + '/payments/grant', signed)
                self.check_grant(node, grant)
                return grant
            except HTTPError as e:
                error = json.loads(e.read(4096)).get('error', '')
                # Only finality is retried. Invalid terms/signatures fail immediately.
                if e.code != 403 or 'not finalized' not in error or time.monotonic() >= deadline:
                    raise
                time.sleep(10)

    def on_receipt(self, result, out):
        require('payment_receipt' in result, 'guest returned no paid usage receipt')
        path = out/'payment-receipt.json'; path.write_bytes(canonical(result['payment_receipt']))
        summary = self.tool.run('finish', self.state_path, self.funding, path, '--send')
        (out/'payments.json').write_bytes(canonical(summary))
        print(json.dumps(summary, indent=2))
        request(self.broker + '/payments/receipts', result['payment_receipt'])


def run_paid(args):
    require(args.send_payments and (args.funding_key is not None or args.payment_service), 'paid run requires a funding key or loopback payment service and --send-payments')
    require(not args.out.exists(), 'paid output directory must be new')
    args.out.mkdir(parents=True, mode=0o700)
    state = args.out/'payment-state'; state.mkdir(mode=0o700)
    tool = PaymentTool(args.payments_config,args.payment_service)
    selected = PaidPolicy(args.manifest.read_bytes(), args.enrollment, args.cdhash, args.rpc, args.attest, args.canary, args.model)
    selected.payment_tool = tool
    selected.payment_config = json.loads(args.payments_config.read_bytes())
    selected.payment_node_path = state/'node.json'
    env = selected.service['environment']
    measured = json.loads(env['PAYMENTS_CONFIG'])
    require(measured['grantSigner'].lower() == selected.payment_config['grantSigner'].lower(), 'compose grant signer')
    require(measured['destinationPolicyHash'] == selected.payment_config['destinationPolicyHash'], 'compose destination policy')
    c = PaidClient(args.binary, state/'buyer-libp2p.key', args.broker, args.broker_key, selected)
    c.tool, c.state_dir, c.state_path, c.funding = tool, state, state/'buyer.json', args.funding_key.resolve() if args.funding_key else None
    # Client.run creates the public result directory itself.
    return c.run(args.repo.resolve(), args.prompt, args.credential, args.out/'job', args.seconds, args.node_peer)
