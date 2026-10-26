"""Drive a running coordinator with recorded evidence. Stdlib only.

e2e_client.py unregistered URL SPIKE   turn 1's launch before CDRegistry admits its build
e2e_client.py turns URL TOKEN SPIKE   replay the personal-agent spike (agent-turns/testdata/personal-agent): genesis, two turns, then the replays
e2e_client.py admit URL TOKEN RELEASE_JSON PROFILE_JSON DISK_JSON OUT
    sign a re-keyed copy of a release, mint one admission, and write the files the alpha verify path reads
"""
import base64, hashlib, json, secrets, sys, urllib.error, urllib.request
from pathlib import Path

AGENT = 'personal-agent-turns-20261025'
unb64 = base64.b64decode
canonical = lambda o: json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def http(method, url, token=None, body=None):
    headers = {'content-type': 'application/json', **({'authorization': 'Bearer ' + token} if token else {})}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body and canonical(body), headers, method=method)) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def expect(got, code, check=lambda out: True):
    status, out = got
    print(status, json.dumps(out)[:200])
    assert status == code and check(out), (status, out)
    return out


def launch_request(state, turn):
    ev = json.loads((Path(state) / f'evidence-turn-{turn}.json').read_bytes())
    return {'mode': 'attested', 'client_data': ev['bootClientData'], 'key_id': ev['keyId'], 'attestation': ev['attestation']}, ev


def unregistered(url, state):
    expect(http('POST', url + '/turn/release', body=launch_request(state, 1)[0]), 403, lambda o: o['error'] == 'build_not_in_cdregistry')


def turns(url, token, spike):
    spike = Path(spike)
    blob = lambda h: base64.b64encode((spike / h).read_bytes()).decode()
    compose1 = (spike / 'compose-turn-1.json').read_bytes()
    image = json.loads(json.loads(compose1)['docker_compose_file'])['services']['turn']['image']
    calls = {n: launch_request(spike, n) for n in (1, 2)}
    moves = {n: json.loads(json.loads(unb64(ev['assertClientData']))['data']) for n, (_, ev) in calls.items()}
    head = expect(http('POST', url + '/agent', token, {'agent': AGENT, 'image': image, 'port': 19471, 'ciphertext': blob(moves[1]['state_in'])}), 200)
    assert head['compose_hash'] == hashlib.sha256(compose1).hexdigest(), 'genesis compose differs from the spike'
    for n, (rel, ev) in calls.items():
        t = moves[n]
        calls[n] = (rel, {'ciphertext': blob(t['state_out']), 'evidence': ev, **t})
        expect(http('POST', url + '/turn/release', body=rel), 200, lambda o: set(o) == {'epk', 'sealed'})
        out = expect(http('POST', url + '/turn/commit', body=calls[n][1]), 200)
        assert out['head']['head'] == t['state_out'] and out['head']['turn'] == n + 1
    stale = lambda o: o['error'].startswith('stale_head')
    expect(http('POST', url + '/turn/release', body=calls[2][0]), 403, stale)
    expect(http('POST', url + '/turn/commit', body=calls[2][1]), 403, stale)
    expect(http('POST', url + '/turn/commit', body=calls[1][1]), 403, stale)
    final = expect(http('GET', url + '/head/' + AGENT), 200)
    assert final == json.loads((spike / 'head.json').read_bytes())
    compose = expect(http('GET', url + '/compose/' + AGENT), 200)
    assert hashlib.sha256(canonical(compose)).hexdigest() == final['compose_hash']
    print('turns ok: head', final)


def admit(url, token, release, profile, disk, out):
    out = Path(out)
    out.mkdir()
    keys = expect(http('GET', url + '/keys'), 200)
    inv = dict(json.loads(Path(release).read_bytes()), key_id=keys['key_id'])
    signed = expect(http('POST', url + '/sign-release', token, {'inventory': inv}), 200)
    profile = json.loads(Path(profile).read_bytes())
    closure = {'schema': 'dsmack-result-closure-context/1', 'attempt_id': secrets.token_hex(16), 'selectors': [profile['profile_id']]}
    req = {'release_inventory_sha256': signed['inventory_sha256'], 'profile': profile, 'closure_context': closure,
           'workload_disk': json.loads(Path(disk).read_bytes())['workload_disk']}
    a = expect(http('POST', url + '/admit', token, req), 200)
    expect(http('POST', url + '/admit', token, req), 403, lambda o: o['error'] == 'attempt_already_admitted')
    expect(http('POST', url + '/admit', None, req), 401)
    (out / 'release.json').write_text(signed['inventory'])
    (out / 'release.sig').write_bytes(base64.b64decode(signed['signature']))
    (out / 'workload-admission.json').write_text(a['admission'])
    (out / 'workload.sig').write_bytes(base64.b64decode(a['signature']))
    (out / 'closure-context.json').write_bytes(canonical(closure))
    (out / 'coordinator.pem').write_text(keys['public_pem'])
    (out / 'keys.json').write_bytes(canonical(keys))
    print('admit ok:', a['admission'])


{'unregistered': unregistered, 'turns': turns, 'admit': admit}[sys.argv[1]](*sys.argv[2:])
