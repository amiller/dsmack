#!/usr/bin/env python3
import json
import os
from datetime import timezone
from cryptography import x509
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT/'app-attest/contracts/fixtures/local-data/mutations'
cases = json.loads((DATA/'manifest.json').read_text())['cases']
solidity = json.loads((DATA/'solidity.json').read_text())
circuit = json.loads((DATA/'circuit.json').read_text())
leaf = [c for c in cases if c['stage']=='leaf']
assert set(solidity)=={c['id'] for c in cases}
assert set(circuit)=={c['id'] for c in leaf}
assert all(v['verdict']!='ERROR' for v in circuit.values()), 'Infrastructure failure; inspect local logs'
expected = json.loads((ROOT/'app-attest/corpus/expected-circuit.json').read_text())
assert set(expected) == set(circuit), 'Circuit expectation cases changed'
for ident, want in expected.items():
    got = circuit[ident]
    actual = got['site'] if got['verdict']=='REJECT' and got['phase']=='witness' else got['phase'] if got['verdict']=='REJECT' else got['verdict']
    assert actual == want, (ident, want, actual)
covered = {}
for ident, verdict in solidity.items():
    if verdict['verdict']=='REJECT': covered.setdefault(verdict['reason'],[]).append(ident)
unexpected = [c['id'] for c in cases if (c['covers'] and (solidity[c['id']]['verdict']!='REJECT' or solidity[c['id']]['reason'] not in c['covers'])) or (not c['covers'] and solidity[c['id']]['verdict']!='ACCEPT')]
differences = [c['id'] for c in leaf if solidity[c['id']]['verdict']!=circuit[c['id']]['verdict']]
lines = ['# App Attest rule-coverage corpus', '',
    'Machine **zed**, Intel Xeon E-2276G.',
    'Source fixtures: local Mac `real-apple.json`, `iphone-apple.json`, `apple-intermediate.der`.',
    'Generated fixtures, synthetic root coordinates, Solidity root-key library and raw logs stay in',
    'ignored `app-attest/contracts/fixtures/local-data/mutations/`. No uploads, pushes or transactions.', '',
    '## Reproduction', '', 'From the checkout root:', '', '```sh', '. app-attest/circuit/env.sh',
    'python3 app-attest/corpus/generate.py', 'python3 app-attest/corpus/run.py solidity',
    'python3 app-attest/corpus/run.py circuit', 'python3 app-attest/corpus/report.py', '```', '',
    f"Foundry 1.8.5, solc 0.8.21 (`{os.environ['SOLC']}`), optimizer 200/via IR;",
    'nargo beta.17. Solidity command: `FOUNDRY_TEST=../corpus/test forge test --offline --use <solc> --gas-limit 6000000000 -vv`',
    'from `app-attest/contracts`. The large local limit batches independent cases; no transaction gas claim is made.',
    'Circuit command per leaf case: `app-attest/circuit/check-leaf.sh <generated-fixture.json>`.', '',
    f'Observed: **{len(cases)} Solidity verdicts**, **{len(circuit)} leaf-circuit verdicts**,',
    f'**{len(cases)-len(leaf)} endorsement-only cases**, **{len(differences)} raw verdict differences** (4 time-window cases + 12 public-binding probes).', '',
    '## Scope', '',
    'The harness endorses each synthetic intermediate through production `AppleEndorsements` with a',
    'test subclass overriding only the pinned root. Real chains use the production Apple root.',
    'Leaf cases invoke production `AppleAttest.enroll`; the test admission hook accepts all RP/CDHash',
    'pairs. Policy fields remain pinned to the source profile. Intermediate cases stop after endorsement.',
    'Duplicate and same-subject rotation cases exercise registry state. Expiry cases endorse while valid,',
    'then warp before enrollment. Wrong-key cases corrupt one stored coordinate limb with `vm.store`;',
    'they test a mismatched registry key, not a root-authorized way to change it. Circuit inputs alter',
    'that same public limb while retaining the correct private intermediate coordinates.', '',
    'All leaf fixtures carry 24 explicit public fields and private intermediate coordinates.',
    'Preparation bypasses DER/CBOR extraction for these explicit inputs. Oversize arrays are rejected',
    'by preparation because they cannot be represented in the circuit ABI; those are distinguished below.',
    'The obsolete full-circuit runner/test-root mode and wait script were removed.', '',
    '## Verdicts', '', '| Case id | Rule | Solidity verdict / reason | Circuit verdict | Agree? |',
    '|---|---|---|---|---|']
for case in cases:
    ident=case['id'];s=solidity[ident];c=circuit.get(ident)
    sv=s['verdict']+(' / '+s['reason'] if s['reason'] else '')
    cv=c['verdict']+' / '+c['phase'] if c else 'n/a'
    agree=('yes' if s['verdict']==c['verdict'] else '**NO**') if c else 'n/a'
    lines.append(f"| `{ident}` | {case['description']} | {sv} | {cv} | {agree} |")
lines += ['', '## Findings', '', f'Unexpected Solidity verdict/reason cases: {len(unexpected)}.', '']
for ident in unexpected: lines.append(f'- `{ident}`: expected {next(c for c in cases if c["id"]==ident)["covers"] or "acceptance"}; observed {solidity[ident]}.')
for ident in differences:
    f=json.loads((DATA/(ident+'.json')).read_text())
    ca=x509.load_der_x509_certificate(bytes.fromhex(f['intermediate'].removeprefix('0x')))
    ca_window=[int(t.replace(tzinfo=timezone.utc).timestamp()) for t in [ca.not_valid_before,ca.not_valid_after]]
    lines.append(f"- `{ident}`: Solidity {solidity[ident]['verdict']} ({solidity[ident]['reason'] or 'success'}); circuit {circuit[ident]['verdict']} ({circuit[ident]['phase']}). Block time `{f['timestamp']}`, supplied leaf window `{f['public_inputs'][10:12]}`, endorsed window `{ca_window}` (Unix seconds).")
lines += ['', 'Public-binding probes intentionally compare a supplied circuit vector against native derived values;',
    'these 12 expected rejections are separate from the four time-window disagreements.']
if not differences: lines.append('No observed disagreement. This finite corpus does not establish equivalence for all inputs.')
lines += ['', 'The circuit publishes leaf validity but has no block-time or endorsement-window input.',
    '`future`/`expired` and `endorsement-future`/`endorsement-expired` therefore may accept in the raw',
    'circuit while enrollment rejects. This is the caller/circuit boundary, not an authorized enrollment.',
    'The two endorsement-window timestamps are also outside the leaf window; Solidity reaches the',
    'intermediate guard first. No production validator was changed to align verdicts.', '', '## Solidity require coverage', '',
    'Each row is a source require/revert site. Shared reasons map to observed rejecting cases; a shared',
    'message alone does not prove every subcondition or call path was exercised. Intermediate parser',
    'coverage is included because endorsement delegates policy checks there.', '',
    '| Source / reason | Observed rejecting cases |', '|---|---|']
for filename in ['AppleLeaf.sol','StrictDER.sol','AppleAuthData.sol','AppleEndorsements.sol','AppleIntermediate.sol']:
    source=(ROOT/'app-attest/contracts/src'/filename).read_text()
    for m in re.finditer(r'(?:require\([\s\S]*?,|revert\()"([^"\n]+)"\)',source):
        reason=m.group(1);n=source[:m.start()].count('\n')+1
        ids=covered.get(reason,[])
        if filename=='AppleIntermediate.sol': ids=[i for i in ids if next(c for c in cases if c['id']==i)['stage']=='endorsement']
        if filename in ('AppleLeaf.sol','AppleAuthData.sol'): ids=[i for i in ids if next(c for c in cases if c['id']==i)['stage']=='leaf']
        if filename=='AppleAuthData.sol' and reason=='CBOR truncated': ids={9:['cbor-truncated'],11:['cbor-truncated-head8'],12:['cbor-truncated-head16']}[n]
        if filename=='AppleAuthData.sol' and reason=='CBOR nonminimal': ids={11:['cbor-nonminimal-map','cbor-nonminimal-key'],12:['cbor-nonminimal-map16']}[n]
        status = 'unreachable through enrollment/endorsement (see proof below)' if (filename,reason) in [('StrictDER.sol','DER slice'),('AppleAuthData.sol','COSE truncated')] else '**uncovered**'
        lines.append(f"| `{filename}:{n}` / {reason} | "+(', '.join('`'+i+'`' for i in ids) if ids else status)+' |')
lines += ['', 'Unreachable helper guards: `StrictDER.slice` is dominated by bounded traversal;',
    '`AppleAuthData` COSE-truncated guard is dominated by the enrollment minimum length.',
    'Assertion-only authentication guards are outside this enrollment corpus. Shared-message mappings',
    'do not independently cover the intermediate parser at every structural guard.', '',
    '## Leaf circuit assert coverage', '',
    'Own-source assert sites (including leaf-callable DER/auth helpers); dependency-internal arithmetic',
    'assertions are outside this rule corpus. Mapping uses observed assertion messages in raw logs.',
    'Circuit sites use the assertion source location in the error, not only its message.', '',
    '| Source / assertion | Observed rejecting cases |', '|---|---|']
observed={}
for ident,c in circuit.items():
    if c['phase']=='witness' and c['verdict']=='REJECT':
        log=(DATA/(ident+'.circuit.log')).read_text()
        message=re.search(r'Assertion failed: ([^\n]+)',log)
        if message:
            for filename,line in re.findall(r'┌─ core/src/([^:]+):(\d+):',log):
                observed.setdefault((filename,int(line),message.group(1).strip()),[]).append(ident)
for filename in ['der.nr','certificate.nr','auth.nr','leaf_only.nr']:
    source=(ROOT/'app-attest/circuit/core/src'/filename).read_text()
    for m in re.finditer(r'assert\([\s\S]*?,\s*"([^"\n]+)"\)',source):
        message=m.group(1);n=source[:m.start()].count('\n')+1
        ids=observed.get((filename,n,message),[])
        status = 'adapter capacity guard (see below)' if (filename,n) in [('certificate.nr',22),('leaf_only.nr',24)] else 'unreachable with honest hint (see below)' if (filename,n)==('certificate.nr',73) else '**uncovered**'
        lines.append(f"| `{filename}:{n}` / {message} | "+(', '.join('`'+i+'`' for i in ids) if ids else status)+' |')
lines += ['', '## Regression validation', '',
    'Run the default and real-proof suites separately; see CONTRIBUTING.md.', '',
    '## Reachability and deliberate input differences', '',
    '`StrictDER.slice` rejection is unreachable through enrollment/endorsement: node() establishes',
    '`start <= body <= end <= limit <= cert.length`; contents/encoded preserve these bounds.',
    'The only direct slices are the SPKI points, after exact lengths 66/98 establish body+2 <= end.',
    '`AppleAuthData` COSE truncation is unreachable: its enrollment guard requires length >=164;',
    'the fixed COSE is 10+32+3+32=77 bytes, so p=87+77=164. Assertion mode skips that block.', '',
    'Circuit certificate/auth capacity guards cannot be rejected through the fixed-array adapter:',
    'prepare-leaf.py enforces leaf <=4096/auth <=1024 before witness generation.',
    'The second duplicate-OID assertion cannot fail with the honest different_byte hint:',
    'equal OIDs return length and fail the preceding bound; unequal OIDs return a differing byte.',
    'This is not a claim of coverage against a malicious unconstrained hint.', '',
    'The 12 public-binding cases alter only an explicit circuit public field. Native enrollment',
    'has no corresponding supplied field and derives the correct value; acceptance there versus',
    'circuit rejection is expected for these binding probes. The four time-window differences',
    'remain expected at the caller boundary. No production validator changed.', '']
metadata=json.loads((DATA/'circuit-run.json').read_text())
lines += ['', f"Checker base HEAD: `{metadata['revision']}`; working checker-source SHA256:",
    f"`{metadata['source_sha256']}`. Compiled tree SHA256: `{metadata['compiled_tree_sha256']}`.", '']
summary = []
for title, end in [('## Solidity require coverage','## Leaf circuit assert coverage'),('## Leaf circuit assert coverage','## Regression validation')]:
    rows = [line for line in lines[lines.index(title):lines.index(end)] if line.startswith('| `')]
    observed_count = sum(' | `' in line for line in rows)
    untargeted = sum('**uncovered**' in line for line in rows)
    summary.append(f'| {title.removeprefix("## ")} | {len(rows)} | {observed_count} | {len(rows)-observed_count-untargeted} | {untargeted} |')
lines += ['## Coverage totals', '', '| Table | Sites | Observed rejection | Unreachable or adapter/hint bound | Untargeted |', '|---|---:|---:|---:|---:|', *summary, '',
    'These are own-source guard sites, not complete condition or branch coverage.', '']
expected_differences = {'future','expired','endorsement-future','endorsement-expired'} | {'public-binding-'+str(i) for i in range(12)}
lines += [f'Unexpected verdict/reason cases: {len(unexpected)}; unexpected disagreements: {len(set(differences)^expected_differences)}.', '']
(DATA/'report.md').write_text('\n'.join(lines))
assert not unexpected, unexpected
assert set(differences) == expected_differences, differences
print('Wrote local corpus report; verdicts and expected assert sites match')
