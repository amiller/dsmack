# Private develop profile (source candidate)

This is a separate, bounded extension of the authenticated alpha route. It does
not qualify a provider run, import credentials, fund a task or authorize payment.
Existing browser profile/2 and local task/2 stay credential-free.

The develop branch of signed `dsmack-alpha-profile/3` admits only
`bounty-board-search-develop-v1`, model label `claude-opus-4-8`, security label
`none`, and the exact compose-manifest digest in that signed profile. Resources
remain 4096MiB, one vCPU,600 seconds,4GiB scratch and256MiB result. Model/tool
budgets and provider routing must be enforced by the selected measured workload;
labels alone do not configure them. The independently reviewed application
recipe selects480 seconds,30 turns and its fixed Claude tool list. Generator selection has a separate closed branch described below.

Profile/3 adds an exact signed `private_input_policy`:

```json
{"schema":"dsmack-alpha-private-channel/1","channel":"runtime-envelope-v1","max_bytes":1073741824,"public_runtime_envelope":false}
```

Only matching `dsmack-alpha-local-task/3` may add `private_input_path`, an
absolute local reference. The path and ancestors must be protected; the input
must be owned, regular, single-link,0600 and nonempty, bounded by the lesser of
1GiB and scratch capacity. Prepare and each execution validation repeat these
metadata checks. Host admission does not read or hash its contents. The existing
guest validates the private runtime envelope and selected subscription-broker
contract. The private input is visible to the trusted host; this is not a claim
of confidentiality from the Mac owner.

The independently authenticated public workload remains a separately signed
per-attempt disk. Its actual USTAR contents, manifest and canonical closure are
checked locally. For this develop selector, `public-inputs`, `envelopes` and
`broker` entries are refused, including descendants, so public and private
runtime representations cannot compete. Application inputs and credential
broker data use the existing private VDE contract, not invented public channels.
The selected transport entry is `envelopes/<selector>.envelope.json`: required
files carry the eight application slots, while the credential is broker-only
`CLAUDE_SUBSCRIPTION_OAUTH`. The measured manifest must use the exact qualified
`claude-subscription/1` adapter, `claudeAiOauth` accepted field, explicit caller
stdin/file source and `https://api.anthropic.com` provider route. Stdin and user
configuration channels remain disabled. Retain a separate public projection
without credentials for the subsequent independent application audit.

The selected release app/base/helper remain unchanged. A new signed inventory,
per-attempt public admission, fresh challenge, enrollment/context joins and
independent actual prelaunch gate are still required. This source candidate
cannot launch against a historical browser inventory.

For a paid worker turn, the requester must freeze specification, base and
acceptance policy, confirm funding, and the worker must durably claim before
actual development starts. The application request must bind those terms and
claim; candidate is initially null. Generic signed execution admission does not
itself prove funding. Existing nonfunded qualification cannot be relabelled as
paid work. A later candidate-dependent review DAG must follow the policy fixed
before the worker started.

## Separate generate profile

`bounty-board-search-generate-v1` is the only additional profile/3 selector.
It uses the same explicit private-channel policy and exact `claude-opus-4-8` /
`none` tuple. It cannot be inferred from a model label, and its manifest digest
must separately match the signed release role. The independently selected
application generator recipe uses180 seconds, two turns, no tools and a fresh
context; it admits at most16 generated tests and512 steps. These budgets are
measured workload policy, not caller-provided alpha configuration. The release
must bind its actual generator image/driver/manifest before any invocation.
No actual generator provider run, three-judge verdict or acceptance is qualified
by this source extension. Existing develop packaging may continue separately.
