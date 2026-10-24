# Private develop and generate profiles

Signed `dsmack-alpha-profile/3` adds two selectors to the authenticated alpha
route, each with a private input channel. Browser profile/2 and local task/2 take
no credentials.

## Develop

The develop branch admits only `bounty-board-search-develop-v1`, model label
`claude-opus-4-8`, security label `none`, and the exact compose-manifest digest
in the signed profile. Resources are 4096MiB, one vCPU, 600 seconds, 4GiB scratch
and 256MiB result. The measured workload enforces model/tool budgets and provider
routing; the application recipe sets 480 seconds, 30 turns and its fixed Claude
tool list.

Profile/3 carries an exact signed `private_input_policy`:

```json
{"schema":"dsmack-alpha-private-channel/1","channel":"runtime-envelope-v1","max_bytes":1073741824,"public_runtime_envelope":false}
```

A matching `dsmack-alpha-local-task/3` may add `private_input_path`, an absolute
local path. The path and its ancestors must be protected; the input must be
owned, regular, single-link, 0600 and nonempty, at most the lesser of 1GiB and
scratch capacity. Prepare and every execution repeat these metadata checks. Host
admission does not read or hash the contents; the guest validates the private
runtime envelope and the subscription-broker contract. The trusted host can read
the private input.

The public workload is a signed per-attempt disk. Its USTAR contents, manifest
and canonical closure are checked locally. For the develop selector,
`public-inputs`, `envelopes` and `broker` entries (and descendants) are refused,
so inputs and credentials travel only through the private VDE contract. The
transport entry is `envelopes/<selector>.envelope.json`: required files carry the
eight application slots, and the credential is broker-only
`CLAUDE_SUBSCRIPTION_OAUTH`. The measured manifest uses the `claude-subscription/1`
adapter, accepted field `claudeAiOauth`, an explicit caller stdin/file source and
provider route `https://api.anthropic.com`. Stdin and user configuration channels
are disabled. Keep a credential-free public projection for the application audit.

The release app/base/helper are unchanged. Each run needs a new signed inventory,
per-attempt public admission, a fresh challenge, enrollment/context joins and the
prelaunch gate.

For a paid worker turn, the requester freezes specification, base and acceptance
policy and confirms funding, and the worker durably claims the task before
development starts. The application request binds those terms and the claim;
`candidate` starts as null. Funding is checked by the application, not by
execution admission. Review of the result follows the policy fixed before the
worker started.

## Generate

`bounty-board-search-generate-v1` uses the same private-channel policy and the
exact `claude-opus-4-8` / `none` tuple, and its manifest digest must match the
signed release role. The generator recipe uses 180 seconds, two turns, no tools
and a fresh context, and admits at most 16 generated tests and 512 steps. These
budgets come from the measured workload, not from caller configuration. The
release binds the generator image/driver/manifest.
