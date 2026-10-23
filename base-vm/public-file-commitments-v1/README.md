# Optional committed public files

This is an unqualified source overlay on the separately pinned
[`browser-sandbox-v1`](../browser-sandbox-v1/README.md) base source package. It
replaces only `dsmack_guest_io/public_inputs.py`; the original package source,
lock, and qualified `8eea5c4d...` image remain unchanged. A newly measured derived
image and actual receipt qualification are required before use.

The existing credential-free, network-none public browser channel accepts an
optional `dsmack.task-commitment/3` covering **every** declared public file. In
this committed form every slot must be required. The shared runtime validator
recomputes the digest over the exact manifest and decoded file bytes. Secret
algorithms, partial scopes, null values and other input groups are refused.
Existing envelopes omitting commitments retain their previous behavior.

The existing runner records the entire validated commitment object in the guest
receipt. Application admission and the full verifier must independently compare
that object and actual original input bytes; a task digest or job-written audit
flag alone grants no authority. The completed six-check diagnostic had no such
commitment and gains none retroactively.

No bounty task semantics, source extractor, application audit, provider credential
channel or network exception is added to the base. Those belong in separately
pinned application harnesses and external verification. This overlay does not
resolve the separate generator public/private input transport.

Run the detecting controls without dependencies:

```sh
python3 base-vm/public-file-commitments-v1/test_public_commitments.py
```
