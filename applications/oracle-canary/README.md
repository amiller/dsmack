# Oracle canary

A public workload whose only secret is a P-256 key K it mints in memory. It calls
`/v1/Attest` with `report_data` = K's public key (x || y), then signs any message the
host sends, as ECDSA over `sha256("dsmack.canary.oracle/1" || msg)`. It refuses messages
that start with `dsmack.canary.claim/1`, and because it hashes under its own prefix, no
encoding of the input yields a signature over a claim digest. The Mac owner gets unlimited
chosen-message signing with full control of timing, scheduling and the network.

A `Canary` Oracle entry (`armOracle`) pins the image, the compose manifest and the
`oracle` service, and reads K from the attestation's `report_data`. A K signature over
`claimDigest(id, claimant)` therefore means K left the guest. A fresh K is minted on
every boot, so a leak has to work within one run.

Two signers, one manifest each:

- `variable`: pure-Python double-and-add with a branch per nonce bit. Its timing leaks
  the nonce, so its entry calibrates whether host-observable timing reaches guest
  computation.
- `constant`: the image's OpenSSL (`libcrypto.so.3` through ctypes).

The workload dials the host at `192.168.127.254:<port>` (the Mac's loopback through
gvproxy), sends `{signer, public_key, attestation}` and answers one JSON line per
request: `{"msg": hex}` gets `{"r", "s"}` or `{"error": "claim message"}`. It exits when
the host hangs up.

## Build and run

```sh
python3 workload.py <repo> <image files> <starter public-tree> <out> variable 18806
python3 host.py 18806 500 <dir>    # on the Mac, before launching the run
```

`workload.py` prints the manifest sha256, `os_image_hash` and workload disk digest.
`host.py` times 500 signing requests from the host side into `<dir>/timing.csv`
(`i,msg,ns,r,s`), checks that a claim message is refused and saves the guest's hello as
`<dir>/hello.json`. Appending `print-k` to `workload.py` builds a test manifest that also
writes K to its outputs, for exercising the claim path.

Claim with `contracts/canary_claim.py <attestation hex> <K hex> <claimant> <id> <canary> <chainid>`.

## TLS canary

`tls.py` builds a second Oracle canary for the provider TLS boundary (#170). Service `tls`
mints K, attests K's public key, then every 30 s sends K as the `x-api-key` of a request to
`https://api.anthropic.com` through the Mac's CONNECT proxy, the path the credential sentinel
uses. Anthropic answers 401. K reaches the host only if the host can read the guest's provider
TLS, and then it signs the claim.

```sh
python3 tls.py <repo> <image files> <starter public-tree> <out> sentinel 18807 600
python3 tls_host.py 18807 honest    # on the Mac: a plain tunnel
python3 tls_host.py 18807 steal     # the eMudhra attack; prints K once the guest sends it
```

`sentinel` trusts `guest/sentinel/roots/api.anthropic.com.pem`; `system` trusts the image's
`/etc/ssl/certs/ca-certificates.crt`, as the sentinel did before #170. Claim with
`contracts/canary_claim.py` and the K that `steal` prints. `test_tls.py` runs the guest code
locally against `steal`.
