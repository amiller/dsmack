# Host from your own Apple team

`CDRegistry` admits a copy of the approved runner re-signed by any Apple team. It pins the
code pages, page 0 apart from the signature's size fields, the CodeDirectory header, and the
entitlements apart from the application identifier, team identifier and keychain groups.
[`runner-vm/packaging/own-team.sh`](../runner-vm/packaging/own-team.sh) re-signs the released
app with your identity, registers the copy, enrolls its App Attest key and links the key to
your operator wallet.

## Apple Developer account

In your team: an explicit App ID with the App Attest capability, an Apple Development
certificate, this Mac's provisioning UDID registered, and a macOS development profile for
that App ID, certificate and Mac. The hypervisor entitlement needs no capability in the
profile. The script takes the application identifier and team from the profile.

## Re-sign, register and enroll

Unpack `DsmackRunner.app.zip` from the current
[runner release](https://github.com/amiller/dsmack/releases) and check it as the release's
`HOST-START-HERE.txt` says. From a checkout with its Python environment
([CONTRIBUTING.md](../CONTRIBUTING.md)) and Foundry's `cast`:

```sh
cast wallet import host --interactive   # once: the key that pays gas, in a Foundry keystore
policy() { python3 -c 'import json,sys;print(json.load(open("applications/private-agent-web/sandbox-policy.json"))[sys.argv[1]])' "$1"; }
APP=/path/to/DsmackRunner.app \
PROFILE=/path/to/your.provisionprofile \
SIGN_IDENTITY="Apple Development: Your Name (XXXXXXXXXX)" \
OUT="$HOME/dsmack-runner" \
RPC=https://sepolia.base.org CDS=$(policy registry) ATTEST=$(policy attest) \
INTERMEDIATE=0xb4fb420570c9ae811939c8953a785ed10beeca40453a89404f36e87a12b88d90 \
ACCOUNT=host PYTHON=.venv/bin/python \
runner-vm/packaging/own-team.sh
```

The script:

1. Re-signs `APP` into `OUT/DsmackRunner.app` and compares the fields `CDRegistry` pins with
   `APP`'s.
2. Checks that `APP` is a copy of the registry's current build, simulates `registerBuild` for
   your copy, sends it (about 0.85M gas) and checks that `rpIdHash(cdhash)` is the SHA-256 of
   your application identifier.
3. Runs the copy's `enroll` into `OUT/enrollment`, simulates the verifier's `enroll`, sends it
   (about 14M gas, 16M limit) and checks `keys(kid)`.

It prints the application identifier, your copy's CDHash and the key ID. A run skips what
the chain already shows, so repeat it after a failure. `registerBuild` publishes the
entitlements, so your team and application identifier are public. `INTERMEDIATE` is the
entry ID of Apple's App Attest intermediate in `AppleEndorsements`
([app-attest/DEPLOY.md](../app-attest/DEPLOY.md)).

`OUT` has the layout of a runner directory: add the release's `base/` and `runtime/` to
launch workloads from it.

## Link the key to an operator

Create a provisioner and the operator's authorization as in
[Mac ownership](../applications/mac-ownership/README.md), then run the script again with

```sh
AUTHORIZATION="$HOME/.dsmack/provisioning.json" PROVISIONER_KEY="$HOME/.dsmack/provisioner.key" \
PUBLISHER_KEY=/path/to/publisher.key
```

added. It posts the `MacLink` for the enrolled key to the broker (`BROKER` overrides the
default).
