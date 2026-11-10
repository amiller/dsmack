# Encrypted payload

Export a Linux arm64 Docker image, encrypt its filesystem and launch config with
AES-256-GCM, and execute it after the existing guest-attestation release policy
releases its key. The public loader and ciphertext travel in a digest-pinned OCI
image on measured vdc. The compose command also names the ciphertext SHA-256.

The loader builds PRoot 5.4.0 and directs its temporary files to `/run/dsmack`.
The loader decrypts under `/run/dsmack`, verifies that it is tmpfs, and uses PRoot
to execute the exported entrypoint plus command with the image's environment and
working directory. The networked contract fixes UID 1000 and has no configurable
capabilities; PRoot supplies the filesystem switch without `CAP_SYS_CHROOT`.
The payload writes declared files under `/outputs` and prints its result. The
example declares `answer.json`, release metadata and the attestation as artifacts.

## Author

Needs Docker, Python with `cryptography` on a Linux builder:

```sh
APP=/path/to/dsmack/applications/encrypted-payload
mkdir demo
cp "$APP/demo.sh" demo/
cp /path/to/private-marker demo/marker
docker build --platform linux/arm64 -f "$APP/demo.Dockerfile" -t encrypted-demo:local demo
python3 "$APP/encrypt.py" encrypted-demo:local encrypted
mkdir loader-context
cp "$APP/loader.py" "$APP/Dockerfile" loader-context/
cp encrypted/payload.aes loader-context/
docker build --platform linux/arm64 -t encrypted-loader:local loader-context
python3 "$APP/image.py" encrypted-loader:local loader-image
```

`encrypted/` holds `payload.aes`, `key.hex` (mode 0600), and
`ciphertext.sha256`. Provision the key to a fresh task in
[`dstack-compat/secret-release`](../../dstack-compat/secret-release/server.ts),
using the packed compose hash and base image hash. Keep the author directory and
policy key store on the author/policy machines. Stage only the packed workload
and public base files on the worker Mac.

## Pack and run

Use an existing base bundle and a reference manifest for that runtime:

```sh
python3 "$APP/workload.py" --base BASE --reference REFERENCE.app-compose.json \
  --image loader-image --ciphertext encrypted/payload.aes --out packed \
  --task FRESH_TASK_ID --policy http://192.168.127.254:18791
```

The packer emits `packed/compose-manifest.json` and `packed/disk/workload.img`.
Run them with DsmackRunner's existing hvf-v3 launcher and matching disk templates.
The measured egress policy permits only TCP to the policy URL's IP and port;
the URL must use an IP literal. `192.168.127.254` reaches Mac loopback through
gvproxy for a temporary local policy server.

The demo hashes `encrypted-demo:fixed-challenge:` followed by the marker bytes,
and returns that digest on stdout and in `/outputs/answer.json`.
