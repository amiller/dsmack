#!/bin/sh
# Rootless podman inside a dev-session-v1 service: pull by digest, run, bind the result with /v1/Attest.
set -eu
IMG=ghcr.io/containerd/busybox@sha256:7b3ccabffc97de872a30dfd234fd972a66d247c8cfc69b0550f276481852627c
OUT=/workspace/artifacts
mkdir -p "$XDG_RUNTIME_DIR" "$TMPDIR"
{
  podman info --format 'rootless={{.Host.Security.Rootless}} driver={{.Store.GraphDriverName}} runtime={{.Host.OCIRuntime.Name}} uidmap={{.Host.IDMappings.UIDMap}}'
  podman pull -q "$IMG" >/dev/null
  podman image inspect --format 'pulled={{.Digest}} arch={{.Architecture}}' "$IMG"
  podman run --rm "$IMG" sh -c 'echo inner: hello; echo inner: $(id); echo inner: $(uname -m)'
  for t in ghcr.io:443 1.1.1.1:443; do
    podman run --rm "$IMG" nc -z -w 5 ${t%:*} ${t#*:} && echo "inner egress $t: connected" || echo "inner egress $t: refused or timed out"
  done
} > $OUT/result.txt
cat $OUT/result.txt
d=$(sha256sum $OUT/result.txt | cut -c1-64)
curl -fsS --unix-socket /var/run/dstack.sock -H 'Content-Type: application/json' \
  -d "{\"report_data\":\"${d}0000000000000000000000000000000000000000000000000000000000000000\"}" http://dstack/v1/Attest > $OUT/attestation.json
echo "attested sha256(result.txt)=$d"
