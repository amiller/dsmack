#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
: "${ATTEST_TOOLS:?Set ATTEST_TOOLS to an absolute toolchain directory}"
[[ "$ATTEST_TOOLS" = /* ]] || { echo "ATTEST_TOOLS must be absolute" >&2; exit 1; }
export HOME="$ATTEST_TOOLS/home" TMPDIR="$ATTEST_TOOLS/tmp"
export BB_HOME="$ATTEST_TOOLS/bb-home" XDG_CACHE_HOME="$ATTEST_TOOLS/cache"
source_dir=$PWD
mkdir -p "$BB_HOME/crs" "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$ATTEST_TOOLS/"{bin,nargo,bb,runtime}
cd "$ATTEST_TOOLS"
curl -fsSL https://github.com/noir-lang/noir/releases/download/v1.0.0-beta.17/nargo-x86_64-unknown-linux-gnu.tar.gz -o nargo.tar.gz
tar -xzf nargo.tar.gz -C nargo
curl -fsSL https://github.com/AztecProtocol/aztec-packages/releases/download/v3.0.3/barretenberg-amd64-linux.tar.gz -o bb.tar.gz
tar -xzf bb.tar.gz -C bb
# zed runs glibc 2.35; the release binary requires 2.39.
curl -fsSL https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.39-0ubuntu8.9_amd64.deb -o libc.deb
curl -fsSL https://archive.ubuntu.com/ubuntu/pool/main/g/gcc-14/libstdc++6_14.2.0-4ubuntu2~24.04.1_amd64.deb -o libstdcpp.deb
dpkg-deb -x libc.deb runtime
dpkg-deb -x libstdcpp.deb runtime
cat > bin/bb <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
r=$(cd "$(dirname "$0")/.." && pwd)
exec "$r/runtime/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" --library-path "$r/runtime/usr/lib/x86_64-linux-gnu" "$r/bb/bb" "$@"
WRAPPER
chmod +x bin/bb
curl -fsSL https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.27+commit.40a35a09 -o bin/solc-0.8.27
chmod +x bin/solc-0.8.27
curl -fsSL https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.21+commit.d9974bed -o bin/solc-0.8.21
chmod +x bin/solc-0.8.21
mkdir -p foundry/bin
curl -fsSL https://github.com/foundry-rs/foundry/releases/download/v1.8.5/foundry_v1.8.5_linux_amd64.tar.gz -o foundry.tar.gz
tar -xzf foundry.tar.gz -C foundry/bin
. "$source_dir/env.sh"
forge --version
"$SOLC" --version
"$ATTEST_TOOLS/bin/solc-0.8.27" --version
