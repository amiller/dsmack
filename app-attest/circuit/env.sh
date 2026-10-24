: "${ATTEST_TOOLS:?Set ATTEST_TOOLS to an absolute toolchain directory}"
[[ "$ATTEST_TOOLS" = /* ]] || { echo "ATTEST_TOOLS must be absolute" >&2; return 1; }
export ATTEST_TOOLS
export SOLC="$ATTEST_TOOLS/bin/solc-0.8.21"
export HOME="$ATTEST_TOOLS/home"
export NARGO_HOME="$ATTEST_TOOLS/nargo-home"
export BB_HOME="$ATTEST_TOOLS/bb-home"
export XDG_CACHE_HOME="$ATTEST_TOOLS/cache"
export CARGO_HOME="$ATTEST_TOOLS/cargo"
export TMPDIR="$ATTEST_TOOLS/tmp"
export PATH="$ATTEST_TOOLS/bin:$ATTEST_TOOLS/nargo:$ATTEST_TOOLS/foundry/bin:$PATH"
export HARDWARE_CONCURRENCY=12
export OMP_NUM_THREADS=12

for tool in forge cast anvil nargo bb; do
    resolved=$(command -v "$tool") || { echo "Missing pinned tool: $tool; run app-attest/circuit/install.sh" >&2; return 1; }
    [[ "$resolved" = "$ATTEST_TOOLS/"* && -x "$resolved" ]] || { echo "$tool resolves outside ATTEST_TOOLS: $resolved" >&2; return 1; }
done
for tool in "$SOLC" "$ATTEST_TOOLS/bin/solc-0.8.27"; do
    [[ -x "$tool" ]] || { echo "Missing pinned compiler: $tool" >&2; return 1; }
done
unset tool resolved
