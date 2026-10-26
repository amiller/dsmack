#!/bin/sh
# Cross-builds libdsmack_hvf_returning.a for aarch64-apple-darwin with the toolchain pinned in
# source-tree/rust-toolchain.toml. Build paths are remapped so the archive does not
# depend on the checkout, CARGO_HOME or rustup locations.
# Output: native/source-tree/target/aarch64-apple-darwin/release/
set -eu
cd "$(dirname "$0")/source-tree"
native="$(cd .. && pwd)"
sysroot="$(rustc --print sysroot)"
commit="$(rustc -vV | sed -n 's/^commit-hash: //p')"
export RUSTFLAGS="--remap-path-prefix=$native=/dsmack/runner-vm/native --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$sysroot/lib/rustlib/src/rust=/rustc/$commit"
cargo build -p dsmack-hvf-returning --release --locked --target aarch64-apple-darwin "$@"
