#!/bin/sh
# Cross-builds libdsmack_hvf_returning.a for aarch64-apple-darwin (needs the rust-std for that target).
# Output: native/source-tree/apple-static/target/aarch64-apple-darwin/release/
set -eu
cd "$(dirname "$0")/source-tree/apple-static"
cargo build --release --locked --target aarch64-apple-darwin "$@"
