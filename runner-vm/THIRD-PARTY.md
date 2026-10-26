# Third-party components

- `native/source-tree/source`: modified [libkrun](https://github.com/containers/libkrun),
  Apache-2.0, license at `native/source-tree/source/LICENSE`.
- Rust crate dependencies are pinned in `native/source-tree/Cargo.lock`
  and fetched by Cargo.
- The app links Apple's DeviceCheck and Hypervisor frameworks from the macOS SDK.
