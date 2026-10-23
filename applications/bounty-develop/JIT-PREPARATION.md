# Maintainer preparation of an admitted development run

These auxiliary scripts prepare bytes. They do not authenticate requester
approval, a funded task, a worker claim, or permission to run a provider call.
Select the requester policy and Store terms, fund and durably claim the task,
and independently select the complete request/manifest before importing OAuth.

`prepare.py` consumes eight independently selected public files and fixed request,
profile, driver and plan hashes. It audits the full base and emits a manifest and
public-file projection. That projection intentionally lacks the required broker
credential and is **not a complete executable runtime envelope**.

`build_public.py` runs on Zed `/data` and includes the actual pinned f62b develop
OCI layout in the new disk. It verifies the original OCI layout with the qualified
publisher code, normalizes only its repository annotation, and checks the manifest
consumes that exact loopback repository and digest. The measured disk contains
only public channels: manifest, admitted base bytes, OCI, closure context, and the
explicit files-only task commitment declaration. There is no develop envelope in
`public-inputs`, `envelopes`, or `broker` on the measured disk.

`stage_private.py` accepts an explicit credential document on stdin only after
public inputs, selected source pins and private namespace checks pass. Run with
isolated Python (`-I -B`). It reuses the unchanged strict subscription schema,
requires at least 1200 seconds of remaining lifetime before and after staging,
and adds only the broker-audience env value to the full runtime envelope. The
same canonical credential is delivered to the guest-root sentinel separately.
The original private packer and guest parser validate the resulting transport.
Do not let another client refresh this subscription during the admitted run.

The new owned `0700` output namespace retains `0600` private files and the private
image, including on a refusal after staging starts. Never publish, hash for public
evidence, or put these bytes in a public checksum inventory. The report contains
only independently selected public hashes, a lifetime count and presence flags.
There is no claim of Python memory erasure or protection from another process
already acting as the same host user. Host staging assumes a stable owned
namespace; the VM/container boundary is a separate qualified property.

The default `linux-memfd-v1` backend retains the original Linux sealed-descriptor
route. On a Mac, explicitly select `darwin-owned-tempfile-v1`, the separately
reviewed portable module, and an owned `0700` temporary parent. No backend fallback
is automatic. The portable source is pinned and initialized before reading any
credential. It preserves the original wire and guest parser, while using unlinked
owned temporary files instead of kernel write seals; it does not claim Linux seal
equivalence. Standalone Mac qualification requires the actual complete JIT route,
not only portable encoder controls. Keep the credential local to the selected Mac;
a maintainer Zed-to-Mini staging route is never an implicit subscriber requirement.
No new signed app, VM base or workload image is implied by these host tools.
Actual private import, task admission, launch and evidence verification remain
separate selected steps. Dummy/no-network controls are not provider qualification.

The exact original subscription-document source is retained under `reference/`.
The transport loader verifies and compiles selected raw source bytes, including
its private reader dependencies; it does not execute matching bytecode caches.
External source ownership, selected interpreter/library closure and stable staging
are operator prerequisites. No automatic dependency downloads or signing occur.
