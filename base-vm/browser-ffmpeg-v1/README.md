# Separately selected browser FFmpeg build

This candidate replaces only the FFmpeg executable used to record browser video,
plus its source/notice metadata, in a new derivative of the qualified ARM64
browser image. It does not replace or retag an image used by existing paid tasks.
The new digest needs independent selection and fresh starter qualification.

The original installed binary reports `n7.0.1-playwright-build-1013`, static
libvpx/zlib support, and the bundled LGPL 2.1 notice. The available historical
Playwright build recipe predates build 1013. This directory therefore defines a
new build rather than claiming that an inferred recipe reproduces that binary.

`SOURCES.json` pins original FFmpeg 7.0.1, libvpx 1.14.1 and zlib 1.3.1 archives
from their official release locations. Acquisition hashes identify the exact
inputs; detached release-signature verification is not claimed. Retain all three
archives with this build script, generated configuration, compiler/package
records and original notices in the corresponding-source package.

The caller verifies the exact source filenames, sizes and hashes, selects the
builder image digest and mounts `/sources` and `/build.sh` read-only. Run
`build.sh` as an unprivileged user with networking disabled and a fresh `/work`
directory. The build uses four compiler workers. Its output is not executed as a
host program; ARM64 validation occurs in a separate bounded container.

The executable has statically linked FFmpeg/libvpx/zlib code and uses the target
Ubuntu C runtime dynamically. Source and generated configuration are retained;
this is not a claim of bit-for-bit reproduction of Microsoft's binary. The
configure command permits file/pipe input, MJPEG frames, VP9 WebM recording and
PNG frame output. It does not enable network protocols, GPL or nonfree features.
The original license texts govern; the directory does not grant additional
rights or declare all unrelated image dependencies cleared.

`Dockerfile.runtime` leaves the application entrypoint and harness source intact.
The existing Playwright filename is retained for compatibility; version output
identifies `dsmack-source-v1`. Before adoption, check the actual parent digest,
resulting OCI ancestry and installed binary hash, offline JPEG-to-WebM and
WebM-to-PNG operation, malformed-input refusal, protocol list and dynamic
libraries. Full14 browser qualification is a separate step and must not be
inferred from those media controls.
