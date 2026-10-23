#!/bin/bash
set -euo pipefail
umask 022
cd /work
# The caller pins every archive before this offline, source-read-only build.
mkdir build prefix output tmp
export TMPDIR=/work/tmp
for src in /sources/*.tar.*; do tar -xf "$src" -C build; done
export CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar RANLIB=aarch64-linux-gnu-ranlib
export CROSS=aarch64-linux-gnu-
cd /work/build/zlib-1.3.1
./configure --static --prefix=/work/prefix
make -j4
make install
cd /work/build/libvpx-1.14.1
./configure --prefix=/work/prefix --target=arm64-linux-gcc --enable-static --disable-shared --disable-docs --disable-tools --disable-unit-tests --disable-examples
make -j4
make install
cd /work/build/ffmpeg-7.0.1
export PKG_CONFIG_PATH=/work/prefix/lib/pkgconfig
./configure --enable-cross-compile --arch=aarch64 --target-os=linux --cross-prefix=aarch64-linux-gnu- --disable-doc --pkg-config=pkg-config --pkg-config-flags=--static --extra-cflags=-I/work/prefix/include --extra-ldflags=-L/work/prefix/lib --prefix=/work/prefix --bindir=/work/output --extra-version=dsmack-source-v1 --disable-debug --disable-autodetect --disable-everything --disable-shared --enable-static --enable-ffmpeg --disable-ffplay --disable-ffprobe --enable-protocol=pipe --enable-protocol=file --enable-parser=mjpeg --enable-decoder=mjpeg --enable-demuxer=image2pipe --enable-filter=pad --enable-filter=crop --enable-filter=scale --enable-muxer=webm --enable-libvpx --enable-encoder=libvpx_vp9 --enable-decoder=libvpx_vp9 --enable-bsf=vp9_superframe --enable-demuxer=matroska --enable-encoder=png --enable-zlib --enable-muxer=image2 --disable-iconv --disable-bzlib
make -j4 ffmpeg
cp ffmpeg /work/output/ffmpeg-linux
mkdir /work/output/notices
cp COPYING.LGPLv2.1 LICENSE.md /work/output/notices/
cp /work/build/libvpx-1.14.1/LICENSE /work/output/notices/libvpx-LICENSE
cp /work/build/zlib-1.3.1/LICENSE /work/output/notices/zlib-LICENSE
cp config.h config_components.h ffbuild/config.mak /work/output/
$CC --version > /work/output/compiler.txt
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > /work/output/builder-packages.txt
aarch64-linux-gnu-readelf -d /work/output/ffmpeg-linux > /work/output/elf-dynamic.txt
sha256sum /work/output/ffmpeg-linux > /work/output/ffmpeg.sha256
