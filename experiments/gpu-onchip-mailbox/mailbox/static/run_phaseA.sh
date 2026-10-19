#!/usr/bin/env bash
# Phase A — static RE of the MLX system-scope fence mechanism on the Mac mini.
# Compile-only: no kernel in this phase is ever dispatched.
# Needs clones: MLX=<ml-explore/mlx @ 243bdf09> APPLEGPU=<dougallj/applegpu @ 28dd8046>.
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
MLX=${MLX:?set MLX to an ml-explore/mlx clone}
APPLEGPU=${APPLEGPU:?set APPLEGPU to an applegpu clone}
LOG=$ROOT/logs/phaseA
mkdir -p "$LOG"
WORK=$LOG/work
mkdir -p "$WORK"
cd "$WORK"

step() { echo; echo "===== [phaseA] $* ====="; }
rec() { echo "[phaseA] $*"; }

step "environment"
{
  date
  uname -a
  sw_vers
  xcrun metal --version 2>&1 | head -2
  xcrun metallib --version 2>&1 | head -1
  xcrun clang --version 2>&1 | head -2
} > ../env.txt 2>&1
cat ../env.txt

step "device record (Metal device used for binary archives)"
xcrun clang -O2 -fobjc-arc -framework Metal -framework Foundation \
  -x objective-c -o device_info - <<'EOF' 2> ../device_info_build.log
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
int main() {
  @autoreleasepool {
    id<MTLDevice> d = MTLCreateSystemDefaultDevice();
    if (!d) { printf("no device\n"); return 1; }
    printf("name=%s\n", [[d name] UTF8String]);
    printf("registryID=%llu\n", (unsigned long long)[d registryID]);
    printf("unifiedMemory=%d\n", [d hasUnifiedMemory]);
    for (NSInteger f = 1001; f <= 1012; f++)
      printf("family(%ld)=%d\n", (long)f, [d supportsFamily:(MTLGPUFamily)f]);
    printf("family(5001)=%d\n", [d supportsFamily:(MTLGPUFamily)5001]);
    return 0;
  }
}
EOF
./device_info | tee ../device_info.txt

step "pin inputs"
MLX_FENCE=$MLX/mlx/backend/metal/kernels/fence.metal
rec "mlx fence.metal sha256:"
shasum -a 256 "$MLX_FENCE" | tee ../sha256_inputs.txt
rec "applegpu pinned: $(git -C "$APPLEGPU" rev-parse HEAD)"
rec "mlx pinned: $(git -C "$MLX" rev-parse HEAD)"
cp "$MLX_FENCE" fence_sys.metal
cp "$EXP/control_fence_device.metal" fence_dev.metal
shasum -a 256 fence_dev.metal >> ../sha256_inputs.txt

step "compile system + device variants (AIR, LLVM IR, metallib)"
for v in sys dev; do
  echo "--- $v ---"
  xcrun metal -S -emit-llvm -c fence_$v.metal -o fence_$v.ll \
    > metal_${v}_emitllvm.log 2>&1
  echo "emit-llvm exit: $?"
  xcrun metal -c fence_$v.metal -o fence_$v.air > metal_${v}_c.log 2>&1
  echo "compile exit: $? air sha256: $(shasum -a 256 fence_$v.air | cut -d' ' -f1)"
  xcrun metallib fence_$v.air -o fence_$v.metallib > metallib_${v}.log 2>&1
  echo "metallib exit: $? sha256: $(shasum -a 256 fence_$v.metallib | cut -d' ' -f1)"
done
# Unoptimized IR as well, to see the pre-lowering form of the fence builtin.
for v in sys dev; do
  xcrun metal -O0 -S -emit-llvm -c fence_$v.metal -o fence_${v}_O0.ll \
    > metal_${v}_O0.log 2>&1
  echo "emit-llvm -O0 ($v) exit: $?"
done

step "build applegpu tools"
make -C "$APPLEGPU/compiler_explorer_tools" > ../applegpu_build.log 2>&1
echo "make exit: $?"
tail -3 ../applegpu_build.log

step "G16 machine code via MTLBinaryArchive (compile-only, no dispatch)"
# NOTE: metal-compile-tool rejects a metallib with more than one compute
# kernel ("Only one compute shader is allowed!"). Recorded in mct_*.log.
# We do NOT modify or split the pinned source; we use the tool's own -f
# <function> selection on the unmodified metallib, once per kernel.
CT=$APPLEGPU/compiler_explorer_tools
for v in sys dev; do
  if [ "$v" = sys ]; then fns="fence_wait fence_update input_coherent";
  else fns="fence_wait_device fence_update_device input_coherent_device"; fi
  for fn in $fns; do
    "$CT/metal-compile-tool" -f "$fn" -o ${fn}.bin fence_$v.metallib \
      > mct_${fn}.log 2>&1
    echo "metal-compile-tool ($fn) exit: $?"
    if [ ! -s ${fn}.bin ]; then echo "  (no archive produced)"; continue; fi
    "$CT/metal-archive-extractor" --list-shaders ${fn}.bin 2>&1 | \
      tee list_shaders_${fn}.txt
    "$CT/metal-archive-extractor" --extract-compute ${fn}_compute.bin \
      ${fn}.bin 2>&1 | tee extract_${fn}.log
    echo "extract exit: $? size: $(stat -f%z ${fn}_compute.bin 2>/dev/null)"
  done
done

step "disassemble with applegpu (G13-targeted; G16 may decode partially)"
for f in fence_wait fence_update input_coherent \
         fence_wait_device fence_update_device input_coherent_device; do
  [ -s ${f}_compute.bin ] || continue
  python3 "$APPLEGPU/disassemble.py" ${f}_compute.bin \
    > ${f}_compute.disasm 2> ${f}_compute.disasm.err
  echo "disassemble ($f) exit: $?"
  echo "failed-instruction lines: $(grep -c 'disassembly failed' ${f}_compute.disasm || true)"
done

step "diff summaries"
diff fence_sys.ll fence_dev.ll > ll.diff; echo "ll.diff exit: $? lines: $(wc -l < ll.diff)"
diff fence_sys_O0.ll fence_dev_O0.ll > ll_O0.diff; \
  echo "ll_O0.diff exit: $? lines: $(wc -l < ll_O0.diff)"
for pair in "fence_wait fence_wait_device" \
            "fence_update fence_update_device"; do
  set -- $pair
  if [ -s ${1}_compute.disasm ] && [ -s ${2}_compute.disasm ]; then
    diff ${1}_compute.disasm ${2}_compute.disasm > ${1}_vs_${2}.disasm.diff
    echo "${1} vs ${2} diff lines: $(wc -l < ${1}_vs_${2}.disasm.diff)"
  fi
done

step "done"
rec "outputs in $WORK"
exit 0
