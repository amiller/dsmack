// Device-scope control for the MLX fence kernels.
//
// Mirrors mlx/backend/metal/kernels/fence.metal @
// 243bdf09c0cccbb85ca6a686dab3cc0102cf1f7e kernel-for-kernel, built the same
// way (same `#pragma METAL internals : enable`, same include, same toolchain),
// with exactly two differences:
//   * the shared pointers are `coherent(device)` instead of `coherent(system)`
//   * the fences use the documented `thread_scope_device` instead of the
//     internal `thread_scope_system` (scope 3)
//
// Like the MLX original, these kernels contain `while (1)` and are NEVER
// dispatched. This file exists only so the system-scope and device-scope
// lowering can be diffed in LLVM IR and G16 machine code (Phase A).

#pragma METAL internals : enable

#include <metal_atomic>

[[kernel]] void input_coherent_device(
    volatile coherent(device) device uint* input [[buffer(0)]],
    const constant uint& size [[buffer(1)]],
    uint index [[thread_position_in_grid]]) {
  if (index < size) {
    input[index] = input[index];
  }
  metal::atomic_thread_fence(
      metal::mem_flags::mem_device,
      metal::memory_order_seq_cst,
      metal::thread_scope_device);
}

// single thread kernel to update timestamp
[[kernel]] void fence_update_device(
    volatile coherent(device) device uint* timestamp [[buffer(0)]],
    constant uint& value [[buffer(1)]]) {
  timestamp[0] = value;
  metal::atomic_thread_fence(
      metal::mem_flags::mem_device,
      metal::memory_order_seq_cst,
      metal::thread_scope_device);
}

// single thread kernel to spin wait for timestamp value
[[kernel]] void fence_wait_device(
    volatile coherent(device) device uint* timestamp [[buffer(0)]],
    constant uint& value [[buffer(1)]]) {
  while (1) {
    metal::atomic_thread_fence(
        metal::mem_flags::mem_device,
        metal::memory_order_seq_cst,
        metal::thread_scope_device);
    if (timestamp[0] >= value) {
      break;
    }
  }
}
