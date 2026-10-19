// Bounded CPU<->GPU round-trip mailbox, modeled on MLX fence.metal
// (ml-explore/mlx @ 243bdf09c0cccbb85ca6a686dab3cc0102cf1f7e,
//  mlx/backend/metal/kernels/fence.metal, Copyright Apple).
//
// Differences from MLX fence.metal, on purpose:
//  * every spin loop has a finite iteration cap (spin_cap); no while(1),
//  * the kernel carries a synthetic register value across trips and both
//    sides verify every published word,
//  * a device-scope control kernel (mailbox_device) mirrors the system-scope
//    kernel (mailbox_system) exactly except for the coherence qualifier and
//    the fence scope, so the two can be diffed in IR and machine code.
//
// Word layout is documented in ../README.md.

#pragma METAL internals : enable

#ifndef __METAL_MEMORY_SCOPE_SYSTEM__
#define __METAL_MEMORY_SCOPE_SYSTEM__ 3
#endif

namespace metal {
constexpr constant metal::thread_scope thread_scope_system =
    static_cast<thread_scope>(__METAL_MEMORY_SCOPE_SYSTEM__);
}

#include <metal_atomic>

using namespace metal;

#define MAILBOX_STATUS_RUNNING 0u
#define MAILBOX_STATUS_DONE 1u
#define MAILBOX_STATUS_CAP_HIT 2u
#define MAILBOX_STATUS_STOPPED 3u
#define MAILBOX_STATUS_STOP_SPIN 4u

#define MAILBOX_BODY(MB, FENCE_SCOPE)                                         \
  if (tid != 0) {                                                             \
    return;                                                                   \
  }                                                                           \
  ulong x = ((ulong)seed << 32) | 0x9E3779B97F4A7C15ul;                       \
  uint wrong = 0u;                                                            \
  uint future = 0u;                                                           \
  MB[5] = MAILBOX_STATUS_RUNNING;                                             \
  MB[6] = 0u;                                                                 \
  MB[7] = 0u;                                                                 \
  MB[8] = 0u;                                                                 \
  MB[9] = 0u;                                                                 \
  MB[10] = 0u;                                                                \
  atomic_thread_fence(                                                        \
      mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);              \
  for (uint i = 1u; i <= max_trips; i++) {                                    \
    x = x * 6364136223846793005ul + 1442695040888963407ul;                    \
    uint val = (uint)(x & 0xfffffffful);                                      \
    MB[1] = val;                                                              \
    MB[0] = i;                                                                \
    atomic_thread_fence(                                                      \
        mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);            \
    uint iters = 0u;                                                          \
    bool got = false;                                                         \
    bool stopped = false;                                                     \
    bool saw_future = false;                                                  \
    while (iters < spin_cap) {                                                \
      atomic_thread_fence(                                                    \
          mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);          \
      uint r = MB[2];                                                         \
      if (r == i) {                                                           \
        uint echo = MB[3];                                                    \
        uint want = (val ^ 0xA5A5A5A5u) + i;                                  \
        if (echo != want) {                                                   \
          wrong++;                                                            \
        }                                                                     \
        got = true;                                                           \
        break;                                                                \
      }                                                                       \
      if (r > i) {                                                            \
        saw_future = true;                                                    \
      }                                                                       \
      if (MB[4] == 1u) {                                                      \
        stopped = true;                                                       \
        break;                                                                \
      }                                                                       \
      iters++;                                                                \
    }                                                                         \
    MB[7] += iters;                                                           \
    if (saw_future) {                                                         \
      future++;                                                               \
    }                                                                         \
    if (stopped) {                                                            \
      MB[5] = MAILBOX_STATUS_STOP_SPIN;                                       \
      MB[6] = i - 1u;                                                         \
      MB[10] = i;                                                             \
      break;                                                                  \
    }                                                                         \
    if (!got) {                                                               \
      MB[5] = MAILBOX_STATUS_CAP_HIT;                                         \
      MB[6] = i - 1u;                                                         \
      MB[10] = i;                                                             \
      break;                                                                  \
    }                                                                         \
    MB[6] = i;                                                                \
  }                                                                           \
  if (MB[5] == MAILBOX_STATUS_RUNNING) {                                      \
    MB[5] = MAILBOX_STATUS_DONE;                                              \
  }                                                                           \
  MB[8] = wrong;                                                              \
  MB[9] = future;                                                             \
  atomic_thread_fence(                                                        \
      mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);

// System-scope variant: the MLX mechanism under test.
[[kernel]] void mailbox_system(
    volatile coherent(system) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  MAILBOX_BODY(mb, thread_scope_system)
}

// Device-scope control: documented scope, everything else identical.
[[kernel]] void mailbox_device(
    volatile coherent(device) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  MAILBOX_BODY(mb, thread_scope_device)
}
