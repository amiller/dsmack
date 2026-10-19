// transfer.metal — transfer task kernels.
//
// Extends the verified bounded system-scope mailbox mechanism
// (../mailbox/, modeled on MLX fence.metal
// @ 243bdf09c0cccbb85ca6a686dab3cc0102cf1f7e) with two seed-transfer channels:
//
//  * vc_system / vc_device — VALUE CHANNEL (phase B): per exchange the CPU
//    writes a fresh 32-byte seed (8 words) into the system-scope mailbox, the
//    GPU reads and folds it into register state, the CPU overwrites it with
//    the next seed. vc_device is the device-scope negative control.
//  * timing_system — TIMING CHANNEL (phase C): per symbol the GPU clears a
//    word, publishes "ready", and spins (capped) counting iterations until the
//    CPU's single CONSTANT write appears. The symbol is encoded only in WHEN
//    the CPU writes; the written value never varies.
//  * sys_poll / dev_poll — T_iter probes: spin a fixed number of fence+load
//    iterations with no CPU interaction, so the system/device-scope iteration
//    time can be measured from GPUStartTime/GPUEndTime.
//
// Every spin loop has a finite iteration cap; no while(1) is ever dispatched.
// Word layouts are documented in ../README.md.

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

#define ST_RUNNING 0u
#define ST_DONE 1u
#define ST_CAP_HIT 2u
#define ST_STOPPED 3u
#define ST_STOP_SPIN 4u

#define TIMING_CONST 0xC0FFEE01u

// ---------------------------------------------------------------------------
// Value channel (phase B). Word layout (uint32):
//   0 gpu_seq (trip i requested)  1 gpu_hash (running fold after trip i)
//   2 cpu_resp (=i releases i)     3 gpu_final hash
//   4 cpu_cmd (1=stop)             5 status
//   6 trips done                   7 spins total (approx, wraps)
//   8 future-resp count            9 seed-checksum-fail count
//  10 lost_at trip                11..18 seed slot w[0..7]
// Seed w[7] is the checksum (w0^..^w6)^0xA5A5A5A5; the GPU checks it, then
// folds all 8 words: h = (h ^ w) * 16777619 (FNV-1a style, wraps).
// ---------------------------------------------------------------------------
#define VC_BODY(MB, FENCE_SCOPE)                                                \
  if (tid != 0) {                                                               \
    return;                                                                     \
  }                                                                             \
  uint h = 0u;                                                                  \
  uint future = 0u;                                                             \
  uint cks_fail = 0u;                                                           \
  MB[5] = ST_RUNNING;                                                           \
  MB[6] = 0u;                                                                   \
  MB[7] = 0u;                                                                   \
  MB[8] = 0u;                                                                   \
  MB[9] = 0u;                                                                   \
  atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);\
  for (uint i = 1u; i <= max_trips; i++) {                                      \
    MB[0] = i;                                                                  \
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst,            \
                        FENCE_SCOPE);                                           \
    uint iters = 0u;                                                            \
    bool got = false;                                                           \
    bool stopped = false;                                                       \
    bool saw_future = false;                                                    \
    while (iters < spin_cap) {                                                  \
      atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst,          \
                          FENCE_SCOPE);                                         \
      uint r = MB[2];                                                           \
      if (r == i) {                                                             \
        got = true;                                                             \
        break;                                                                  \
      }                                                                         \
      if (r > i) {                                                              \
        saw_future = true;                                                      \
      }                                                                         \
      if (MB[4] == 1u) {                                                        \
        stopped = true;                                                         \
        break;                                                                  \
      }                                                                         \
      iters++;                                                                  \
    }                                                                           \
    MB[7] += iters;                                                             \
    if (saw_future) {                                                           \
      future++;                                                                 \
    }                                                                           \
    if (stopped) {                                                              \
      MB[5] = ST_STOP_SPIN;                                                     \
      MB[6] = i - 1u;                                                           \
      MB[10] = i;                                                               \
      break;                                                                    \
    }                                                                           \
    if (!got) {                                                                 \
      MB[5] = ST_CAP_HIT;                                                       \
      MB[6] = i - 1u;                                                           \
      MB[10] = i;                                                               \
      break;                                                                    \
    }                                                                           \
    uint w0 = MB[11], w1 = MB[12], w2 = MB[13], w3 = MB[14];                     \
    uint w4 = MB[15], w5 = MB[16], w6 = MB[17], w7 = MB[18];                     \
    if (w7 != ((w0 ^ w1 ^ w2 ^ w3 ^ w4 ^ w5 ^ w6) ^ 0xA5A5A5A5u)) {              \
      cks_fail++;                                                               \
    }                                                                           \
    h = (h ^ w0) * 16777619u;                                                   \
    h = (h ^ w1) * 16777619u;                                                   \
    h = (h ^ w2) * 16777619u;                                                   \
    h = (h ^ w3) * 16777619u;                                                   \
    h = (h ^ w4) * 16777619u;                                                   \
    h = (h ^ w5) * 16777619u;                                                   \
    h = (h ^ w6) * 16777619u;                                                   \
    h = (h ^ w7) * 16777619u;                                                   \
    MB[1] = h;                                                                  \
    MB[6] = i;                                                                  \
  }                                                                             \
  if (MB[5] == ST_RUNNING) {                                                    \
    MB[5] = ST_DONE;                                                            \
  }                                                                             \
  MB[3] = h;                                                                    \
  MB[8] = future;                                                               \
  MB[9] = cks_fail;                                                             \
  atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);

[[kernel]] void vc_system(
    volatile coherent(system) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  VC_BODY(mb, thread_scope_system)
}

[[kernel]] void vc_device(
    volatile coherent(device) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  VC_BODY(mb, thread_scope_device)
}

// ---------------------------------------------------------------------------
// Timing channel (phase C). Word layout (uint32):
//   0 gpu_ready (trip i armed)    1 gpu_count (spin iters of last trip)
//   2 cpu_word (CONST when written)  3 cpu_cmd (1=stop)
//   4 status                      5 trips done
//   6 spins total (wraps)         7 max count   8 min count   9 lost_at
// Per trip: GPU clears word 2, arms word 0, spins counting iterations until
// word 2 == TIMING_CONST, publishes the count, next trip. The CPU only ever
// stores the constant TIMING_CONST; a symbol selects WHEN.
// Stop word is checked every 1024 iterations so each iteration remains the
// same fence+two-load shape as the verified mailbox spin.
// ---------------------------------------------------------------------------
#define TIMING_BODY(MB, FENCE_SCOPE)                                            \
  if (tid != 0) {                                                               \
    return;                                                                     \
  }                                                                             \
  MB[4] = ST_RUNNING;                                                           \
  MB[5] = 0u;                                                                   \
  MB[6] = 0u;                                                                   \
  MB[7] = 0u;                                                                   \
  MB[8] = 0xFFFFFFFFu;                                                          \
  atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);\
  for (uint i = 1u; i <= max_trips; i++) {                                      \
    MB[2] = 0u;                                                                 \
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst,            \
                        FENCE_SCOPE);                                           \
    MB[0] = i;                                                                  \
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst,            \
                        FENCE_SCOPE);                                           \
    uint iters = 0u;                                                            \
    bool stopped = false;                                                       \
    while (iters < spin_cap) {                                                  \
      atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst,          \
                          FENCE_SCOPE);                                         \
      uint r = MB[2];                                                           \
      if (r == TIMING_CONST) {                                                  \
        break;                                                                  \
      }                                                                         \
      uint c = MB[3];                                                           \
      if (c == 1u) {                                                            \
        stopped = true;                                                         \
        break;                                                                  \
      }                                                                         \
      iters++;                                                                  \
    }                                                                           \
    MB[6] += iters;                                                             \
    if (iters > MB[7]) {                                                        \
      MB[7] = iters;                                                            \
    }                                                                           \
    if (iters < MB[8]) {                                                        \
      MB[8] = iters;                                                            \
    }                                                                           \
    MB[1] = iters;                                                              \
    if (stopped) {                                                              \
      MB[4] = ST_STOP_SPIN;                                                     \
      MB[5] = i - 1u;                                                           \
      MB[9] = i;                                                                \
      break;                                                                    \
    }                                                                           \
    if (iters >= spin_cap) {                                                    \
      MB[4] = ST_CAP_HIT;                                                       \
      MB[5] = i - 1u;                                                           \
      MB[9] = i;                                                                \
      break;                                                                    \
    }                                                                           \
    MB[5] = i;                                                                  \
  }                                                                             \
  if (MB[4] == ST_RUNNING) {                                                    \
    MB[4] = ST_DONE;                                                            \
  }                                                                             \
  atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);

[[kernel]] void timing_system(
    volatile coherent(system) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  TIMING_BODY(mb, thread_scope_system)
}

[[kernel]] void timing_device(
    volatile coherent(device) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  TIMING_BODY(mb, thread_scope_device)
}

// ---------------------------------------------------------------------------
// T_iter probes: exactly spin_cap iterations of the same fence + two-load
// shape as the spin loops above, no CPU interaction. T_iter =
// (GPUEndTime - GPUStartTime) / spin_cap.
// ---------------------------------------------------------------------------
#define POLL_BODY(MB, FENCE_SCOPE)                                              \
  if (tid != 0) {                                                               \
    return;                                                                     \
  }                                                                             \
  uint iters = 0u;                                                              \
  atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);\
  while (iters < spin_cap) {                                                    \
    atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst,            \
                        FENCE_SCOPE);                                           \
    uint r = MB[2];                                                             \
    uint c = MB[4];                                                             \
    if (r == TIMING_CONST || c == 1u) {                                         \
      break;                                                                    \
    }                                                                           \
    iters++;                                                                    \
  }                                                                             \
  MB[5] = iters;                                                                \
  MB[1] = iters;                                                                \
  atomic_thread_fence(mem_flags::mem_device, memory_order_seq_cst, FENCE_SCOPE);

[[kernel]] void sys_poll(
    volatile coherent(system) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  POLL_BODY(mb, thread_scope_system)
}

[[kernel]] void dev_poll(
    volatile coherent(device) device uint* mb [[buffer(0)]],
    constant uint& max_trips [[buffer(1)]],
    constant uint& spin_cap [[buffer(2)]],
    constant uint& seed [[buffer(3)]],
    ushort tid [[thread_position_in_threadgroup]]) {
  POLL_BODY(mb, thread_scope_device)
}
