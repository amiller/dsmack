// transfer2_host.mm — phase 2 host (mailbox retest).
//
// Two conditions on one binary:
//  * mode "fresh" + kernel vc_system — the real system-scope mailbox
//    exchange at full rate, identical to the prior phase B fresh runs
//    except for the LCG defect fix below.
//  * mode "matched" + kernel dev_poll — matched no-exchange control: the
//    CPU runs the identical host loop (same word layout, same 8 seed-word
//    stores + response store per exchange, same fold recomputation, same
//    trip count) against a malloc'd, never-GPU-mapped 128-byte line whose
//    seq self-advances after a spin of the measured mean exchange period
//    (period_ns); concurrently a device-scope dev_poll kernel spins on its
//    own private buffer for spin_cap iterations (~4 s at ~181 ns/iter), so
//    the GPU is busy for the same wall span as the real exchange without
//    ever touching the CPU's line. Residual asymmetry vs (a): no GPU stores
//    or GPU loads of the line per exchange, and the CPU spin reads a timer
//    instead of polling the shared line.
//
// LCG defect fix (prior phase B): the seed words were derived from the LOW
// 32 bits of the 64-bit LCG state, which depend only on the low 32 bits of
// the initial state — a fixed constant — so every run sent the same word
// sequence regardless of the seed argument. Words are now derived from the
// HIGH 32 bits of the state ((uint32_t)(x >> 32)), which depend on all 64
// initial bits. Verified by comparing gpu_final_hash of two smoke runs with
// different seeds.
//
// Exit codes: 0 = completed within bounds; 87 = GPU did not return in bound /
// accessRevoked / command-buffer error (runner must abort, no retry).
//
// argv: transfer2_host <metallib> <kernel:vc_system|dev_poll>
//         <mode:fresh|matched> <chunks> <trips> <spin_cap> <seed>
//         <respond_s> <period_ns> <tag>

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mach/mach_time.h>

static mach_timebase_info_data_t g_tb;
static inline double mach_to_ns(uint64_t t) {
  return (double)t * (double)g_tb.numer / (double)g_tb.denom;
}
static inline uint64_t now_mach() { return mach_absolute_time(); }

enum {
  W_GPU_SEQ = 0, W_GPU_HASH = 1, W_CPU_RESP = 2, W_GPU_FINAL = 3, W_CPU_CMD = 4,
  W_STATUS = 5, W_TRIPS = 6, W_SPINS = 7, W_FUTURE = 8, W_CKSFAIL = 9,
  W_LOST_AT = 10, W_SEED0 = 11, W_N = 32
};

static const char* status_name(uint32_t s) {
  switch (s) {
    case 0: return "running";
    case 1: return "done";
    case 2: return "cap_hit";
    case 3: return "stopped_boundary";
    case 4: return "stopped_in_spin";
    default: return "unknown";
  }
}

static const char* cb_error_name(NSInteger code) {
  switch (code) {
    case MTLCommandBufferErrorNone: return "none";
    case MTLCommandBufferErrorInternal: return "internal";
    case MTLCommandBufferErrorTimeout: return "timeout";
    case MTLCommandBufferErrorPageFault: return "pageFault";
    case MTLCommandBufferErrorAccessRevoked: return "accessRevoked";
    case MTLCommandBufferErrorNotPermitted: return "notPermitted";
    case MTLCommandBufferErrorOutOfMemory: return "outOfMemory";
    case MTLCommandBufferErrorInvalidResource: return "invalidResource";
    default: return "other";
  }
}

int main(int argc, char** argv) {
  if (argc != 11) {
    fprintf(stderr, "usage: %s <metallib> <kernel> <mode:fresh|matched> "
        "<chunks> <trips> <spin_cap> <seed> <respond_s> <period_ns> <tag>\n",
        argv[0]);
    return 2;
  }
  const char* metallib_path = argv[1];
  const char* kernel_name = argv[2];
  int mode_matched = (0 == strcmp(argv[3], "matched"));
  int chunks = atoi(argv[4]);
  uint32_t trips = (uint32_t)strtoul(argv[5], nullptr, 10);
  uint32_t spin_cap = (uint32_t)strtoul(argv[6], nullptr, 10);
  uint32_t seed = (uint32_t)strtoul(argv[7], nullptr, 10);
  double respond_seconds = atof(argv[8]);
  double period_ns = atof(argv[9]);
  const char* tag = argv[10];

  mach_timebase_info(&g_tb);
  uint64_t period_ticks = (uint64_t)(period_ns * (double)g_tb.denom /
                                     (double)g_tb.numer);
  @autoreleasepool {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) { fprintf(stderr, "no Metal device\n"); return 2; }
    NSError* err = nil;
    NSData* libData = [NSData dataWithContentsOfFile:
        [NSString stringWithUTF8String:metallib_path]];
    if (!libData) { fprintf(stderr, "cannot read %s\n", metallib_path); return 2; }
    id<MTLLibrary> lib = [device newLibraryWithData:
        dispatch_data_create([libData bytes], [libData length], nil,
                             DISPATCH_DATA_DESTRUCTOR_DEFAULT) error:&err];
    if (!lib) { fprintf(stderr, "newLibraryWithData failed\n"); return 2; }
    id<MTLFunction> fn = [lib newFunctionWithName:
        [NSString stringWithUTF8String:kernel_name]];
    if (!fn) { fprintf(stderr, "kernel %s not found\n", kernel_name); return 2; }
    NSError* perr = nil;
    id<MTLComputePipelineState> pipe =
        [device newComputePipelineStateWithFunction:fn error:&perr];
    if (!pipe) { fprintf(stderr, "pipeline failed\n"); return 2; }
    id<MTLCommandQueue> queue = [device newCommandQueue];

    double cpu_bound_s = (respond_seconds > 0) ? respond_seconds : 20.0;
    double complete_bound_s = cpu_bound_s + 15.0;
    int fatal = 0;

    if (mode_matched) {
      // ---- matched no-exchange control --------------------------------
      // The CPU mailbox is a malloc'd, never-GPU-mapped 128-byte line with
      // the same word layout. dev_poll spins concurrently on its own buffer.
      if (chunks != 1) { fprintf(stderr, "matched mode requires chunks=1\n"); return 2; }
      void* line_raw = nullptr;
      if (posix_memalign(&line_raw, 128, W_N * sizeof(uint32_t)) != 0) {
        fprintf(stderr, "line alloc failed\n"); return 2;
      }
      memset(line_raw, 0, W_N * sizeof(uint32_t));
      std::atomic_uint* w = reinterpret_cast<std::atomic_uint*>(line_raw);
      if (!w[0].is_lock_free()) { fprintf(stderr, "atomic_uint not lock free\n"); return 2; }

      id<MTLBuffer> devbuf = [device newBufferWithLength:16 * sizeof(uint32_t)
                                                options:MTLStorageModeShared];
      if (!devbuf) { fprintf(stderr, "dev buffer alloc failed\n"); return 2; }
      memset([devbuf contents], 0, 16 * sizeof(uint32_t));

      uint64_t cseed = seed;
      uint32_t cseed32 = seed;
      // Public fixed-seed PRNG state (same recurrence the analysis
      // recomputes); words derived from the HIGH 32 bits (defect fix).
      uint64_t x = (cseed << 32) | 0x9E3779B97F4A7C15ull;
      uint32_t h = 0u;
      uint64_t responded = 0;

      uint64_t t_start = now_mach();
      id<MTLCommandBuffer> cb = [queue commandBuffer];
      id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
      [enc setComputePipelineState:pipe];
      [enc setBuffer:devbuf offset:0 atIndex:0];
      [enc setBytes:&trips length:sizeof(uint32_t) atIndex:1];
      [enc setBytes:&spin_cap length:sizeof(uint32_t) atIndex:2];
      [enc setBytes:&cseed32 length:sizeof(uint32_t) atIndex:3];
      [enc dispatchThreadgroups:MTLSizeMake(1, 1, 1)
          threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
      [enc endEncoding];
      [cb commit];

      int cpu_lost = 0;
      for (uint32_t i = 1; i <= trips; i++) {
        if ((i & 65535u) == 0) {
          double el = mach_to_ns(now_mach() - t_start) / 1e9;
          if (el > cpu_bound_s) { cpu_lost = 1; break; }
        }
        // Self-advancing seq: spin one measured mean exchange period.
        uint64_t deadline = now_mach() + period_ticks;
        while (now_mach() < deadline) {}
        // Fresh public PRNG seed words (identical generation to mode a).
        uint32_t wd[8];
        for (int j = 0; j < 7; j++) {
          x = x * 6364136223846793005ull + 1442695040888963407ull;
          wd[j] = (uint32_t)(x >> 32);   // HIGH 32 bits (defect fix)
        }
        wd[7] = (wd[0] ^ wd[1] ^ wd[2] ^ wd[3] ^ wd[4] ^ wd[5] ^ wd[6]) ^ 0xA5A5A5A5u;
        for (int j = 0; j < 8; j++) h = (h ^ wd[j]) * 16777619u;
        // Same stores as the real exchange: 8 seed words + response.
        w[W_SEED0 + 0].store(wd[0], std::memory_order_seq_cst);
        w[W_SEED0 + 1].store(wd[1], std::memory_order_seq_cst);
        w[W_SEED0 + 2].store(wd[2], std::memory_order_seq_cst);
        w[W_SEED0 + 3].store(wd[3], std::memory_order_seq_cst);
        w[W_SEED0 + 4].store(wd[4], std::memory_order_seq_cst);
        w[W_SEED0 + 5].store(wd[5], std::memory_order_seq_cst);
        w[W_SEED0 + 6].store(wd[6], std::memory_order_seq_cst);
        w[W_SEED0 + 7].store(wd[7], std::memory_order_seq_cst);
        w[W_CPU_RESP].store(i, std::memory_order_seq_cst);
        responded++;
        // The verification read the real loop performs on the GPU-published
        // hash; here the word is never GPU-written (kept for loop shape).
        uint32_t got_hash = w[W_GPU_HASH].load(std::memory_order_seq_cst);
        (void)got_hash;
      }

      int completed_in_bound = 1;
      for (;;) {
        MTLCommandBufferStatus st = [cb status];
        if (st == MTLCommandBufferStatusCompleted ||
            st == MTLCommandBufferStatusError) break;
        double el = mach_to_ns(now_mach() - t_start) / 1e9;
        if (el > complete_bound_s) { completed_in_bound = 0; break; }
        struct timespec rq = {0, 200000};
        nanosleep(&rq, nullptr);
      }
      uint32_t dev_iters = ((std::atomic_uint*)[devbuf contents])[5].load(
          std::memory_order_seq_cst);
      double gpu_s = [cb GPUStartTime], gpu_e = [cb GPUEndTime];
      double wall_s = mach_to_ns(now_mach() - t_start) / 1e9;
      int cb_errored = ([cb status] == MTLCommandBufferStatusError);
      NSInteger cb_code = cb_errored ? [[cb error] code] : 0;
      if (!completed_in_bound || cb_errored) fatal = 87;

      fprintf(stderr,
          "[matched] responded=%llu dev_poll_iters=%u dispatch=%.3fs "
          "wall=%.3fs rate=%.0f/s cb_err=%d\n",
          (unsigned long long)responded, dev_iters, gpu_e - gpu_s, wall_s,
          (wall_s > 0) ? (double)responded / wall_s : 0.0, cb_errored);

      NSDictionary* out = @{
        @"tag": [NSString stringWithUTF8String:tag],
        @"kernel": [NSString stringWithUTF8String:kernel_name],
        @"mode": @"matched",
        @"device": @{
          @"name": [device name],
          @"unifiedMemory": @([device hasUnifiedMemory]),
        },
        @"params": @{
          @"chunks": @(chunks), @"trips": @(trips), @"spin_cap": @(spin_cap),
          @"seed": @(seed), @"respond_seconds": @(respond_seconds),
          @"period_ns": @(period_ns),
        },
        @"totals": @{
          @"cpu_responded": @(responded),
          @"cpu_lost": @(cpu_lost),
          @"dev_poll_iters": @(dev_iters),
          @"command_buffer_errors": @(cb_errored ? 1 : 0),
        },
        @"chunks_arr": @[@{
          @"chunk": @(0),
          @"kernel_status": @(1),
          @"trips_done": @((uint32_t)responded),
          @"gpu_dispatch_s": @(gpu_e - gpu_s),
          @"wall_s": @(wall_s),
          @"exchanges_per_s": @((wall_s > 0) ? (double)responded / wall_s : 0.0),
          @"cb_errored": @(cb_errored),
          @"cb_error_name": [NSString stringWithUTF8String:cb_error_name(cb_code)],
          @"completed_in_bound": @(completed_in_bound),
        }],
      };
      NSError* jerr = nil;
      NSOutputStream* os = [NSOutputStream outputStreamToMemory];
      [os open];
      [NSJSONSerialization writeJSONObject:out toStream:os
          options:NSJSONWritingPrettyPrinted error:&jerr];
      [os close];
      NSData* jd = [os propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
      printf("%s\n", [[NSString alloc] initWithData:jd
          encoding:NSUTF8StringEncoding].UTF8String);
      free(line_raw);
      return fatal ? 87 : 0;
    }

    // ---- real system-scope exchange (condition a) -----------------------
    id<MTLBuffer> buf = [device newBufferWithLength:W_N * sizeof(uint32_t)
                                            options:MTLStorageModeShared];
    if (!buf) { fprintf(stderr, "buffer alloc failed\n"); return 2; }
    std::atomic_uint* w = reinterpret_cast<std::atomic_uint*>([buf contents]);
    if (!w[0].is_lock_free()) { fprintf(stderr, "atomic_uint not lock free\n"); return 2; }

    NSMutableArray<NSDictionary*>* chunkDicts = [NSMutableArray array];
    uint64_t total_trips = 0, total_future = 0, total_cks = 0, total_wrong_hash = 0;
    uint64_t total_responded = 0;
    int cap_hits = 0, lost_chunks = 0, cmd_errors = 0;

    for (int c = 0; c < chunks && !fatal; c++) {
      for (int k = 0; k < W_N; k++) w[k].store(0, std::memory_order_seq_cst);

      uint32_t cseed = seed + (uint32_t)c;
      // Public fixed-seed PRNG state; words from the HIGH 32 bits (fix).
      uint64_t x = ((uint64_t)cseed << 32) | 0x9E3779B97F4A7C15ull;
      uint32_t h = 0u;
      uint64_t responded = 0, wrong_hash = 0;
      int cpu_lost = 0; uint32_t cpu_lost_at = 0;

      uint64_t t_start = now_mach();
      id<MTLCommandBuffer> cb = [queue commandBuffer];
      id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
      [enc setComputePipelineState:pipe];
      [enc setBuffer:buf offset:0 atIndex:0];
      [enc setBytes:&trips length:sizeof(uint32_t) atIndex:1];
      [enc setBytes:&spin_cap length:sizeof(uint32_t) atIndex:2];
      [enc setBytes:&cseed length:sizeof(uint32_t) atIndex:3];
      [enc dispatchThreadgroups:MTLSizeMake(1, 1, 1)
          threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
      [enc endEncoding];
      [cb commit];

      for (uint32_t i = 1; i <= trips; i++) {
        if ((i & 65535u) == 0) {
          double el = mach_to_ns(now_mach() - t_start) / 1e9;
          if (el > cpu_bound_s) { cpu_lost = 1; cpu_lost_at = i; break; }
        }
        uint64_t spin = 0;
        uint32_t seq;
        for (;;) {
          seq = w[W_GPU_SEQ].load(std::memory_order_seq_cst);
          if (seq == i) break;
          if ((++spin & 4095u) == 0) {
            double el = mach_to_ns(now_mach() - t_start) / 1e9;
            if (el > cpu_bound_s) { cpu_lost = 1; cpu_lost_at = i; break; }
          }
        }
        if (cpu_lost) break;
        uint32_t wd[8];
        for (int j = 0; j < 7; j++) {
          x = x * 6364136223846793005ull + 1442695040888963407ull;
          wd[j] = (uint32_t)(x >> 32);   // HIGH 32 bits (defect fix)
        }
        wd[7] = (wd[0] ^ wd[1] ^ wd[2] ^ wd[3] ^ wd[4] ^ wd[5] ^ wd[6]) ^ 0xA5A5A5A5u;
        for (int j = 0; j < 8; j++) h = (h ^ wd[j]) * 16777619u;
        w[W_SEED0 + 0].store(wd[0], std::memory_order_seq_cst);
        w[W_SEED0 + 1].store(wd[1], std::memory_order_seq_cst);
        w[W_SEED0 + 2].store(wd[2], std::memory_order_seq_cst);
        w[W_SEED0 + 3].store(wd[3], std::memory_order_seq_cst);
        w[W_SEED0 + 4].store(wd[4], std::memory_order_seq_cst);
        w[W_SEED0 + 5].store(wd[5], std::memory_order_seq_cst);
        w[W_SEED0 + 6].store(wd[6], std::memory_order_seq_cst);
        w[W_SEED0 + 7].store(wd[7], std::memory_order_seq_cst);
        w[W_CPU_RESP].store(i, std::memory_order_seq_cst);
        responded++;
        uint32_t expect_hash = h;
        int saw_next = 0;
        uint32_t exit_status = 0;
        for (;;) {
          uint32_t nxt = w[W_GPU_SEQ].load(std::memory_order_seq_cst);
          if (nxt > i) { saw_next = 1; break; }
          exit_status = w[W_STATUS].load(std::memory_order_seq_cst);
          if (exit_status != 0u) break;
          if ((++spin & 4095u) == 0) {
            double el = mach_to_ns(now_mach() - t_start) / 1e9;
            if (el > cpu_bound_s) { cpu_lost = 1; cpu_lost_at = i; break; }
          }
        }
        if (cpu_lost) break;
        if (saw_next || exit_status == 1u) {
          uint32_t got_hash = w[W_GPU_HASH].load(std::memory_order_seq_cst);
          if (got_hash != expect_hash) wrong_hash++;
        }
      }

      w[W_CPU_CMD].store(1, std::memory_order_seq_cst);

      int completed_in_bound = 1;
      for (;;) {
        MTLCommandBufferStatus st = [cb status];
        if (st == MTLCommandBufferStatusCompleted ||
            st == MTLCommandBufferStatusError) break;
        double el = mach_to_ns(now_mach() - t_start) / 1e9;
        if (el > complete_bound_s) { completed_in_bound = 0; break; }
        struct timespec rq = {0, 200000};
        nanosleep(&rq, nullptr);
      }

      uint32_t kernel_status = w[W_STATUS].load(std::memory_order_seq_cst);
      uint32_t trips_done = w[W_TRIPS].load(std::memory_order_seq_cst);
      uint32_t future = w[W_FUTURE].load(std::memory_order_seq_cst);
      uint32_t cks = w[W_CKSFAIL].load(std::memory_order_seq_cst);
      uint32_t gpu_final = w[W_GPU_FINAL].load(std::memory_order_seq_cst);
      int final_ok = (trips_done > 0) ? (gpu_final == h) : 1;

      double gpu_s = [cb GPUStartTime], gpu_e = [cb GPUEndTime];
      double wall_s = mach_to_ns(now_mach() - t_start) / 1e9;
      int cb_errored = ([cb status] == MTLCommandBufferStatusError);
      NSInteger cb_code = cb_errored ? [[cb error] code] : 0;

      total_trips += trips_done;
      total_future += future;
      total_cks += cks;
      total_wrong_hash += wrong_hash;
      total_responded += responded;
      if (kernel_status == 2) cap_hits++;
      if (cpu_lost) lost_chunks++;
      if (cb_errored) cmd_errors++;

      [chunkDicts addObject:@{
        @"chunk": @(c),
        @"seed": @(cseed),
        @"kernel_status": @(kernel_status),
        @"kernel_status_name":
            [NSString stringWithUTF8String:status_name(kernel_status)],
        @"trips_done": @(trips_done),
        @"kernel_future": @(future),
        @"kernel_cks_fail": @(cks),
        @"gpu_final_hash": @(gpu_final),
        @"cpu_expected_final_hash": @(h),
        @"final_hash_ok": @(final_ok),
        @"cpu_wrong_hash": @(wrong_hash),
        @"cpu_responded": @(responded),
        @"cpu_lost": @(cpu_lost),
        @"cpu_lost_at": @(cpu_lost_at),
        @"cb_errored": @(cb_errored),
        @"cb_error_name": [NSString stringWithUTF8String:cb_error_name(cb_code)],
        @"completed_in_bound": @(completed_in_bound),
        @"gpu_dispatch_s": @(gpu_e - gpu_s),
        @"wall_s": @(wall_s),
        @"trips_per_s": @((gpu_e > gpu_s) ? (double)trips_done / (gpu_e - gpu_s) : 0.0),
      }];

      fprintf(stderr,
          "[chunk %d] kernel=%s trips=%u wrong_hash=%llu cks=%u future=%u "
          "responded=%llu final_ok=%d cpu_lost=%d cb_err=%d dispatch=%.3fs "
          "rate=%.0f/s\n",
          c, status_name(kernel_status), trips_done,
          (unsigned long long)wrong_hash, cks, future,
          (unsigned long long)responded, final_ok, cpu_lost, cb_errored,
          gpu_e - gpu_s, (gpu_e > gpu_s) ? (double)trips_done / (gpu_e - gpu_s) : 0.0);

      if (!completed_in_bound || cb_errored) fatal = 87;
    }

    NSDictionary* out = @{
      @"tag": [NSString stringWithUTF8String:tag],
      @"kernel": [NSString stringWithUTF8String:kernel_name],
      @"mode": @"fresh",
      @"device": @{
        @"name": [device name],
        @"unifiedMemory": @([device hasUnifiedMemory]),
      },
      @"params": @{
        @"chunks": @(chunks), @"trips": @(trips), @"spin_cap": @(spin_cap),
        @"seed": @(seed), @"respond_seconds": @(respond_seconds),
        @"period_ns": @(period_ns),
      },
      @"totals": @{
        @"trips_done_kernel": @(total_trips),
        @"cpu_responded": @(total_responded),
        @"cpu_wrong_hash": @(total_wrong_hash),
        @"kernel_cks_fail": @(total_cks),
        @"kernel_future": @(total_future),
        @"cap_hits": @(cap_hits),
        @"cpu_lost_chunks": @(lost_chunks),
        @"command_buffer_errors": @(cmd_errors),
      },
      @"chunks_arr": chunkDicts,
    };
    NSError* jerr = nil;
    NSOutputStream* os = [NSOutputStream outputStreamToMemory];
    [os open];
    [NSJSONSerialization writeJSONObject:out toStream:os
        options:NSJSONWritingPrettyPrinted error:&jerr];
    [os close];
    NSData* jd = [os propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
    printf("%s\n", [[NSString alloc] initWithData:jd
        encoding:NSUTF8StringEncoding].UTF8String);
    return fatal ? 87 : 0;
  }
}
