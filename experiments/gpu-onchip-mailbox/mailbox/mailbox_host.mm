// Host side of the bounded CPU<->GPU mailbox mechanism test.
//
// Loads the precompiled mailbox.metallib (built by phaseB/run_phaseB.sh with
// the Mac mini's pinned Metal toolchain), dispatches ONE single-threadgroup
// kernel at a time and talks to it through a shared MTLBuffer with
// std::atomic loads/stores, mirroring the MLX CPU side (mlx fence.cpp:
// std::atomic_uint on MTLBuffer.contents()).
//
// Exit codes: 0 = completed within bounds; 87 = GPU did not return within its
// bound / accessRevoked observed (runner scripts must abort, no retry).
//
// argv: mailbox_host <metallib> <kernel> <default|dsbsy> <chunks>
//         <trips_per_chunk> <spin_cap> <seed> <respond_seconds|0=all>
//         <record_lat 0|1> <latency_csv> <tag>

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mach/mach_time.h>
#include <sys/time.h>

static mach_timebase_info_data_t g_tb;
static inline double mach_to_ns(uint64_t t) {
  return (double)t * (double)g_tb.numer / (double)g_tb.denom;
}
static inline uint64_t now_mach() { return mach_absolute_time(); }

static inline void dsb_sy(void) { __asm__ volatile("dsb sy" ::: "memory"); }

// Word indices (see ../README.md)
enum {
  W_GPU_SEQ = 0, W_GPU_VAL = 1, W_CPU_RESP = 2, W_CPU_ECHO = 3, W_CPU_CMD = 4,
  W_STATUS = 5, W_TRIPS = 6, W_SPINS = 7, W_WRONG = 8, W_FUTURE = 9, W_LOST_AT = 10,
  W_N = 16
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

static const char* cb_status_name(MTLCommandBufferStatus st) {
  switch (st) {
    case MTLCommandBufferStatusNotEnqueued: return "notEnqueued";
    case MTLCommandBufferStatusEnqueued: return "enqueued";
    case MTLCommandBufferStatusCommitted: return "committed";
    case MTLCommandBufferStatusScheduled: return "scheduled";
    case MTLCommandBufferStatusCompleted: return "completed";
    case MTLCommandBufferStatusError: return "error";
    default: return "other";  // committed/scheduled both mean in-flight here
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
    case MTLCommandBufferErrorMemoryless: return "memoryless";
    case MTLCommandBufferErrorStackOverflow: return "stackOverflow";
    default: return "other";
  }
}

struct ChunkResult {
  int chunk;
  uint32_t kernel_status, trips_done, spins, wrong, future, lost_at;
  uint64_t cpu_trips_responded;
  uint64_t cpu_wrong;
  int cpu_lost;            // 1 if CPU timed out waiting for gpu_seq
  uint32_t cpu_lost_at;
  const char* cb_status;   // final command buffer status name
  int cb_errored;          // 1 if error status
  NSInteger cb_error_code;
  const char* cb_error_name_str;
  char cb_error_desc[256];
  double gpu_start_s, gpu_end_s;   // [cmdbuf GPUStartTime/GPUEndTime]
  double wall_s;
};

int main(int argc, char** argv) {
  if (argc != 12) {
    fprintf(stderr, "usage: %s <metallib> <kernel> <default|dsbsy> <chunks> "
        "<trips_per_chunk> <spin_cap> <seed> <respond_seconds|0=all> "
        "<record_lat 0|1> <latency_csv> <tag>\n", argv[0]);
    return 2;
  }
  const char* metallib_path = argv[1];
  const char* kernel_name = argv[2];
  int mode_dsbsy = (0 == strcmp(argv[3], "dsbsy"));
  int chunks = atoi(argv[4]);
  uint32_t trips = (uint32_t)strtoul(argv[5], nullptr, 10);
  uint32_t spin_cap = (uint32_t)strtoul(argv[6], nullptr, 10);
  uint32_t seed = (uint32_t)strtoul(argv[7], nullptr, 10);
  double respond_seconds = atof(argv[8]);
  int record_lat = atoi(argv[9]);
  const char* lat_csv_path = argv[10];
  const char* tag = argv[11];

  mach_timebase_info(&g_tb);
  @autoreleasepool {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) { fprintf(stderr, "no Metal device\n"); return 2; }

    NSError* err = nil;
    NSData* libData = [NSData dataWithContentsOfFile:
        [NSString stringWithUTF8String:metallib_path]];
    if (!libData) { fprintf(stderr, "cannot read %s\n", metallib_path); return 2; }
    id<MTLLibrary> lib = [device newLibraryWithData:
        dispatch_data_create([libData bytes], [libData length], nil,
                             DISPATCH_DATA_DESTRUCTOR_DEFAULT)
        error:&err];
    if (!lib) { fprintf(stderr, "newLibraryWithData failed: %s\n",
        err ? [[err localizedDescription] UTF8String] : "?"); return 2; }
    id<MTLFunction> fn = [lib newFunctionWithName:
        [NSString stringWithUTF8String:kernel_name]];
    if (!fn) { fprintf(stderr, "kernel %s not found\n", kernel_name); return 2; }

    NSError* perr = nil;
    id<MTLComputePipelineState> pipe =
        [device newComputePipelineStateWithFunction:fn error:&perr];
    if (!pipe) { fprintf(stderr, "pipeline failed: %s\n",
        perr ? [[perr localizedDescription] UTF8String] : "?"); return 2; }

    id<MTLCommandQueue> queue = [device newCommandQueue];
    id<MTLBuffer> buf = [device newBufferWithLength:W_N * sizeof(uint32_t)
                                             options:MTLStorageModeShared];
    if (!buf) { fprintf(stderr, "buffer alloc failed\n"); return 2; }
    std::atomic_uint* w = reinterpret_cast<std::atomic_uint*>([buf contents]);
    if (!w[0].is_lock_free()) { fprintf(stderr, "atomic_uint not lock free\n"); return 2; }

    FILE* lat_csv = nullptr;
    if (record_lat) {
      lat_csv = fopen(lat_csv_path, "w");
      if (!lat_csv) { fprintf(stderr, "cannot open %s\n", lat_csv_path); return 2; }
      fprintf(lat_csv, "trip_ns\n");
    }

    // Bounds (seconds, monotonic wall clock from start of each chunk):
    //   cpu respond loop  : respond_seconds if given, else 20 s
    //   completion wait   : +6 s (phaseB) / +15 s (duration steps)
    // One chunk per invocation in phaseB, so the outer 30 s watchdog always
    // dominates these.
    double cpu_bound_s = (respond_seconds > 0) ? respond_seconds : 20.0;
    double complete_bound_s = cpu_bound_s + ((respond_seconds > 0) ? 15.0 : 6.0);

    NSMutableArray<NSDictionary*>* chunkDicts = [NSMutableArray array];
    int fatal = 0;  // 87 condition

    uint64_t total_trips = 0, total_wrong_kernel = 0, total_future = 0;
    uint64_t total_wrong_cpu = 0;
    int cap_hits = 0, lost_chunks = 0, cmd_errors = 0;

    for (int c = 0; c < chunks && !fatal; c++) {
      // Reset the mailbox while the GPU is idle.
      for (int k = 0; k < W_N; k++) w[k].store(0, std::memory_order_seq_cst);
      w[W_CPU_CMD].store(0, std::memory_order_seq_cst);

      uint32_t cseed = seed + (uint32_t)c;
      uint64_t x = ((uint64_t)cseed << 32) | 0x9E3779B97F4A7C15ull;
      uint64_t responded = 0, cpu_wrong = 0;
      int cpu_lost = 0; uint32_t cpu_lost_at = 0;

      struct timeval tv0; gettimeofday(&tv0, nullptr);
      uint64_t t_start = now_mach();

      id<MTLCommandBuffer> cb = [queue commandBuffer];
      id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
      [enc setComputePipelineState:pipe];
      [enc setBuffer:buf offset:0 atIndex:0];
      [enc setBytes:&trips length:sizeof(uint32_t) atIndex:1];
      [enc setBytes:&spin_cap length:sizeof(uint32_t) atIndex:2];
      [enc setBytes:&cseed length:sizeof(uint32_t) atIndex:3];
      // Single threadgroup, single thread, exactly as MLX dispatches fence_wait.
      [enc dispatchThreadgroups:MTLSizeMake(1, 1, 1)
          threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
      [enc endEncoding];
      [cb commit];

      uint64_t t_prev = now_mach();
      // CPU respond loop. The deadline is enforced both in the slow path
      // (while waiting for a trip) and in the fast lockstep path (every
      // 65536 trips), so a duration step cannot overrun its respond bound.
      for (uint32_t i = 1; i <= trips; i++) {
        if ((i & 65535u) == 0) {
          double el = mach_to_ns(now_mach() - t_start) / 1e9;
          if (el > cpu_bound_s) { cpu_lost = 1; cpu_lost_at = i; break; }
        }
        // Wait for gpu_seq == i (bounded by chunk deadline).
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
        uint32_t val = w[W_GPU_VAL].load(std::memory_order_seq_cst);
        x = x * 6364136223846793005ull + 1442695040888963407ull;
        uint32_t expect = (uint32_t)(x & 0xffffffffull);
        if (val != expect) cpu_wrong++;
        uint32_t echo = (val ^ 0xA5A5A5A5u) + i;
        w[W_CPU_ECHO].store(echo, std::memory_order_seq_cst);
        w[W_CPU_RESP].store(i, std::memory_order_seq_cst);
        if (mode_dsbsy) dsb_sy();
        if (record_lat && lat_csv) {
          uint64_t t = now_mach();
          fprintf(lat_csv, "%llu\n",
              (unsigned long long)(mach_to_ns(t - t_prev) + 0.5));
          t_prev = t;
        } else if ((responded & 0xffffu) == 0) {
          t_prev = now_mach();
        }
        responded++;
      }

      // Tell the kernel to stop; wait for completion within bounds.
      w[W_CPU_CMD].store(1, std::memory_order_seq_cst);
      if (mode_dsbsy) dsb_sy();

      int completed_in_bound = 1;
      for (;;) {
        MTLCommandBufferStatus st = [cb status];
        if (st == MTLCommandBufferStatusCompleted ||
            st == MTLCommandBufferStatusError) break;
        double el = mach_to_ns(now_mach() - t_start) / 1e9;
        if (el > complete_bound_s) { completed_in_bound = 0; break; }
        struct timespec rq = {0, 200000};  // 200 us
        nanosleep(&rq, nullptr);
      }

      ChunkResult r = {};
      r.chunk = c;
      r.kernel_status = w[W_STATUS].load(std::memory_order_seq_cst);
      r.trips_done = w[W_TRIPS].load(std::memory_order_seq_cst);
      r.spins = w[W_SPINS].load(std::memory_order_seq_cst);
      r.wrong = w[W_WRONG].load(std::memory_order_seq_cst);
      r.future = w[W_FUTURE].load(std::memory_order_seq_cst);
      r.lost_at = w[W_LOST_AT].load(std::memory_order_seq_cst);
      r.cpu_trips_responded = responded;
      r.cpu_wrong = cpu_wrong;
      r.cpu_lost = cpu_lost;
      r.cpu_lost_at = cpu_lost_at;
      r.cb_status = cb_status_name([cb status]);
      r.cb_errored = ([cb status] == MTLCommandBufferStatusError);
      r.cb_error_code = r.cb_errored ? [[cb error] code] : 0;
      r.cb_error_name_str = cb_error_name(r.cb_error_code);
      if (r.cb_errored) {
        NSString* d = [[cb error] localizedDescription];
        snprintf(r.cb_error_desc, sizeof(r.cb_error_desc), "%s",
            d ? [d UTF8String] : "");
      } else {
        r.cb_error_desc[0] = 0;
      }
      r.gpu_start_s = [cb GPUStartTime];
      r.gpu_end_s = [cb GPUEndTime];
      uint64_t t_end = now_mach();
      r.wall_s = mach_to_ns(t_end - t_start) / 1e9;

      total_trips += r.trips_done;
      total_wrong_kernel += r.wrong;
      total_future += r.future;
      total_wrong_cpu += cpu_wrong;
      if (r.kernel_status == 2) cap_hits++;
      if (cpu_lost) lost_chunks++;
      if (r.cb_errored) cmd_errors++;

      [chunkDicts addObject:@{
        @"chunk": @(c),
        @"seed": @(cseed),
        @"kernel_status": @(r.kernel_status),
        @"kernel_status_name": [NSString stringWithUTF8String:status_name(r.kernel_status)],
        @"trips_done": @(r.trips_done),
        @"spin_iters_approx": @(r.spins),
        @"kernel_wrong_echo": @(r.wrong),
        @"kernel_future_resp": @(r.future),
        @"kernel_lost_at": @(r.lost_at),
        @"cpu_trips_responded": @(r.cpu_trips_responded),
        @"cpu_wrong_val": @(r.cpu_wrong),
        @"cpu_lost_wakeup": @(r.cpu_lost),
        @"cpu_lost_at": @(r.cpu_lost_at),
        @"cb_status": [NSString stringWithUTF8String:r.cb_status],
        @"cb_errored": @(r.cb_errored),
        @"cb_error_code": @(r.cb_error_code),
        @"cb_error_name": [NSString stringWithUTF8String:r.cb_error_name_str],
        @"cb_error_desc": [NSString stringWithUTF8String:r.cb_error_desc],
        @"completed_in_bound": @(completed_in_bound),
        @"gpu_start_s": @(r.gpu_start_s),
        @"gpu_end_s": @(r.gpu_end_s),
        @"gpu_dispatch_s": @(r.gpu_end_s - r.gpu_start_s),
        @"wall_s": @(r.wall_s),
      }];

      fprintf(stderr,
          "[chunk %d] kernel=%s trips=%u spins~%u wrong=%u future=%u "
          "responded=%llu cpu_wrong=%llu cpu_lost=%d cb=%s%s%s completed=%d "
          "gpu_dispatch=%.3fs wall=%.3fs\n",
          c, status_name(r.kernel_status), r.trips_done, r.spins, r.wrong,
          r.future, (unsigned long long)r.cpu_trips_responded,
          (unsigned long long)r.cpu_wrong, r.cpu_lost, r.cb_status,
          r.cb_errored ? " err=" : "", r.cb_errored ? r.cb_error_desc : "",
          completed_in_bound, r.gpu_end_s - r.gpu_start_s, r.wall_s);

      if (!completed_in_bound || r.cb_errored) {
        // Record read-only state and bail out of all GPU work.
        fatal = 87;
      }
    }

    if (lat_csv) fclose(lat_csv);

    NSDictionary* out = @{
      @"tag": [NSString stringWithUTF8String:tag],
      @"kernel": [NSString stringWithUTF8String:kernel_name],
      @"cpu_mode": [NSString stringWithUTF8String:mode_dsbsy ? "dsbsy" : "default"],
      @"device": @{
        @"name": [device name],
        @"registryID": [device respondsToSelector:@selector(registryID)]
            ? @((unsigned long long)[device registryID]) : @"n/a",
        @"unifiedMemory": @([device hasUnifiedMemory]),
        @"maxThreadgroupThreads": @((unsigned long)[pipe maxTotalThreadsPerThreadgroup]),
        @"family_1007_apple6": @([device supportsFamily:(MTLGPUFamily)1007]),
        @"family_1008_apple7": @([device supportsFamily:(MTLGPUFamily)1008]),
        @"family_1009_apple8": @([device supportsFamily:(MTLGPUFamily)1009]),
        @"family_1010_apple9": @([device supportsFamily:(MTLGPUFamily)1010]),
        @"family_1011_apple10": @([device supportsFamily:(MTLGPUFamily)1011]),
        @"family_1012_apple11": @([device supportsFamily:(MTLGPUFamily)1012]),
        @"family_5001_metal3": @([device supportsFamily:(MTLGPUFamily)5001]),
      },
      @"params": @{
        @"chunks": @(chunks), @"trips": @(trips), @"spin_cap": @(spin_cap),
        @"seed": @(seed), @"respond_seconds": @(respond_seconds),
        @"record_lat": @(record_lat),
      },
      @"totals": @{
        @"trips_done_kernel": @(total_trips),
        @"kernel_wrong_echo": @(total_wrong_kernel),
        @"kernel_future_resp": @(total_future),
        @"cpu_wrong_val": @(total_wrong_cpu),
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
