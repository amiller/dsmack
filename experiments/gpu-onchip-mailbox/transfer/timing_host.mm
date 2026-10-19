// timing_host.mm — timing-channel host (phase C, transfer).
//
// Per symbol: the GPU clears the target word, publishes "ready" (gpu_ready=i),
// and spins (capped) counting iterations until the CPU's single CONSTANT write
// appears. The CPU observes ready, busy-waits D = d0 + s*delta_ns, then stores
// the constant TIMING_CONST — the only value it ever stores. Symbols come from
// the public fixed-seed LCG (mode rng), round-robin (mode cal), or are fixed
// (mode constD, the deterministic-delay control of leakage note E2). The GPU's
// per-symbol spin counts are exported as diagnostics; in the intended protocol
// they would be conditioned in registers and only aggregates published.
//
// Mode poll: dispatches sys_poll/dev_poll (no CPU writes) once so the
// system-scope iteration time T_iter = (GPUEnd-GPUStart)/spin_cap is measured.
//
// Exit codes: 0 = completed within bounds; 87 = anomaly (cap hit, lost
// deadline, command-buffer error) — runner must abort, no retry.
//
// argv: timing_host <metallib> <kernel> <cal|rng|constD|poll> <d0_ns>
//         <delta_ns> <alphabet> <n_symbols> <spin_cap> <seed> <respond_s>
//         <csv_out> <tag>

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
static inline uint64_t ns_to_ticks(double ns) {
  return (uint64_t)(ns * (double)g_tb.denom / (double)g_tb.numer + 0.5);
}

enum {
  W_READY = 0, W_COUNT = 1, W_CPU_WORD = 2, W_CPU_CMD = 3,
  W_STATUS = 4, W_TRIPS = 5, W_SPINS = 6, W_MAXC = 7, W_MINC = 8,
  W_LOST_AT = 9, W_N = 16
};
static const uint32_t TIMING_CONST = 0xC0FFEE01u;

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

int main(int argc, char** argv) {
  if (argc != 13) {
    fprintf(stderr, "usage: %s <metallib> <kernel> <cal|rng|constD|poll> "
        "<d0_ns> <delta_ns> <alphabet> <n_symbols> <spin_cap> <seed> "
        "<respond_s> <csv_out> <tag>\n", argv[0]);
    return 2;
  }
  const char* metallib_path = argv[1];
  const char* kernel_name = argv[2];
  char mode = argv[3][0];            // c=cal, r=rng, D=constD, p=poll
  double d0_ns = atof(argv[4]);
  double delta_ns = atof(argv[5]);
  uint32_t alphabet = (uint32_t)strtoul(argv[6], nullptr, 10);
  uint32_t n_symbols = (uint32_t)strtoul(argv[7], nullptr, 10);
  uint32_t spin_cap = (uint32_t)strtoul(argv[8], nullptr, 10);
  uint32_t seed = (uint32_t)strtoul(argv[9], nullptr, 10);
  double respond_seconds = atof(argv[10]);
  const char* csv_path = argv[11];
  const char* tag = argv[12];

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
    id<MTLBuffer> buf = [device newBufferWithLength:W_N * sizeof(uint32_t)
                                             options:MTLStorageModeShared];
    if (!buf) { fprintf(stderr, "buffer alloc failed\n"); return 2; }
    std::atomic_uint* w = reinterpret_cast<std::atomic_uint*>([buf contents]);

    FILE* csv = fopen(csv_path, "w");
    if (!csv) { fprintf(stderr, "cannot open %s\n", csv_path); return 2; }
    fprintf(csv, "i,s,D_ns,count,t_ready_ns,t_write_ns\n");

    for (int k = 0; k < W_N; k++) w[k].store(0, std::memory_order_seq_cst);

    uint64_t t_start = now_mach();
    id<MTLCommandBuffer> cb = [queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:pipe];
    [enc setBuffer:buf offset:0 atIndex:0];
    uint32_t max_trips = (mode == 'p') ? 1u : n_symbols;
    [enc setBytes:&max_trips length:sizeof(uint32_t) atIndex:1];
    [enc setBytes:&spin_cap length:sizeof(uint32_t) atIndex:2];
    [enc setBytes:&seed length:sizeof(uint32_t) atIndex:3];
    [enc dispatchThreadgroups:MTLSizeMake(1, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
    [enc endEncoding];
    [cb commit];

    int fatal = 0;

    if (mode == 'p') {
      // T_iter probe: never write; wait for completion within bounds.
      double bound = respond_seconds > 0 ? respond_seconds : 25.0;
      for (;;) {
        MTLCommandBufferStatus st = [cb status];
        if (st == MTLCommandBufferStatusCompleted ||
            st == MTLCommandBufferStatusError) break;
        if (mach_to_ns(now_mach() - t_start) / 1e9 > bound) break;
        struct timespec rq = {0, 200000};
        nanosleep(&rq, nullptr);
      }
      double gpu_s = [cb GPUStartTime], gpu_e = [cb GPUEndTime];
      int cb_errored = ([cb status] == MTLCommandBufferStatusError);
      uint32_t iters = w[W_COUNT].load(std::memory_order_seq_cst);
      double t_iter_ns = (gpu_e > gpu_s) ? (gpu_e - gpu_s) * 1e9 / iters : 0.0;
      printf("POLL {\"kernel\":\"%s\",\"spin_cap\":%u,\"iters\":%u,"
             "\"gpu_dispatch_s\":%.6f,\"t_iter_ns\":%.3f,\"cb_errored\":%d,"
             "\"kernel_status\":\"%s\",\"desc\":\"%s\"}\n",
             kernel_name, spin_cap, iters, gpu_e - gpu_s, t_iter_ns,
             cb_errored, status_name(w[W_STATUS].load(std::memory_order_seq_cst)),
             cb_errored ? [[[cb error] localizedDescription] UTF8String] : "");
      fclose(csv);
      return (cb_errored || iters == 0) ? 87 : 0;
    }

    // Symbol channel. Public fixed-seed PRNG (same recurrence as phase B).
    uint64_t x = ((uint64_t)seed << 32) | 0x9E3779B97F4A7C15ull;
    double cpu_bound_s = (respond_seconds > 0) ? respond_seconds : 25.0;
    uint32_t done = 0;
    int cpu_lost = 0;
    uint32_t lost_at = 0;
    uint32_t fixed_s = alphabet / 2;   // constD control symbol
    // Calibration accumulators (cal mode): sum/n per symbol + min/max.
    double* ssum = (double*)calloc(alphabet ? alphabet : 1, sizeof(double));
    uint64_t* scnt = (uint64_t*)calloc(alphabet ? alphabet : 1, sizeof(uint64_t));
    uint32_t* smin = (uint32_t*)malloc(sizeof(uint32_t) * (alphabet ? alphabet : 1));
    uint32_t* smax = (uint32_t*)malloc(sizeof(uint32_t) * (alphabet ? alphabet : 1));
    for (uint32_t j = 0; j < alphabet; j++) { smin[j] = 0xFFFFFFFFu; smax[j] = 0; }

    for (uint32_t i = 1; i <= n_symbols; i++) {
      // 1. Wait for GPU to arm trip i.
      uint32_t ready;
      uint64_t spin = 0;
      for (;;) {
        ready = w[W_READY].load(std::memory_order_seq_cst);
        if (ready == i) break;
        uint32_t st = w[W_STATUS].load(std::memory_order_seq_cst);
        if (st != 0u) break;   // kernel exited early: fatal below
        if ((++spin & 4095u) == 0 &&
            mach_to_ns(now_mach() - t_start) / 1e9 > cpu_bound_s) {
          cpu_lost = 1; lost_at = i; break;
        }
      }
      if (cpu_lost) break;
      uint32_t st_early = w[W_STATUS].load(std::memory_order_seq_cst);
      if (ready != i) {
        fprintf(stderr, "[timing] kernel exited early at trip %u: status=%s\n",
                i, status_name(st_early));
        fatal = 87;
        break;
      }
      uint64_t t_ready = now_mach();
      // 2. Symbol schedule and delay.
      uint32_t s;
      if (mode == 'c') {
        s = (i - 1) % alphabet;
      } else if (mode == 'r') {
        x = x * 6364136223846793005ull + 1442695040888963407ull;
        s = (uint32_t)((x >> 32) % alphabet);
      } else {
        s = fixed_s;
      }
      double D_ns = d0_ns + (double)s * delta_ns;
      uint64_t deadline = t_ready + ns_to_ticks(D_ns);
      while (now_mach() < deadline) { /* calibrated busy-wait */ }
      // 3. The single constant write — the only CPU store in the channel.
      w[W_CPU_WORD].store(TIMING_CONST, std::memory_order_seq_cst);
      uint64_t t_write = now_mach();
      done = i;
      // 4. Wait for the GPU to arm trip i+1 (its count for trip i is then
      //    stable), then record. On the last trip, wait for kernel exit.
      uint64_t spin2 = 0;
      for (;;) {
        uint32_t nxt = w[W_READY].load(std::memory_order_seq_cst);
        if (nxt > i) break;
        uint32_t st = w[W_STATUS].load(std::memory_order_seq_cst);
        if (st != 0u) break;
        if ((++spin2 & 4095u) == 0 &&
            mach_to_ns(now_mach() - t_start) / 1e9 > cpu_bound_s) {
          cpu_lost = 1; lost_at = i; break;
        }
      }
      if (cpu_lost) break;
      uint32_t count = w[W_COUNT].load(std::memory_order_seq_cst);
      fprintf(csv, "%u,%u,%.0f,%u,%.0f,%.0f\n", i, s, D_ns, count,
              mach_to_ns(t_ready - t_start), mach_to_ns(t_write - t_start));
      if (mode == 'c' && s < alphabet) {
        ssum[s] += count; scnt[s]++;
        if (count < smin[s]) smin[s] = count;
        if (count > smax[s]) smax[s] = count;
      }
    }
    fflush(csv);

    // Stop the kernel if it is still spinning, then wait within bounds.
    w[W_CPU_CMD].store(1, std::memory_order_seq_cst);
    double complete_bound_s = cpu_bound_s + 10.0;
    int completed_in_bound = 1;
    for (;;) {
      MTLCommandBufferStatus st = [cb status];
      if (st == MTLCommandBufferStatusCompleted ||
          st == MTLCommandBufferStatusError) break;
      if (mach_to_ns(now_mach() - t_start) / 1e9 > complete_bound_s) {
        completed_in_bound = 0; break;
      }
      struct timespec rq = {0, 200000};
      nanosleep(&rq, nullptr);
    }
    fclose(csv);

    uint32_t kernel_status = w[W_STATUS].load(std::memory_order_seq_cst);
    uint32_t trips_done = w[W_TRIPS].load(std::memory_order_seq_cst);
    uint32_t maxc = w[W_MAXC].load(std::memory_order_seq_cst);
    uint32_t minc = w[W_MINC].load(std::memory_order_seq_cst);
    int cb_errored = ([cb status] == MTLCommandBufferStatusError);
    double gpu_s = [cb GPUStartTime], gpu_e = [cb GPUEndTime];
    double wall_s = mach_to_ns(now_mach() - t_start) / 1e9;

    fprintf(stderr, "[timing] mode=%c A=%u d0=%.0fns delta=%.0fns symbols=%u "
        "done=%u kernel=%s trips=%u cb_err=%d wall=%.3f gpu=%.3f\n",
        mode, alphabet, d0_ns, delta_ns, n_symbols, done,
        status_name(kernel_status), trips_done, cb_errored, wall_s,
        gpu_e - gpu_s);
    if (mode == 'c') {
      for (uint32_t j = 0; j < alphabet; j++) {
        if (scnt[j]) {
          fprintf(stderr, "  [cal] s=%u n=%llu mean=%.2f min=%u max=%u\n",
              j, (unsigned long long)scnt[j], ssum[j] / (double)scnt[j],
              smin[j], smax[j]);
        }
      }
    }
    printf("TIMING {\"tag\":\"%s\",\"mode\":\"%s\",\"alphabet\":%u,"
        "\"d0_ns\":%.0f,\"delta_ns\":%.0f,\"n_symbols\":%u,\"done\":%u,"
        "\"kernel_status\":\"%s\",\"trips_done\":%u,\"max_count\":%u,"
        "\"min_count\":%u,\"cb_errored\":%d,\"completed_in_bound\":%d,"
        "\"cpu_lost\":%d,\"lost_at\":%u,\"wall_s\":%.6f,"
        "\"gpu_dispatch_s\":%.6f,\"symbols_per_s\":%.1f}\n",
        tag, mode == 'c' ? "cal" : (mode == 'r' ? "rng" : "constD"),
        alphabet, d0_ns, delta_ns, n_symbols, done,
        status_name(kernel_status), trips_done, maxc, minc, cb_errored,
        completed_in_bound, cpu_lost, lost_at, wall_s, gpu_e - gpu_s,
        wall_s > 0 ? done / wall_s : 0.0);

    free(ssum); free(scnt); free(smin); free(smax);
    if (!completed_in_bound || cb_errored || cpu_lost) fatal = 87;
    if (kernel_status == 2u) {   // cap hit: write never seen — mechanism failure
      fprintf(stderr, "[timing] CAP HIT at trip %u — aborting\n",
              w[W_LOST_AT].load(std::memory_order_seq_cst));
      fatal = 87;
    }
    return fatal ? 87 : 0;
  }
}
