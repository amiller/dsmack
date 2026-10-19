// inject.c — CPU-only DRAM traffic injector (phase 1 + phase 2
// positive control). No GPU, no root, plain stores (Apple cores' non-temporal
// handling is undocumented, so no store hints are used).
//
// Modes:
//   inject write <buf_mib> <seconds> <rate_mbps|0> <nonce>
//     One thread writes sequential 128-byte-aligned lines into a buffer of
//     buf_mib MiB, 8 x 16-byte stores per line, every 16-byte lane set to the
//     same 64-bit value (line index ^ nonce), wrapping at the buffer size.
//     rate 0 = unpaced (full speed); rate > 0 = paced by spin-waiting on
//     mach_absolute_time so cumulative bytes track rate*elapsed (pacing only;
//     never sleeps). Prints one INJECT line with its own exact byte count.
//   inject spin <seconds> <rate_mbps|0> <nonce>
//     Identical pacing loop, store sequence and duty cycle, but the 128-byte
//     lines live in a 32 KiB L1-resident buffer, so the stores do not reach
//     DRAM. Control for CPU/pacing activity.
//   inject readflush <buf_mib>
//     memset prefault then one XOR-read pass over the buffer (the stream_cpu
//     read shape), as the inter-window cache flush: displaces dirty lines left
//     by the previous window so they cannot leak into the next one. Prints the
//     accumulated checksum so the pass cannot be elided.
//
// All output lines are single-line key=value records on stdout.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach_time.h>

typedef unsigned __int128 u128;

static mach_timebase_info_data_t g_tb;
static double mach_to_s(uint64_t t) {
  return (double)t * (double)g_tb.numer / (double)g_tb.denom / 1e9;
}

static void* alloc_aligned(size_t len) {
  void* p = NULL;
  if (posix_memalign(&p, 128, len) != 0) {
    fprintf(stderr, "inject: alloc %zu failed\n", len);
    exit(2);
  }
  memset(p, 0, len);  // prefault + first-touch before the timed loop
  return p;
}

// Paced sequential 128-byte-line writer. nlines*128 == len.
static uint64_t write_lines(volatile u128* buf, size_t nlines, double seconds,
                            double rate_mbps, uint64_t nonce) {
  uint64_t bytes = 0;
  uint64_t line = 0;
  uint64_t t0 = mach_absolute_time();
  for (;;) {
    double el = mach_to_s(mach_absolute_time() - t0);
    if (el >= seconds) break;
    if (rate_mbps > 0.0) {
      // Pacing only: spin until the budget admits the next line.
      double budget = rate_mbps * 1e6 * el;
      while ((double)bytes >= budget) {
        el = mach_to_s(mach_absolute_time() - t0);
        if (el >= seconds) goto done;
        budget = rate_mbps * 1e6 * el;
      }
    }
    uint64_t v = line ^ nonce;  // value = line index ^ window nonce
    u128 vv = ((u128)v << 64) | (u128)v;
    volatile u128* dst = buf + line * 8;
    dst[0] = vv; dst[1] = vv; dst[2] = vv; dst[3] = vv;
    dst[4] = vv; dst[5] = vv; dst[6] = vv; dst[7] = vv;
    bytes += 128;
    line = (line + 1) % nlines;
  }
done:
  return bytes;
}

int main(int argc, char** argv) {
  mach_timebase_info(&g_tb);
  if (argc == 6 && 0 == strcmp(argv[1], "write")) {
    size_t mib = (size_t)strtoul(argv[2], NULL, 10);
    double seconds = atof(argv[3]);
    double rate = atof(argv[4]);
    uint64_t nonce = (uint64_t)strtoull(argv[5], NULL, 10);
    size_t len = mib * 1024ull * 1024ull;
    volatile u128* buf = (volatile u128*)alloc_aligned(len);
    uint64_t t0 = mach_absolute_time();
    uint64_t bytes = write_lines(buf, len / 128, seconds, rate, nonce);
    double wall = mach_to_s(mach_absolute_time() - t0);
    printf("INJECT mode=write buf_mib=%zu seconds=%.3f rate_req=%.1f "
           "nonce=%llu bytes=%llu wall_s=%.6f achieved_mbps=%.3f\n",
           mib, seconds, rate, (unsigned long long)nonce,
           (unsigned long long)bytes, wall, (double)bytes / wall / 1e6);
    return 0;
  }
  if (argc == 5 && 0 == strcmp(argv[1], "spin")) {
    double seconds = atof(argv[2]);
    double rate = atof(argv[3]);
    uint64_t nonce = (uint64_t)strtoull(argv[4], NULL, 10);
    size_t len = 32 * 1024;  // 256 lines, L1-resident
    volatile u128* buf = (volatile u128*)alloc_aligned(len);
    uint64_t t0 = mach_absolute_time();
    uint64_t bytes = write_lines(buf, len / 128, seconds, rate, nonce);
    double wall = mach_to_s(mach_absolute_time() - t0);
    printf("INJECT mode=spin buf_kib=32 seconds=%.3f rate_req=%.1f "
           "nonce=%llu bytes=%llu wall_s=%.6f achieved_mbps=%.3f\n",
           seconds, rate, (unsigned long long)nonce,
           (unsigned long long)bytes, wall, (double)bytes / wall / 1e6);
    return 0;
  }
  if (argc == 3 && 0 == strcmp(argv[1], "readflush")) {
    size_t mib = (size_t)strtoul(argv[2], NULL, 10);
    size_t len = mib * 1024ull * 1024ull;
    uint8_t* buf = (uint8_t*)alloc_aligned(len);
    uint64_t* p = (uint64_t*)buf;
    size_t n = len / sizeof(uint64_t);
    uint64_t t0 = mach_absolute_time();
    uint64_t acc = 0;
    for (size_t i = 0; i < n; i++) acc ^= p[i];
    volatile uint64_t sink = acc;
    (void)sink;
    double wall = mach_to_s(mach_absolute_time() - t0);
    printf("READFLUSH buf_mib=%zu acc=%llu bytes=%llu wall_s=%.6f\n",
           mib, (unsigned long long)acc, (unsigned long long)len, wall);
    return 0;
  }
  fprintf(stderr, "usage: %s write <buf_mib> <seconds> <rate_mbps|0> <nonce>\n"
                  "       %s spin <seconds> <rate_mbps|0> <nonce>\n"
                  "       %s readflush <buf_mib>\n", argv[0], argv[0], argv[0]);
  return 2;
}
