// iomon.m — unprivileged IOReport channel enumerator and periodic sampler
// (transfer task, phase A: find a DRAM/memory-controller traffic
// counter readable without root on M4 Pro / macOS 27.0).
//
// The public SDK ships libIOReport.tbd but no user-space header, so the
// prototypes below are declared here explicitly, following the usage pattern
// of open-source tools (freedomtan/test-ioreport, macmon, NeoAsitop's DCS
// memory-bandwidth readout). Only the default (unprivileged) report tap is
// used: IOReportCreateSubscription(NULL, ...). No entitlement is requested.
//
// usage:
//   iomon list — one sample over ALL channels; print every channel's
//               identity + raw value
//   iomon watch <groupRegex> <subgroupRegex> <interval_ms> <nsamples>
//              <outCsv> <metaOut>
//             — subscribe to all channels, sample at fixed cadence, emit CSV
//               rows for channels whose group AND subgroup match the
//               (case-insensitive) regexes (empty subgroupRegex = all).
//               Values are cumulative per-state event/histogram counts as
//               reported; downstream analysis takes deltas and computes
//               level-weighted means. Flushes every row; exits cleanly on
//               SIGTERM/SIGINT.
//
// CSV: unix_ms,group,subgroup,channel,state,value
// meta: one line per emitted key: driver | group | subgroup | channel | state |
//       format | unit-label

#import <Foundation/Foundation.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <mach/mach_time.h>
#include <unistd.h>

typedef struct IOReportSubscriptionRef* IOReportSubscriptionRef;
typedef CFDictionaryRef IOReportSampleRef;

extern CFMutableDictionaryRef IOReportCopyChannelsInGroup(NSString*, NSString*, uint64_t, uint64_t, uint64_t);
extern CFMutableDictionaryRef IOReportCopyAllChannels(uint64_t, uint64_t);
extern IOReportSubscriptionRef IOReportCreateSubscription(void*, CFMutableDictionaryRef, CFMutableDictionaryRef*, uint64_t, CFTypeRef);
extern CFDictionaryRef IOReportCreateSamples(IOReportSubscriptionRef, CFMutableDictionaryRef, CFTypeRef);
typedef int (^ioreportiterateblock)(IOReportSampleRef);
extern void IOReportIterate(CFDictionaryRef, ioreportiterateblock);
extern int IOReportChannelGetFormat(CFDictionaryRef);
extern long IOReportSimpleGetIntegerValue(CFDictionaryRef, int);
extern uint64_t IOReportArrayGetValueAtIndex(CFDictionaryRef, int);
extern NSString* IOReportChannelGetDriverName(CFDictionaryRef);
extern NSString* IOReportChannelGetChannelName(CFDictionaryRef);
extern int IOReportStateGetCount(CFDictionaryRef);
extern uint64_t IOReportStateGetResidency(CFDictionaryRef, int);
extern NSString* IOReportStateGetNameForIndex(CFDictionaryRef, int);
extern NSString* IOReportChannelGetUnitLabel(CFDictionaryRef);
extern NSString* IOReportChannelGetGroup(CFDictionaryRef);
extern NSString* IOReportChannelGetSubGroup(CFDictionaryRef);

enum {
  kIOReportFormatSimple = 1,
  kIOReportFormatState = 2,
  kIOReportFormatHistogram = 3,
  kIOReportFormatSimpleArray = 4,
};

static mach_timebase_info_data_t g_tb;
static double mach_to_ns(uint64_t t) {
  return (double)t * (double)g_tb.numer / (double)g_tb.denom;
}
static uint64_t now_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000ull + tv.tv_usec / 1000ull;
}

static volatile sig_atomic_t g_stop = 0;
static void on_term(int sig) { (void)sig; g_stop = 1; }

// Emits every readable channel once (identity + current raw value).
static int list_all(void) {
  CFMutableDictionaryRef channels = IOReportCopyAllChannels(0, 0);
  if (!channels) { fprintf(stderr, "iomon: IOReportCopyAllChannels -> NULL\n"); return 3; }
  CFMutableDictionaryRef subbed = NULL;
  IOReportSubscriptionRef sub = IOReportCreateSubscription(NULL, channels, &subbed, 0, NULL);
  if (!sub) { fprintf(stderr, "iomon: subscription failed (NULL)\n"); return 3; }
  CFDictionaryRef samples = IOReportCreateSamples(sub, subbed, NULL);
  if (!samples) { fprintf(stderr, "iomon: IOReportCreateSamples -> NULL\n"); return 3; }
  printf("driver\tgroup\tsubgroup\tchannel\tformat\tstate\tunitlabel\tvalue\n");
  IOReportIterate(samples, ^(IOReportSampleRef ch) {
    NSString* drv = IOReportChannelGetDriverName(ch);
    NSString* grp = IOReportChannelGetGroup(ch);
    NSString* sub = IOReportChannelGetSubGroup(ch);
    NSString* name = IOReportChannelGetChannelName(ch);
    NSString* label = IOReportChannelGetUnitLabel(ch);
    int fmt = IOReportChannelGetFormat(ch);
    const char* fmts[] = {"?", "simple", "state", "hist", "arr"};
    switch (fmt) {
      case kIOReportFormatSimple:
        printf("%s\t%s\t%s\t%s\t%s\t-\t%s\t%ld\n", drv.UTF8String, grp.UTF8String,
               sub.UTF8String, name.UTF8String, fmts[fmt & 7],
               label.UTF8String, IOReportSimpleGetIntegerValue(ch, 0));
        break;
      case kIOReportFormatState: {
        int n = IOReportStateGetCount(ch);
        for (int i = 0; i < n; i++) {
          printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%llu\n", drv.UTF8String, grp.UTF8String,
                 sub.UTF8String, name.UTF8String, fmts[fmt & 7],
                 [IOReportStateGetNameForIndex(ch, i) UTF8String],
                 label.UTF8String,
                 (unsigned long long)IOReportStateGetResidency(ch, i));
        }
        break;
      }
      default:
        printf("%s\t%s\t%s\t%s\t%s\t-\t%s\t(unhandled)\n", drv.UTF8String, grp.UTF8String,
               sub.UTF8String, name.UTF8String, fmts[fmt & 7], label.UTF8String);
        break;
    }
    return 0;
  });
  fflush(stdout);
  return 0;
}

int main(int argc, char** argv) {
  mach_timebase_info(&g_tb);
  @autoreleasepool {
    if (argc == 2 && 0 == strcmp(argv[1], "list")) return list_all();
    if (argc != 8 || 0 != strcmp(argv[1], "watch")) {
      fprintf(stderr, "usage: %s list | watch <groupRegex> <subgroupRegex> "
              "<interval_ms> <nsamples> <outCsv> <metaOut>\n", argv[0]);
      return 2;
    }
    const char* regex = argv[2];
    const char* subregex = argv[3];
    long interval_ms = strtol(argv[4], NULL, 10);
    long nsamples = strtol(argv[5], NULL, 10);
    FILE* csv = fopen(argv[6], "w");
    FILE* meta = fopen(argv[7], "w");
    if (!csv || !meta) { fprintf(stderr, "iomon: cannot open outputs\n"); return 2; }

    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);

    CFMutableDictionaryRef channels = IOReportCopyAllChannels(0, 0);
    if (!channels) { fprintf(stderr, "iomon: IOReportCopyAllChannels -> NULL\n"); return 3; }
    CFMutableDictionaryRef subbed = NULL;
    IOReportSubscriptionRef sub = IOReportCreateSubscription(NULL, channels, &subbed, 0, NULL);
    if (!sub) { fprintf(stderr, "iomon: subscription failed (NULL)\n"); return 3; }

    NSRegularExpression* re = [NSRegularExpression regularExpressionWithPattern:
        [NSString stringWithUTF8String:regex]
        options:NSRegularExpressionCaseInsensitive error:nil];
    NSRegularExpression* sre = nil;
    if (subregex[0]) {
      sre = [NSRegularExpression regularExpressionWithPattern:
          [NSString stringWithUTF8String:subregex]
          options:NSRegularExpressionCaseInsensitive error:nil];
    }

    __block FILE* csvF = csv;
    __block FILE* metaF = meta;
    __block BOOL metaWritten = NO;

    uint64_t t_start = mach_absolute_time();
    for (long k = 0; k < nsamples && !g_stop; k++) {
      CFDictionaryRef samples = IOReportCreateSamples(sub, subbed, NULL);
      if (!samples) { fprintf(stderr, "iomon: sample %ld failed\n", k); break; }
      uint64_t sample_mach = mach_absolute_time();
      uint64_t ms = now_ms();
      double lat_ms = mach_to_ns(sample_mach - t_start) / 1e6;
      IOReportIterate(samples, ^(IOReportSampleRef ch) {
        NSString* grp = IOReportChannelGetGroup(ch);
        if (![re numberOfMatchesInString:grp options:0 range:NSMakeRange(0, grp.length)]) return 0;
        NSString* subg = IOReportChannelGetSubGroup(ch);
        if (sre && ![sre numberOfMatchesInString:subg options:0
                              range:NSMakeRange(0, subg.length)]) return 0;
        NSString* name = IOReportChannelGetChannelName(ch);
        int fmt = IOReportChannelGetFormat(ch);
        if (fmt == kIOReportFormatSimple) {
          long v = IOReportSimpleGetIntegerValue(ch, 0);
          fprintf(csvF, "%llu,%s,%s,%s,-,%ld\n", (unsigned long long)ms,
                  grp.UTF8String, subg.UTF8String, name.UTF8String, v);
          if (!metaWritten) {
            fprintf(metaF, "%s | %s | %s | %s | - | simple | %s\n",
                    IOReportChannelGetDriverName(ch).UTF8String, grp.UTF8String,
                    subg.UTF8String, name.UTF8String,
                    IOReportChannelGetUnitLabel(ch).UTF8String);
          }
        } else if (fmt == kIOReportFormatState) {
          int n = IOReportStateGetCount(ch);
          for (int i = 0; i < n; i++) {
            NSString* st = IOReportStateGetNameForIndex(ch, i);
            uint64_t v = IOReportStateGetResidency(ch, i);
            fprintf(csvF, "%llu,%s,%s,%s,%s,%llu\n", (unsigned long long)ms,
                    grp.UTF8String, subg.UTF8String, name.UTF8String,
                    st.UTF8String, (unsigned long long)v);
            if (!metaWritten) {
              fprintf(metaF, "%s | %s | %s | %s | %s | state | %s\n",
                      IOReportChannelGetDriverName(ch).UTF8String, grp.UTF8String,
                      subg.UTF8String, name.UTF8String, st.UTF8String,
                      IOReportChannelGetUnitLabel(ch).UTF8String);
            }
          }
        }
        return 0;
      });
      CFRelease(samples);
      metaWritten = YES;
      fflush(csvF);
      // Sleep to the next cadence boundary (fixed cadence from process start).
      double target_ms = (double)(k + 1) * (double)interval_ms;
      for (;;) {
        if (g_stop) break;
        double el = mach_to_ns(mach_absolute_time() - t_start) / 1e6;
        if (el >= target_ms) break;
        usleep((useconds_t)((target_ms - el) > 2.0 ? ((target_ms - el) - 1.0) * 1000.0 : 500));
      }
      (void)lat_ms;
    }
    fclose(csv);
    fclose(meta);
    fprintf(stderr, "iomon: done\n");
    return 0;
  }
}
