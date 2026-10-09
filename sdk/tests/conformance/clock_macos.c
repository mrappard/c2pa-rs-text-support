// Process-local historical clock for conformance tests on macOS.
// Monotonic clocks and processes without C2PA_CONFORMANCE_EPOCH are unchanged.
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

static int configured_epoch(time_t *epoch) {
    const char *value = getenv("C2PA_CONFORMANCE_EPOCH");
    if (!value || !*value) return 0;
    char *end;
    long long parsed = strtoll(value, &end, 10);
    if (*end) return 0;
    *epoch = (time_t)parsed;
    return 1;
}

static time_t validation_time(time_t *result) {
    time_t epoch;
    if (!configured_epoch(&epoch)) return time(result);
    if (result) *result = epoch;
    return epoch;
}

static int validation_gettimeofday(struct timeval *result, void *timezone) {
    time_t epoch;
    if (!configured_epoch(&epoch)) return gettimeofday(result, timezone);
    if (result) { result->tv_sec = epoch; result->tv_usec = 0; }
    return 0;
}

static int validation_clock_gettime(clockid_t clock, struct timespec *result) {
    time_t epoch;
    if (clock != CLOCK_REALTIME || !configured_epoch(&epoch)) return clock_gettime(clock, result);
    result->tv_sec = epoch;
    result->tv_nsec = 0;
    return 0;
}

static uint64_t validation_clock_gettime_nsec_np(clockid_t clock) {
    time_t epoch;
    if (clock != CLOCK_REALTIME || !configured_epoch(&epoch)) return clock_gettime_nsec_np(clock);
    return (uint64_t)epoch * 1000000000ULL;
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { const void *replacement; const void *original; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = \
    { (const void *)&replacement, (const void *)&original };

INTERPOSE(validation_time, time)
INTERPOSE(validation_gettimeofday, gettimeofday)
INTERPOSE(validation_clock_gettime, clock_gettime)
INTERPOSE(validation_clock_gettime_nsec_np, clock_gettime_nsec_np)
