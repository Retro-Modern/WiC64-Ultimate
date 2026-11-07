#ifndef P14_PLATFORM_H
#define P14_PLATFORM_H
#include <stdint.h>
#include "p14_state.h"

namespace p08 { struct BackendContext; }
namespace p14 {
enum { SETUP_BYTES=64, MAX_ENTROPY_BYTES=128, CLOCK_MAX_AGE_SECONDS=86400 };
enum Result {
    OK=0, UNSEEDED, STORAGE_BLOCKED, STORAGE_UNAVAILABLE, STORAGE_WRITE_FAILED,
    BAD_SETUP, SETUP_CHECKSUM, SETUP_ID, SETUP_REUSED, CRYPTO_ERROR,
    EPOCH_EXHAUSTED, ARGUMENT, CLOCK_UNAVAILABLE, CLOCK_RANGE,
    CLOCK_ROLLBACK, CLOCK_STALE, CLOCK_CHANGED
};
struct Status {
    bool provisioned, entropy_ready, storage_blocked, time_ready;
    Result last_error;
};

// Call once immediately after the initial private-credential load, before any
// normal preference/header write can hide the journal's recovery evidence.
void initialize(const p08::BackendContext &,bool storage_recovered,bool storage_writable);
// Owned worker only, after any prior backend/TLS operation has finished.
// The TLS global DRBG must be forgotten by the caller AFTER success.
Result import_setup(p08::BackendContext &,const uint8_t *,uint32_t length);
// Strong NV seed input for the TLS DRBG. A new private state is persisted and
// verified by the native journal before ANY derived bytes reach the caller.
Result reserve_entropy(p08::BackendContext &,uint8_t *,uint16_t length);
bool entropy_available(const p08::BackendContext &);
// Owned worker only. Existing valid seeds are retained without consulting the
// source. Automatic setup is allowed only for a valid empty secure state whose
// original load and current private journal are clean. A source failure never
// clears a storage prohibition; only explicit manual import may recover it.
struct BootstrapSource {
    bool (*read)(void *,uint8_t seed[32]);
    bool (*permitted)(void *); // bounded operation still live, not cancelled
    void *context;
};
Result ensure_entropy(p08::BackendContext &,const BootstrapSource &);
// Defensive import/invalidation failure: normal saves and SNTP never clear it.
void block_entropy(Result);
// Import validation/reuse results describe the last setup attempt, not the
// readiness of an already provisioned seed. No private setup bytes are exposed.
// Returns false until an import attempt has completed in this program lifetime.
bool get_last_setup_result(Result &out);
// Separate from manual file-import history. True only after an actual private
// bootstrap-source read was attempted in this program lifetime.
bool get_last_bootstrap_result(Result &out);
void get_status(const p08::BackendContext &,Status &);
const char *result_name(Result);

// Snapshot before the native write, then publish AFTER rtc.set_time_utc(). A
// raw RTC reading is not trusted/synchronized merely because it is plausible.
bool utc_snapshot(uint32_t &seconds);
void note_sntp(uint32_t seconds,uint32_t prewrite_seconds,bool prewrite_valid);
// Initial synchronization convenience only; a later call without the required
// prewrite snapshot fails closed. The native hook always uses the full form.
void note_sntp(uint32_t seconds);
Result utc_now(uint64_t &seconds);

#if defined(P14_PLATFORM_HOST_TEST)
// Explicit modeled clock only. Production cannot replace UTC or storage hooks.
struct TestClock {
    uint32_t (*ticks)(void *);
    bool (*utc)(void *,uint32_t &);
    uint32_t ticks_per_second;
    void *context;
};
void test_set_clock(const TestClock &);
void test_reset();
#endif
}
#endif
