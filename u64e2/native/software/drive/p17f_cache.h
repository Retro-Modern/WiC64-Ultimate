#ifndef P17F_MATH_CACHE_H
#define P17F_MATH_CACHE_H
#include <stdint.h>

namespace p17f {
enum CacheState { CACHE_PENDING=0, CACHE_WAIT_HARDWARE, CACHE_READY, CACHE_FAILED };
struct CacheStatus { CacheState state; uint32_t bytes; };

inline const char *math_cache_state_name(unsigned state) {
    static const char *names[]={"Pending","Wait","Ready","Failed"};
    return state<=CACHE_FAILED?names[state]:"Unknown";
}

#if (defined(P17F_CACHED_MATH) && P17F_CACHED_MATH) || defined(P17F_CACHE_HOST_TEST)
// The native main task calls this only after executeAll, C64 startup and the
// new USB controller's initHardware have replaced the old firmware's devices.
void mark_hardware_ready();
// Called under the TLS engine lease, before wolfSSL_Init or any SP operation.
// No caller may execute the linked low SP text until this succeeds.
bool prepare_math_cache();
void get_math_cache_status(CacheStatus &out);
#else
inline void mark_hardware_ready() {}
inline bool prepare_math_cache() { return false; }
inline void get_math_cache_status(CacheStatus &out) {out.state=CACHE_PENDING;out.bytes=0;}
#endif

#if defined(P17F_CACHE_HOST_TEST)
// Owned host tests exercise the actual installer with array-backed memory and
// synthetic addresses. These hooks do not exist in a native firmware build.
struct TestImage {
    uint32_t load_start,load_end,run_start,run_end,sweep_start,sweep_end;
    const volatile uint32_t *source;
    volatile uint32_t *destination;
};
struct TestOps {
    void *context;
    uint32_t (*disable_irq)(void *);
    void (*restore_irq)(void *,uint32_t);
    void (*evict)(void *);
    void (*after_copy)(void *); // optional corruption injection before verify
};
void test_reset();
void test_configure(const TestImage &,const TestOps &);
#endif
}
#endif
