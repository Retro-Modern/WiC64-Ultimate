#if (defined(P17F_CACHED_MATH) && P17F_CACHED_MATH) || defined(P17F_CACHE_HOST_TEST)
#include "p17f_cache.h"
#include <stddef.h>

namespace p17f {
namespace {
const uint32_t LOW_START=0x00030000U,LOW_END=0x00070000U;
const uint32_t HIGH_START=0x03000000U,HIGH_END=0x03c00000U;
const uint32_t SWEEP_BYTES=2048;

struct Image {
    uint32_t load_start,load_end,run_start,run_end,sweep_start,sweep_end;
    const volatile uint32_t *source;
    volatile uint32_t *destination;
};
struct Ops {
    void *context;
    uint32_t (*disable_irq)(void *);
    void (*restore_irq)(void *,uint32_t);
    void (*evict)(void *);
    void (*after_copy)(void *);
};
CacheStatus status={CACHE_PENDING,0};
bool hardware_ready=false;

inline void compiler_barrier(){__asm__ volatile("" ::: "memory");}

#if defined(P17F_CACHE_HOST_TEST)
Image image={};Ops operations={};
#else
extern "C" {
    extern uint8_t __p17f_math_load_start[],__p17f_math_load_end[];
    extern uint8_t __p17f_math_start[],__p17f_math_end[];
    extern uint8_t __p17f_evict_start[],__p17f_evict_end[];
    void p17f_cache_evict();
}
uint32_t disable_irq(void *) {
    uint32_t saved;
    __asm__ volatile("csrrci %0, mstatus, 8" : "=r"(saved) :: "memory");
    return saved;
}
void restore_irq(void *,uint32_t saved) {
    // Restore only MIE, preserving every other status bit and the incoming
    // disabled state. Do not alter FreeRTOS's critical-nesting bookkeeping.
    if(saved&8U)__asm__ volatile("csrsi mstatus, 8" ::: "memory");
    else __asm__ volatile("csrci mstatus, 8" ::: "memory");
}
void evict(void *) {p17f_cache_evict();}
Image native_image() {
    Image r={uint32_t(uintptr_t(__p17f_math_load_start)),uint32_t(uintptr_t(__p17f_math_load_end)),
        uint32_t(uintptr_t(__p17f_math_start)),uint32_t(uintptr_t(__p17f_math_end)),
        uint32_t(uintptr_t(__p17f_evict_start)),uint32_t(uintptr_t(__p17f_evict_end)),
        reinterpret_cast<const volatile uint32_t *>(__p17f_math_load_start),
        reinterpret_cast<volatile uint32_t *>(__p17f_math_start)};
    return r;
}
const Ops operations={0,disable_irq,restore_irq,evict,0};
#endif

bool valid(const Image &r) {
    if(!r.source||!r.destination||r.run_start!=LOW_START||r.run_end<=r.run_start||r.run_end>LOW_END)return false;
    if(r.load_start<HIGH_START||r.load_start>=HIGH_END||r.load_end<=r.load_start||r.load_end>HIGH_END)return false;
    if(r.load_end-r.load_start!=r.run_end-r.run_start)return false;
    if((r.load_start|r.load_end|r.run_start|r.run_end)&3U)return false;
    if((uintptr_t(r.source)|uintptr_t(r.destination))&3U)return false;
    if(r.sweep_start<HIGH_START||r.sweep_start>HIGH_END-SWEEP_BYTES-8U||r.sweep_end!=r.sweep_start+SWEEP_BYTES)return false;
    if(r.sweep_start&(SWEEP_BYTES-1U))return false;
    // The source bytes are a distinct high payload, not the executing sweep.
    if(r.load_start<r.sweep_end+8U&&r.load_end>r.sweep_start)return false;
#if !defined(P17F_CACHE_HOST_TEST)
    if(uintptr_t(r.source)!=r.load_start||uintptr_t(r.destination)!=r.run_start)return false;
#endif
    return true;
}
bool install(const Image &r,const Ops &ops) {
    if(!ops.disable_irq||!ops.restore_irq||!ops.evict)return false;
    const uint32_t saved=ops.disable_irq(ops.context);
    bool ok=false;
    if(status.state==CACHE_READY)ok=true;
    else if(status.state!=CACHE_FAILED) {
        if(!hardware_ready)status.state=CACHE_WAIT_HARDWARE;
        else if(!valid(r))status.state=CACHE_FAILED;
        else {
            const uint32_t words=(r.run_end-r.run_start)/4U;
            compiler_barrier();
            for(uint32_t i=0;i<words;i++)r.destination[i]=r.source[i];
            compiler_barrier();
            if(ops.after_copy)ops.after_copy(ops.context);
            bool equal=true;
            for(uint32_t i=0;i<words;i++)if(r.destination[i]!=r.source[i]){equal=false;break;}
            compiler_barrier();
            if(equal){
                // RVLite's fence.i is a no-op. Its cache fills even uncached
                // instruction fetches. This high sequential sweep replaces
                // all 512 tags with bit24=1, disjoint from the low math text.
                ops.evict(ops.context);
                compiler_barrier();
                status.bytes=words*4U;status.state=CACHE_READY;ok=true;
            }else status.state=CACHE_FAILED;
        }
    }
    ops.restore_irq(ops.context,saved);
    return ok;
}
}

void mark_hardware_ready() {
    if(!operations.disable_irq||!operations.restore_irq)return;
    const uint32_t saved=operations.disable_irq(operations.context);
    hardware_ready=true;
    if(status.state==CACHE_WAIT_HARDWARE)status.state=CACHE_PENDING;
    operations.restore_irq(operations.context,saved);
}
bool prepare_math_cache() {
#if defined(P17F_CACHE_HOST_TEST)
    return install(image,operations);
#else
    return install(native_image(),operations);
#endif
}
void get_math_cache_status(CacheStatus &out) {
    if(!operations.disable_irq||!operations.restore_irq){out=status;return;}
    const uint32_t saved=operations.disable_irq(operations.context);
    out=status;
    operations.restore_irq(operations.context,saved);
}

#if defined(P17F_CACHE_HOST_TEST)
void test_reset(){status.state=CACHE_PENDING;status.bytes=0;hardware_ready=false;image=Image{};operations=Ops{};}
void test_configure(const TestImage &r,const TestOps &ops) {
    image=Image{r.load_start,r.load_end,r.run_start,r.run_end,r.sweep_start,r.sweep_end,r.source,r.destination};
    operations=Ops{ops.context,ops.disable_irq,ops.restore_irq,ops.evict,ops.after_copy};
}
#endif
}
#endif
