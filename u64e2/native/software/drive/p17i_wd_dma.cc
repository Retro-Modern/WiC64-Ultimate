#if defined(P17I_WD_DMA) && P17I_WD_DMA
#include "p17i_wd_dma.h"
#include <string.h>
namespace p17i_wd_dma {
namespace {
bool ready=false;
extern "C" const volatile uint32_t p17i_wd_dma_profile = 0x50313749U;
inline void barrier() { __asm__ volatile("" ::: "memory"); }
#if defined(P17I_WD_DMA_HOST_TEST)
uint8_t *test_region=0;
size_t test_bytes=0;
uint8_t *begin() { return test_region; }
size_t extent() { return test_bytes; }
#else
extern "C" { extern uint8_t __p17i_wd_dma_start[], __p17i_wd_dma_end[]; }
uint8_t *begin() { return __p17i_wd_dma_start; }
size_t extent() {
    const uintptr_t lo=uintptr_t(__p17i_wd_dma_start), hi=uintptr_t(__p17i_wd_dma_end);
    return hi>=lo ? size_t(hi-lo) : 0;
}
#endif
bool layout_valid() {
    const uintptr_t lo=uintptr_t(begin());
    if(p17i_wd_dma_profile!=0x50313749U || !lo || (lo&31U) || extent()!=REGION_BYTES) return false;
#if !defined(P17I_WD_DMA_HOST_TEST)
    if(lo!=0x00070000U || uintptr_t(__p17i_wd_dma_end)!=0x00074000U) return false;
    if(lo+REGION_BYTES>0x01000000U) return false; // WD177x exposes only 24 address bits.
#endif
    return true;
}
}
uint8_t *buffer_for_irq(int irq) {
    if(!layout_valid() || irq<1 || irq>DRIVE_COUNT) return 0;
    return begin()+size_t(irq-1)*SLOT_BYTES;
}
bool usable(const uint8_t *buffer, size_t bytes) {
    barrier();
    if(!__atomic_load_n(&ready,__ATOMIC_ACQUIRE) || !layout_valid() || !bytes || bytes>BUFFER_BYTES) return false;
    return buffer==buffer_for_irq(1) || buffer==buffer_for_irq(2);
}
void mark_hardware_ready() {
    if(__atomic_load_n(&ready,__ATOMIC_ACQUIRE) || !layout_valid()) return;
    // Called after new hardware initialization, while command handlers still
    // fail closed. Publish readiness only after both slots have been cleared.
    memset(begin(),0,REGION_BYTES);
    barrier();
    __atomic_store_n(&ready,true,__ATOMIC_RELEASE);
    barrier();
}
#if defined(P17I_WD_DMA_HOST_TEST)
void bind_test_region(uint8_t *region,size_t bytes) {
    __atomic_store_n(&ready,false,__ATOMIC_RELEASE);barrier();test_region=region;test_bytes=bytes;barrier();
}
#endif
}
#endif
