#ifndef P64_ORDERING_H
#define P64_ORDERING_H
/* Publication primitives for the measured single-core C64U API22/Core49.
 * This core traps on FENCE. Native loads/stores remain typed GNU atomics;
 * short IRQ-preserving sections plus compiler barriers supply the single-core
 * publication boundary. RMW ownership/lock code keeps its existing guards.
 * Other targets/host tests keep the original GCC acquire/release operations.
 */
#if defined(C64U_CORE49_FENCELESS) && C64U_CORE49_FENCELESS
#if !defined(__riscv) || __riscv_xlen != 32 || U64 != 2 || !C64U_API22_ALPHA || !P05_RAM_DIAGNOSTIC
#error Fenceless primitives require the measured RV32 C64U RAM profile
#endif
#endif
namespace p64_ordering {
inline void compiler_barrier(){__asm__ volatile("" ::: "memory");}
#if defined(C64U_CORE49_FENCELESS) && C64U_CORE49_FENCELESS
inline unsigned irq_save(){
    unsigned old;
    __asm__ volatile("csrrci %0, mstatus, 8":"=r"(old)::"memory");
    return old;
}
inline void irq_restore(unsigned old){
    compiler_barrier();
    if(old&8) __asm__ volatile("csrsi mstatus, 8":::"memory");
}
#endif
/* Callers must pass naturally aligned T objects. Type alignment checks do not
 * validate a runtime pointer; current native users are static byte/word fields. */
template<class T> inline T load(const volatile T *address,int order){
#if defined(C64U_CORE49_FENCELESS) && C64U_CORE49_FENCELESS
    static_assert(sizeof(T)==1||sizeof(T)==4,"Only naturally atomic byte/word publications are qualified");
    static_assert(alignof(T)>=sizeof(T),"Publication type must be naturally aligned");
    (void)order;
    const unsigned old=irq_save();
    T value=__atomic_load_n(address,__ATOMIC_RELAXED);
    irq_restore(old);
    return value;
#else
    return __atomic_load_n(address,order);
#endif
}
template<class T,class V> inline void store(volatile T *address,V value,int order){
#if defined(C64U_CORE49_FENCELESS) && C64U_CORE49_FENCELESS
    static_assert(sizeof(T)==1||sizeof(T)==4,"Only naturally atomic byte/word publications are qualified");
    static_assert(alignof(T)>=sizeof(T),"Publication type must be naturally aligned");
    (void)order;
    const unsigned old=irq_save();
    __atomic_store_n(address,T(value),__ATOMIC_RELAXED);
    irq_restore(old);
#else
    __atomic_store_n(address,T(value),order);
#endif
}
/* The pinned in-order core/converter serializes CPU request issue. Preserve
 * the compiler order of the existing volatile mailbox accesses, matching the
 * later upstream FENCE-as-NOP decoder. This does not drain posted device/DMA
 * writes; existing address-specific flush/readback operations stay in place.
 * This is not a generic replacement for a fence on other CPU/FPGA targets. */
inline void mailbox_barrier(){compiler_barrier();}
}
#endif
