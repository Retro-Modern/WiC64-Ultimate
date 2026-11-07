#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
// This stays in HIGH text. Do not place it beside the relocated SP kernels.
.section .text.p17f_cache_evict,"ax",@progbits
.option push
.option norvc
.option norelax
.balign 2048
.global p17f_cache_profile_sp_math
.set p17f_cache_profile_sp_math,0x00030000
.global p17f_cache_evict
.global __p17f_evict_start
.global __p17f_evict_end
.type p17f_cache_evict,@function
p17f_cache_evict:
__p17f_evict_start:
.rept 512
    .word 0x00000013
.endr
__p17f_evict_end:
    // Synchronize instruction stores on a conformant implementation too.
    // Pinned RVLite decodes this as a no-op; the preceding sweep is required.
    .word 0x0000100f
    ret
.size p17f_cache_evict,.-p17f_cache_evict
.option pop
#endif
