/* P18M initialized existing FreeRTOS arena. GPL-3.0-or-later.
 * This replaces heap_4's BSS array; it does not allocate a second arena.
 */
#if defined(P18M_INITIALIZED_ESP_HEAP) && P18M_INITIALIZED_ESP_HEAP
#include "c64u_esp_image_profile.h"
#ifndef P18M_HEAP_BYTES
#define P18M_HEAP_BYTES 0x480000
#endif
#if P18M_HEAP_BYTES != 0x480000
#error P18M requires an explicit reviewed heap profile
#endif

.section .data.p18m_esp_heap,"aw",@progbits
.balign 16
.global ucHeap
.type ucHeap, @object
ucHeap:
.zero 32
.global p18m_esp_resource_seed
.type p18m_esp_resource_seed, @object
p18m_esp_resource_seed:
#if C64U_ESP_RETURN_APP
.incbin "../../../../software/system/p18m_esp_return_app.bin"
#else
.incbin "../../../../software/system/p18m_esp_app.bin"
#endif
.if (.-p18m_esp_resource_seed) != C64U_ESP_RESOURCE_BYTES
.error "C64U embedded ESP application length does not match its exact role"
.endif
.size p18m_esp_resource_seed, .-p18m_esp_resource_seed
.zero P18M_HEAP_BYTES - 32 - C64U_ESP_RESOURCE_BYTES
.size ucHeap, .-ucHeap

.global p18m_ram_profile_initialized_esp_heap
.set p18m_ram_profile_initialized_esp_heap, P18M_HEAP_BYTES
.global p18m_c64u_esp_image_role
#if C64U_ESP_RETURN_APP
.set p18m_c64u_esp_image_role, 2
#else
.set p18m_c64u_esp_image_role, 1
#endif
#endif
