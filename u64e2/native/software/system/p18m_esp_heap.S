#include "p18m_esp_image.h"
/* P18M initialized existing FreeRTOS arena. GPL-3.0-or-later.
 * This replaces heap_4's BSS array; it does not allocate a second arena.
 */
#if defined(P18M_INITIALIZED_ESP_HEAP) && P18M_INITIALIZED_ESP_HEAP
#ifndef P18M_HEAP_BYTES
#define P18M_HEAP_BYTES 0x4E8000
#endif
#if P18M_HEAP_BYTES != 0x4E8000 && P18M_HEAP_BYTES != 0x4E4000
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
.incbin "../../../../software/system/p18m_esp_app.bin"
.size p18m_esp_resource_seed, .-p18m_esp_resource_seed
.zero P18M_HEAP_BYTES - 32 - P18M_ESP_IMAGE_BYTES
.size ucHeap, .-ucHeap

.global p18m_ram_profile_initialized_esp_heap
.set p18m_ram_profile_initialized_esp_heap, P18M_HEAP_BYTES
#endif
