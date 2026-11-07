/* P18M temporary ESP application ownership. GPL-3.0-or-later. */
#include "p18m_esp_resource.h"
#include "FreeRTOS.h"
#include "task.h"
#include <stdlib.h>
#include "c64u_esp_install_profile.h"

#if defined(P18M_INITIALIZED_ESP_HEAP) && P18M_INITIALIZED_ESP_HEAP
#if portBYTE_ALIGNMENT != 16
#error P18M resource requires the reviewed 16-byte heap and malloc alignment
#endif

extern "C" uint8_t p18m_esp_resource_seed[];
namespace {
const uint32_t image_bytes = C64U_ESP_RESOURCE_BYTES;
uint8_t *owned_image;
bool bootstrap_done;
}

void p18m_esp_resource_bootstrap(void)
{
    if (bootstrap_done) return;
    bootstrap_done = true;
    // heap_4's aligned header and memory_wrap's malloc header each occupy
    // 16 bytes. Initializing those headers preserves the seed at ucHeap+32.
    uint8_t *claimed = static_cast<uint8_t *>(malloc(image_bytes));
    if (claimed == p18m_esp_resource_seed) owned_image = claimed;
    else free(claimed); // Fail closed if allocation order or ABI differs.
}

uint8_t *p18m_esp_resource_take(void)
{
    taskENTER_CRITICAL();
    uint8_t *result = owned_image;
    owned_image = 0;
    taskEXIT_CRITICAL();
    return result;
}

void p18m_esp_resource_discard(void)
{
    free(p18m_esp_resource_take());
}

uint32_t p18m_esp_resource_length(void)
{
    return image_bytes;
}
#endif
