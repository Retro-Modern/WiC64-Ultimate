/* P18M temporary, malloc-owned ESP application resource. GPL-3.0-or-later. */
#ifndef P18M_ESP_RESOURCE_H
#define P18M_ESP_RESOURCE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Startup only: after BSS clearing, before any constructors allocate. */
void p18m_esp_resource_bootstrap(void);
/* Transfer once. The caller owns the result and must use free(). */
uint8_t *p18m_esp_resource_take(void);
void p18m_esp_resource_discard(void);
uint32_t p18m_esp_resource_length(void);

#ifdef __cplusplus
}
#endif
#endif
