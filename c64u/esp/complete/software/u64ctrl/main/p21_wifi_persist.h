#ifndef P21_WIFI_PERSIST_H
#define P21_WIFI_PERSIST_H
#include <stdint.h>
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Only the reserved WiC64 control thread uses these readback-checked writes.
 * AP records retain the controller's existing recent_aps representation.
 * Multiple keys are not an atomic transaction; failures remain explicit. */
esp_err_t p21_wifi_store_verified(const char *, const char *, uint8_t, int16_t *);
esp_err_t p21_wifi_forget_verified(void);
#ifdef __cplusplus
}
#endif
#endif
