#ifndef P18_BOOTSTRAP_H
#define P18_BOOTSTRAP_H
#include <stdint.h>
/* Called exactly once, first in app_main, before ADC, RF or UART tasks exist. */
void p18_bootstrap_early_init(void);
/* Fresh 32-byte value, or P18_TLS_BUSY/P18_TLS_FAILED with a wiped output.
 * No ADC/RF reconfiguration is permitted from this dispatcher-facing API. */
uint8_t p18_bootstrap_get_seed(uint8_t output[32]);
#endif
