#ifndef P21_STORE_BACKEND_H
#define P21_STORE_BACKEND_H
#include "p21_store_wire.h"
#define P21_RECORD_HEADER 32U
#define P21_RECORD_MAX (P21_RECORD_HEADER+P21_STORE_MAX)
/* The dedicated store worker is the exclusive caller. No shared UART buffers.
 * Init result is supplied once; this backend never initializes/erases NVS. */
void p21_backend_ready(int ready);
int p21_backend_available(void);
int p21_backend_load(uint8_t *payload,uint32_t *length,uint64_t *generation,uint32_t *crc,int *detail);
int p21_backend_commit(const uint8_t *payload,uint32_t length,uint64_t expected,uint32_t crc,int *detail);
#endif
