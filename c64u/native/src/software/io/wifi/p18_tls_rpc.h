#ifndef P18_TLS_RPC_H
#define P18_TLS_RPC_H
#include <stdint.h>
/* Exchanges one frame; no automatic retransmission. Exactly -2 means the stock
 * firmware's explicit ESP_ERR_NOT_SUPPORTED reply; -1 is absent/timeout,
 * -3 is an invalid received reply. All are fatal after BEGIN. */
// Yield at most one RTOS tick; never wait for TCP readability while the ESP
// may still be producing ClientHello/Finished in its own worker.
void p18_tls_rpc_pause();
int p18_tls_rpc_exchange(uint8_t *frame,uint16_t request_bytes,uint16_t capacity,
                         uint16_t *reply_bytes,uint32_t timeout_ms);
#endif
