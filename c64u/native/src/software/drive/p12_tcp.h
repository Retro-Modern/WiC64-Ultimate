#ifndef P12_TCP_H
#define P12_TCP_H
#include "p08_http.h"
namespace p08 {
// One WiC64 TCP stream. All commands run on the service worker.
bool p12_execute_tcp(BackendContext &,uint8_t,const uint8_t *,uint32_t,
                     uint8_t *,uint32_t,BackendResult &);
void p12_tcp_reset();
// Capture after a successful nonempty READ and finalize only that service
// response. Failed delivery retains the same bytes for the next READ.
uint32_t p12_tcp_read_ticket();
void p12_tcp_finalize_read(uint32_t ticket, bool delivered);
}
#endif
