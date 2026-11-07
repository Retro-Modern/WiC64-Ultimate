#ifndef P15_NETWORK_H
#define P15_NETWORK_H
#include "p08_http.h"
namespace p08 {
// One adapter-bound UDP listener shared by canonical and historic aliases.
// Reset on Stop/session reset or adapter identity/address changes.
void p15_network_reset();
bool p15_execute_network(BackendContext &,uint8_t command,uint8_t protocol,
    const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,
    BackendResult &);
// Packet validation used by the raw-ICMP path and focused parser tests.
// IPv4 source, protocol, fragmentation, checksum, identifier, sequence and
// complete payload must all match; unrelated packets are never a reply.
bool p15_ping_reply(const uint8_t *packet,uint32_t length,const uint8_t target[4],
    const uint8_t expected[24],uint8_t &ttl);
}
#endif
