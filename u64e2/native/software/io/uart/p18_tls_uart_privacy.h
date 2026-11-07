#ifndef P18_TLS_UART_PRIVACY_H
#define P18_TLS_UART_PRIVACY_H
#include "p18_tls_wire.h"
#ifndef CMD_BUF_SIZE
#error P18 privacy helper requires the actual UART buffer capacity
#endif
static_assert(CMD_BUF_SIZE>=P18_TLS_HEADER+P18_TLS_CHUNK,"P18 UART frame exceeds buffer capacity");
/* Called only by the CPU TX owner, after DMA completion or before a failed
 * queue submission returns ownership. Never scrub bytes still owned by DMA. */
static inline int p18_private_tx(const uint8_t *bytes,int size)
{
    if(!bytes||size<P18_TLS_HEADER||size>CMD_BUF_SIZE||size>P18_TLS_HEADER+P18_TLS_CHUNK)return 0;
    if(bytes[0]!=P18_TLS_COMMAND||!p18_magic(bytes)||bytes[8]!=P18_TLS_VERSION)return 0;
    unsigned length=p18_get16(bytes+10);
    if(!length||length!=(unsigned)size-P18_TLS_HEADER)return 0;
    return bytes[9]==P18_TLS_BEGIN||bytes[9]==P18_TLS_WRITE;
}
static inline void p18_wipe_private_tx(uint8_t *bytes,int size)
{
    if(!p18_private_tx(bytes,size))return;
    volatile uint8_t *private_body=bytes+P18_TLS_HEADER;
    unsigned count=(unsigned)size-P18_TLS_HEADER;
    while(count--)*private_body++=0;
}
#endif
