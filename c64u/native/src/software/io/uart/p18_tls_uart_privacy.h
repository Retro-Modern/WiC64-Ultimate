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
    /* Fixed private commands are protected even when their envelope is bad. */
    return bytes&&size>0&&(bytes[0]==P18_TLS_COMMAND||bytes[0]==0x21||bytes[0]==0x05);
}
static inline void p18_wipe_private_tx(uint8_t *bytes,int size)
{
    if(!p18_private_tx(bytes,size))return;
    volatile uint8_t *private_body=bytes+4;
    unsigned count=CMD_BUF_SIZE-4;
    while(count--)*private_body++=0;
}
#endif
