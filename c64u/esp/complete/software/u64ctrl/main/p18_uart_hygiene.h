#ifndef P18_UART_HYGIENE_H
#define P18_UART_HYGIENE_H
#include "cmd_buffer.h"
#include "p18_tls_wire.h"
#include "p21_store_wire.h"
/* Reserved command recognition also suppresses dumps of malformed P18 input. */
static inline int p18_uart_private(const command_buf_t *buf){
    return buf&&buf->size>0&&(buf->data[0]==P18_TLS_COMMAND||buf->data[0]==P21_STORE_COMMAND||buf->data[0]==0x05);
}
/* Called only once the UART FIFO owns every transmitted byte, or when queueing
 * failed and UART never acquired ownership. No legacy-command bytes change. */
static inline void p18_uart_retire(command_buf_t *buf){
    if(!p18_uart_private(buf))return;
    /* Connect replies shrink size before TX. Retire the original request too. */
    unsigned length=CMD_BUF_SIZE;
    volatile uint8_t *p=buf->data;
    for(unsigned i=4;i<length;i++)p[i]=0;
}
#endif
