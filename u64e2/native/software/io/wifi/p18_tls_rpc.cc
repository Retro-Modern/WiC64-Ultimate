#if defined(P18_TLS) && P18_TLS
#include "p18_tls_rpc.h"
#include "p18_tls_wire.h"
#include "wifi_cmd.h"
#include <string.h>
void p18_tls_rpc_pause(){vTaskDelay(1);}
static void p18_erase_owned_buffer(command_buf_t *buf)
{
    volatile uint8_t *bytes=buf->data;
    for(unsigned i=0;i<sizeof(buf->data);++i)bytes[i]=0;
}
static uint32_t p18_rpc_ticks_ms(){return (uint32_t)xTaskGetTickCount()*(1000U/configTICK_RATE_HZ);}
int p18_tls_rpc_exchange(uint8_t *frame,uint16_t count,uint16_t capacity,uint16_t *reply_bytes,uint32_t timeout_ms)
{
    if(reply_bytes)*reply_bytes=0;
    if(!frame||!reply_bytes||count<P18_TLS_HEADER||count>P18_TLS_HEADER+P18_TLS_CHUNK||capacity<count||!timeout_ms||timeout_ms>100)return -1;
    uint32_t begin=p18_rpc_ticks_ms();
    command_buf_t *buf=0;
    if(!esp32.uart || esp32.uart->GetBuffer(&buf,pdMS_TO_TICKS(timeout_ms))!=pdTRUE)return -1;
    uint32_t used=(uint32_t)(p18_rpc_ticks_ms()-begin);
    if(used>=timeout_ms){p18_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);return -1;}
    memcpy(buf->data,frame,count);
    rpc_header_t *header=(rpc_header_t *)buf->data;
    header->command=P18_TLS_COMMAND;
    if(!wifi_reply_register(header)){p18_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);return -1;}
    rpc_header_t expected=*header;
    buf->size=count;
    buf=wifi_transmit(buf,(int)(timeout_ms-used));
    if(!buf)return -1;
    int result=-3;
    if(buf->size>=4 && buf->data[0]==P18_TLS_COMMAND && buf->data[1]==expected.thread && p18_get16(buf->data+2)==expected.sequence){
        if(buf->size==8 && p18_get32(buf->data+4)==0x106U){result=-2;}
        else if(buf->size>=P18_TLS_HEADER && buf->size<=capacity){
            memcpy(frame,buf->data,(unsigned)buf->size);*reply_bytes=(uint16_t)buf->size;result=0;
        }
    }
    // READ replies contain plaintext. This RPC exclusively owns the received
    // buffer; erase its bounded payload storage before returning it to the pool,
    // including malformed replies, without touching a DMA-owned TX buffer.
    p18_erase_owned_buffer(buf);
    esp32.uart->FreeBuffer(buf);
    return result;
}
#endif
