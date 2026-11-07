#if defined(C64U_ESP_PERSIST) && C64U_ESP_PERSIST
#include "p21_store_client.h"
#include "p21_store_wire.h"
#include "wifi_cmd.h"
#include <string.h>
void p21_store_rpc_pause(){vTaskDelay(1);}
static void p21_erase_owned_buffer(command_buf_t *buf)
{
    volatile uint8_t *bytes=buf->data;
    for(unsigned i=0;i<sizeof(buf->data);++i)bytes[i]=0;
}
int p21_store_rpc_exchange(uint8_t *frame,uint16_t count,uint16_t capacity,uint16_t *reply_bytes,uint32_t timeout_ms)
{
    if(reply_bytes)*reply_bytes=0;
    if(!frame||!reply_bytes||count<P21_STORE_HEADER||count>P21_STORE_HEADER+P21_STORE_CHUNK||capacity<count||!timeout_ms||timeout_ms>100)return -1;
    const TickType_t begin=xTaskGetTickCount();
    const TickType_t ticks=pdMS_TO_TICKS(timeout_ms);
    if(!ticks)return -1;
    command_buf_t *buf=0;
    if(!esp32.uart || esp32.uart->GetBuffer(&buf,ticks)!=pdTRUE)return -1;
    TickType_t used=xTaskGetTickCount()-begin;
    if(used>=ticks){p21_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);return -1;}
    memcpy(buf->data,frame,count);
    rpc_header_t *header=(rpc_header_t *)buf->data;
    header->command=P21_STORE_COMMAND;
    if(!wifi_reply_register(header)){p21_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);return -1;}
    rpc_header_t expected=*header;
    buf->size=count;
    used=xTaskGetTickCount()-begin;
    if(used>=ticks){
        // This request is still CPU-owned. Retire its tag even if a stale
        // notification raced the deadline; every received private buffer is
        // separately owned and must be erased before release.
        command_buf_t *pending=wifi_wait_reply(expected,0);
        if(pending){p21_erase_owned_buffer(pending);esp32.uart->FreeBuffer(pending);}
        p21_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);return -1;
    }
    // The ordinary transmitter can wait 200 ticks for queue space. This method
    // commits immediately and owns/frees the TX buffer on both outcomes. Never
    // access that buffer again after enqueue, including the failure path.
    if(esp32.uart->TransmitPacketNonBlocking(buf)!=pdTRUE){
        buf=wifi_wait_reply(expected,0);
        if(buf){p21_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);}
        return -1;
    }
    used=xTaskGetTickCount()-begin;
    const uint32_t remaining_ms=used<ticks?uint32_t(ticks-used)*1000U/configTICK_RATE_HZ:0;
    buf=wifi_wait_reply(expected,int(remaining_ms));
    if(!buf)return -1;
    if(!remaining_ms||TickType_t(xTaskGetTickCount()-begin)>=ticks){
        p21_erase_owned_buffer(buf);esp32.uart->FreeBuffer(buf);return -1;
    }
    int result=-3;
    if(buf->size>=4 && buf->data[0]==P21_STORE_COMMAND && buf->data[1]==expected.thread && p21_get16(buf->data+2)==expected.sequence){
        if(buf->size==8 && p21_get32(buf->data+4)==0x106U){result=-2;}
        else if(buf->size>=P21_STORE_HEADER && buf->size<=capacity){
            memcpy(frame,buf->data,(unsigned)buf->size);*reply_bytes=(uint16_t)buf->size;result=0;
        }
    }
    // READ replies contain plaintext. This RPC exclusively owns the received
    // buffer; erase its bounded payload storage before returning it to the pool,
    // including malformed replies, without touching a DMA-owned TX buffer.
    p21_erase_owned_buffer(buf);
    esp32.uart->FreeBuffer(buf);
    return result;
}
#endif
