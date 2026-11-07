#include "wifi_cmd.h"
#include "dump_hex.h"
#include <stddef.h>
#if U64 && P08_SERVICE && P18_TLS
#include "p18m_esp_firmware.h"
#endif
#if defined(P18_TLS) && P18_TLS
#include "p18_tls_wire.h"
#endif
#if U64 && P08_SERVICE
#include "p12_wifi.h"
#endif

/// C like functions to 'talk' with the WiFi Module
static uint16_t sequence_nr = 0;
static wifi_reply_slot_t replySlots[WIFI_REPLY_SLOTS];

void hex(uint8_t h)
{
    static const uint8_t hexchars[] = "0123456789ABCDEF";
    ioWrite8(UART_DATA, hexchars[h >> 4]);
    ioWrite8(UART_DATA, hexchars[h & 15]);
}

#if defined(P18_TLS) && P18_TLS
// Late or malformed P18 replies must never enter the generic receive queue:
// identification diagnostics can dump that queue, and READ replies are private.
static void p18_discard_orphan_rpc(command_buf_context_t *context, command_buf_t *buf, BaseType_t *w)
{
    volatile uint8_t *bytes=buf->data;
    for(unsigned i=0;i<sizeof(buf->data);++i)bytes[i]=0;
    (void)cmd_buffer_free_isr(context,buf,w);
}
#endif

BaseType_t wifi_rx_isr(command_buf_context_t *context, command_buf_t *buf, BaseType_t *w)
{
#if defined(P18_TLS) && P18_TLS
    // Exclusive store/TLS replies never enter generic diagnostic queues.
    const bool private_rpc=buf->size>0&&(buf->data[0]==P18_TLS_COMMAND||buf->data[0]==0x21);
    const bool connect_rpc=buf->size>0&&buf->data[0]==CMD_WIFI_CONNECT;
#endif
    // Every legacy event/reply has the same four-byte echoed RPC header.
    if (buf->size < (int)sizeof(rpc_header_t) || buf->size > (int)sizeof(buf->data)) {
#if defined(P18_TLS) && P18_TLS
        if(private_rpc||connect_rpc){p18_discard_orphan_rpc(context,buf,w);return pdTRUE;}
#endif
        (void)cmd_buffer_free_isr(context, buf, w);
        return pdTRUE;
    }
#if U64 && P08_SERVICE
#if defined(P18_TLS) && P18_TLS
    // Commands 0x20/0x21 belong only to private RPC clients, even with a malformed thread tag.
    // Every legacy packet retains the existing P12 first-hook behavior.
    if(!private_rpc){
#endif
    if (p08::p12_wifi_rpc_receive_isr(context, buf, w)) return pdTRUE;
#if defined(P18_TLS) && P18_TLS
    }
#endif
#endif
#if defined(P18_TLS) && P18_TLS
    if(private_rpc && buf->size<(int)sizeof(rpc_header_t)){
        p18_discard_orphan_rpc(context,buf,w);return pdTRUE;
    }
#endif
    rpc_header_t *hdr = (rpc_header_t *)buf->data;
    BaseType_t res;

    TaskHandle_t thread = (TaskHandle_t)wifi_reply_take(replySlots, hdr->thread, hdr->sequence);
    if (thread) {
        ioWrite8(UART_DATA, 'N');
        res = xTaskNotifyFromISR(thread, (uint32_t)buf, eSetValueWithOverwrite, w);
#if defined(P18_TLS) && P18_TLS
        if((private_rpc||connect_rpc) && res!=pdTRUE){p18_discard_orphan_rpc(context,buf,w);return pdTRUE;}
#endif
    } else {
#if defined(P18_TLS) && P18_TLS
        if(private_rpc||connect_rpc){p18_discard_orphan_rpc(context,buf,w);return pdTRUE;}
#endif
        ioWrite8(UART_DATA, '~');
        res = cmd_buffer_received_isr(context, buf, w);
    }
    return res;
}

int wifi_reply_register(rpc_header_t *hdr)
{
    wifi_reply_tag_t tag;
    ENTER_SAFE_SECTION;
    int ok = wifi_reply_claim(replySlots, &sequence_nr, xTaskGetCurrentTaskHandle(), &tag);
    LEAVE_SAFE_SECTION;
    if (ok) {
        hdr->thread = tag.thread;
        hdr->sequence = tag.sequence;
    }
    return ok;
}

// The request buffer is freed by the UART once sent, so the tag is read first.
command_buf_t *wifi_transmit(command_buf_t *buf, int timeout_ms)
{
    rpc_header_t hdr = *(rpc_header_t *)buf->data;
    esp32.uart->TransmitPacket(buf);
    return wifi_wait_reply(hdr, timeout_ms);
}

command_buf_t *wifi_wait_reply(rpc_header_t hdr, int timeout_ms)
{
    command_buf_t *reply = NULL;
    if (xTaskNotifyWait(0, 0, (uint32_t *)&reply, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        return reply;
    }
    wifi_reply_tag_t tag = { hdr.thread, hdr.sequence };
    ENTER_SAFE_SECTION;
    wifi_reply_abandon(replySlots, &tag);
    LEAVE_SAFE_SECTION;
    // The reply may have been delivered just before the slot was released
    if (xTaskNotifyWait(0, 0, (uint32_t *)&reply, 0) == pdTRUE) {
        return reply;
    }
    return NULL;
}

void wifi_command_init(void)
{
    // A task that was deleted while it waited must not be notified later
    ENTER_SAFE_SECTION;
    for (int i = 0; i < WIFI_REPLY_SLOTS; i++) {
        replySlots[i].task = NULL;
    }
    LEAVE_SAFE_SECTION;
#if (CLOCK_FREQ == 66666667)
    esp32.uart->SetBaudRate(6666666);
#else
    esp32.uart->SetBaudRate(5000000);
#endif
    esp32.uart->FlowControl(true);
    esp32.uart->ClearRxBuffer();
    esp32.uart->EnableSlip(true);
    esp32.uart->SetReceiveCallback(wifi_rx_isr);
    esp32.uart->EnableIRQ(true);
}


int wifi_setbaud(int baudrate, uint8_t flowctrl)
{
    BUFARGS(setbaud, CMD_SET_BAUD);

    args->baudrate = baudrate;
    args->flowctrl = flowctrl;
    args->inversions = 0;

    rpc_header_t hdr = args->hdr;
    vTaskDelay(1000);

    esp32.uart->TransmitPacket(buf);
    vTaskDelay(100); // wait until transmission must have completed (no handshake!) (~ half second, remote side will send reply at new rate after one second)
    esp32.uart->SetBaudRate(baudrate);
    esp32.uart->FlowControl(flowctrl != 0);

    buf = wifi_wait_reply(hdr, 5000);
    if (buf) {
        // copy results
        rpc_espcmd_resp *result = (rpc_espcmd_resp *)buf->data;
        int retval = result->esp_err;
        esp32.uart->FreeBuffer(buf);
        return retval;
    }
    return -1;
}

BaseType_t wifi_detect(uint16_t *major, uint16_t *minor, char *str, int maxlen)
{
    if(!major||!minor||!str||maxlen<1)return pdFALSE;
    *major=*minor=0;str[0]=0;
    BUFARGS_NOREPLY(identify, CMD_IDENTIFY, pdFALSE); // the result is a success flag here
    if (!wifi_reply_register(&args->hdr)) {
        esp32.uart->FreeBuffer(buf);
        printf(no_wifi_slot);
        return pdFALSE;
    }

    const rpc_header_t expected=args->hdr;
    // now block thread for reply
    printf("Get ident...");
    buf = wifi_transmit(buf, 500);
    BaseType_t success = (buf) ? pdTRUE : pdFALSE;
    if (success == pdTRUE) {
        // From this moment on, "buf" points to the receive buffer!!
        // copy results
        rpc_identify_resp *result = (rpc_identify_resp *)buf->data;
        const unsigned offset=offsetof(rpc_identify_resp,string);
        if(buf->size<=int(offset)||buf->size>int(sizeof(buf->data))||
           result->hdr.command!=CMD_IDENTIFY||result->hdr.thread!=expected.thread||
           result->hdr.sequence!=expected.sequence||
           !memchr(&result->string,0,unsigned(buf->size)-offset)){
            esp32.uart->FreeBuffer(buf);return pdFALSE;
        }
        *major = result->major;
        *minor = result->minor;
        unsigned copied=0;
        while(copied+1<unsigned(maxlen)&&(&result->string)[copied]){
            str[copied]=(&result->string)[copied];++copied;
        }
        str[copied]=0;
        printf("Identify: %s\n", str);
        esp32.uart->FreeBuffer(buf);
    } else {
        printf("No reply...\n");
        // Let's try to get messages from the receive buffer to see what has been received.
        // printf("Receive queue:\n");
        while (esp32.uart->ReceivePacket(&buf, 0) == pdTRUE) {
            printf("Buf %02x. Size: %4d. Data:\n", buf->bufnr, buf->size);
            dump_hex(buf->data, buf->size > 64 ? 64 : buf->size);
            esp32.uart->FreeBuffer(buf);
        }
        // printf("/end of Receive queue\n");
    }
    return success;
}

#if U64 && P08_SERVICE && P18_TLS
// P18N_IDENTITY_BEGIN
bool p18m_esp::read_identity(uint16_t *major,uint16_t *minor,char *name,unsigned capacity,
                              uint32_t budget_ms)
{
    if(!major||!minor||!name||!capacity)return false;
    *major=*minor=0;name[0]=0;
    if(!esp32.uart||!budget_ms||budget_ms>250)return false;
    const TickType_t started=xTaskGetTickCount();
    const TickType_t ticks=pdMS_TO_TICKS(budget_ms);
    if(!ticks)return false;
    command_buf_t *buf=0;
    if(esp32.uart->GetBuffer(&buf,ticks)!=pdTRUE)return false;
    TickType_t used=xTaskGetTickCount()-started;
    if(used>=ticks){esp32.uart->FreeBuffer(buf);return false;}
    rpc_identify_req *request=reinterpret_cast<rpc_identify_req *>(buf->data);
    request->hdr.command=CMD_IDENTIFY;
    if(!wifi_reply_register(&request->hdr)){esp32.uart->FreeBuffer(buf);return false;}
    const rpc_header_t expected=request->hdr;
    buf->size=sizeof(*request);
    // The ordinary transmitter can wait 200 ticks for queue space. This gate
    // must commit immediately; the DMA method owns/frees the request on both
    // outcomes. A zero-wait reply cleanup also releases its reserved tag.
    if(esp32.uart->TransmitPacketNonBlocking(buf)!=pdTRUE){
        buf=wifi_wait_reply(expected,0);
        if(buf)esp32.uart->FreeBuffer(buf);
        return false;
    }
    used=xTaskGetTickCount()-started;
    const uint32_t remaining_ms=used<ticks?uint32_t(ticks-used)*1000U/configTICK_RATE_HZ:0;
    buf=wifi_wait_reply(expected,int(remaining_ms));
    if(!buf)return false;
    if(!remaining_ms||TickType_t(xTaskGetTickCount()-started)>=ticks){
        esp32.uart->FreeBuffer(buf);return false;
    }
    rpc_identify_resp *reply=reinterpret_cast<rpc_identify_resp *>(buf->data);
    const unsigned offset=offsetof(rpc_identify_resp,string);
    bool valid=buf->size>int(offset)&&buf->size<=int(sizeof(buf->data))&&
        reply->hdr.command==CMD_IDENTIFY&&reply->hdr.thread==expected.thread&&
        reply->hdr.sequence==expected.sequence&&
        memchr(&reply->string,0,unsigned(buf->size)-offset);
    if(valid){
        *major=reply->major;*minor=reply->minor;
        unsigned copied=0;
        while(copied+1<capacity&&(&reply->string)[copied]){
            name[copied]=(&reply->string)[copied];++copied;
        }
        name[copied]=0;
    }
    esp32.uart->FreeBuffer(buf);
    return valid;
}
// P18N_IDENTITY_END
#endif

int wifi_getmac(uint8_t *mac)
{
    BUFARGS(identify, CMD_WIFI_GETMAC);
    TRANSMIT(getmac);
    if (result->esp_err == 0) {
        memcpy(mac, result->mac, 6);
    } else {
        printf("Get MAC returned %d as error code.\n", result->esp_err);
    }
    RETURN_ESP;
}

#if U64 == 2
int wifi_set_serial(const char *serial)
{
    BUFARGS(set_serial, CMD_SET_SERIAL);
    strncpy(args->serial, serial, 16);
    TRANSMIT(espcmd);
    RETURN_ESP;
}

int wifi_get_serial(char *serial)
{
    BUFARGS(identify, CMD_GET_SERIAL);
    TRANSMIT(get_serial);
    if (result->esp_err == 0) {
        memcpy(serial, result->serial, 16);
    } else {
        strcpy(serial, "-Not set-");
        printf("Get Serial returned %d as error code.\n", result->esp_err);
    }
    RETURN_ESP;
}
#endif

int wifi_is_connected(uint8_t &status)
{
    BUFARGS(identify, CMD_WIFI_IS_CONNECTED);
    TRANSMIT(get_connection);
    if (result->esp_err == 0) {
        status = result->status;
    } else {
        printf("Get connection status returned %d as error code.\n", result->esp_err);
    }
    RETURN_ESP;
}

/*
int wifi_get_time(const char *timezone, esp_datetime_t *time)
{
    BUFARGS(get_time, CMD_GET_TIME);
    TRANSMIT(get_time);
    if (result->esp_err == 0) {
        time->year = result->datetime.year;
        time->month = result->datetime.month;
        time->day = result->datetime.day;
        time->hour = result->datetime.hour;
        time->minute = result->datetime.minute;
        time->second = result->datetime.second;
        time->weekday = result->datetime.weekday;
    } else {
        printf("Get time returned %d as error code.\n", result->esp_err);
    }
    RETURN_ESP;
}
*/
int wifi_scan(void *a)
{
    ultimate_ap_records_t *aps = (ultimate_ap_records_t *)a;

    BUFARGS(identify, CMD_WIFI_SCAN);
    TRANSMIT_T(scan, WIFI_SLOW_TIMEOUT_MS);
    ENTER_SAFE_SECTION;
    memcpy(aps, &(result->rec), sizeof(ultimate_ap_records_t));
    LEAVE_SAFE_SECTION;
    RETURN_ESP;
}

int wifi_wifi_connect(const char *ssid, const char *password, uint8_t auth)
{
    BUFARGS(wifi_connect, CMD_WIFI_CONNECT);

    bzero(args->ssid, 32);
    bzero(args->password, 64);
    strncpy(args->ssid, ssid, 32);
    strncpy(args->password, password, 64);
    args->auth_mode = auth;

    TRANSMIT_T(scan, WIFI_SLOW_TIMEOUT_MS);
    RETURN_ESP;
}

int wifi_wifi_autoconnect()
{
    BUFARGS(identify, CMD_WIFI_AUTOCONNECT);
    TRANSMIT_T(espcmd, WIFI_SLOW_TIMEOUT_MS);
    RETURN_ESP;
}

int wifi_wifi_disconnect()
{
    BUFARGS(identify, CMD_WIFI_DISCONNECT);
    TRANSMIT(espcmd);
    RETURN_ESP;
}

int wifi_machine_off()
{
    BUFARGS(identify, CMD_MACHINE_OFF);
    TRANSMIT(espcmd);
    RETURN_ESP;
}

#if U64 == 2
int wifi_machine_reboot()
{
    BUFARGS(identify, CMD_MACHINE_REBOOT);
    TRANSMIT(espcmd);
    RETURN_ESP;
}
#endif

int wifi_forget_aps()
{
    BUFARGS(identify, CMD_CLEAR_APS);
#if U64 && P08_SERVICE
    p08::p15_wifi_note_forget_started();
#endif
    buf = wifi_transmit(buf, WIFI_REPLY_TIMEOUT_MS);
    if (!buf) {
#if U64 && P08_SERVICE
        p08::p15_wifi_note_forget_finished(false);
#endif
        printf("*** NO REPLY FROM WIFI MODULE.\n");
        return -1;
    }
    rpc_espcmd_resp *result = (rpc_espcmd_resp *)buf->data;
#if U64 && P08_SERVICE
    // The controller erases APs before it disconnects. An error therefore
    // leaves saved metadata unknown, rather than restoring an obsolete key.
    p08::p15_wifi_note_forget_finished(result->esp_err==0);
#endif
    RETURN_ESP;
}


#if U64 == 2
int wifi_enable()
{
    BUFARGS(identify, CMD_WIFI_ENABLE);
    TRANSMIT(espcmd);
    RETURN_ESP;
}

int wifi_disable()
{
    BUFARGS(identify, CMD_WIFI_DISABLE);
    TRANSMIT(espcmd);
    RETURN_ESP;
}

int wifi_get_voltages(voltages_t *voltages)
{
    BUFARGS(identify, CMD_GET_VOLTAGES);
    TRANSMIT(get_voltages);
    voltages->vbus = result->vbus;
    voltages->vaux = result->vaux;
    voltages->v50  = result->v50;
    voltages->v33  = result->v33;
    voltages->v18  = result->v18;
    voltages->v10  = result->v10;
    voltages->vusb = result->vusb;
    RETURN_ESP;
}
#endif

int wifi_modem_enable(bool enable)
{
    BUFARGS(identify, (enable) ? CMD_MODEM_ON : CMD_MODEM_OFF);
    TRANSMIT(espcmd);
    RETURN_ESP;
}

const char *no_wifi_buf = "*** NO BUFFER TO TRANSMIT ANYTHING.\n";
const char *no_wifi_slot = "*** NO REPLY SLOT FOR THE WIFI MODULE.\n";

