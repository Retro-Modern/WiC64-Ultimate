/* Additive P18 TLS crypto coprocessor. GPL-3.0-or-later.
 * TCP, DNS and adapter ownership remain entirely on the Ultimate.
 * TLS dispatch uses bounded queues; its worker alone owns the TLS contexts.
 * Optional bootstrap generation uses a separate bounded boot-seeded DRBG.
 */
#include "p18_tls.h"
#include "p18_bootstrap.h"
#include "p18_tls_wire.h"
#include "my_uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_random.h"
#include "p18_ca.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_time.h"
#include "sdkconfig.h"
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>

#if !defined(CONFIG_MBEDTLS_HAVE_TIME_DATE) || !CONFIG_MBEDTLS_HAVE_TIME_DATE || !defined(CONFIG_MBEDTLS_PLATFORM_TIME_ALT) || !CONFIG_MBEDTLS_PLATFORM_TIME_ALT
#error P18 requires certificate date verification and per-worker trusted UTC
#endif
_Static_assert(sizeof(time_t)>=8,"P18 requires 64-bit TLS UTC");
_Static_assert(CMD_BUF_SIZE>=P18_TLS_HEADER+P18_TLS_CHUNK,"P18 frame does not fit UART");
#define RING_BYTES 4096U
#define TLS_STACK_BYTES 12288U

typedef struct {uint8_t data[RING_BYTES];unsigned head,used;} ring_t;
typedef struct {
    uint64_t token,utc;
    uint64_t clock_ticks;
    TickType_t started;
    TickType_t clock_tick;
    uint32_t budget;
    TickType_t operation_started;
    uint32_t operation_budget,operation_sequence;
    bool active,abort,initializing,ready,write_busy,write_done,transport_eof,clean_eof;
    bool persistent,operation_active,operation_ending,worker_inflight;
    uint8_t terminal;
    int detail;
    char host[254];
    uint8_t entropy[64],write_data[P18_TLS_CHUNK];
    unsigned write_size,write_offset;
    ring_t encrypted_in,encrypted_out,plaintext;
} session_t;
static session_t session;
static portMUX_TYPE lock=portMUX_INITIALIZER_UNLOCKED;
static TaskHandle_t worker;
static bool starting;
static uint32_t boot_nonce,generation;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config config;
static mbedtls_ctr_drbg_context random_context;
static bool crypto_initialized;

static void wipe(void *data,size_t length){volatile uint8_t *p=data;while(length--)*p++=0;}
static uint32_t elapsed_ms(void){return (uint32_t)(xTaskGetTickCount()-session.started)*(1000U/configTICK_RATE_HZ);}
static bool expired(void){
    if(!session.persistent)return elapsed_ms()>=session.budget;
    return session.operation_active&&
        (uint32_t)(xTaskGetTickCount()-session.operation_started)*(1000U/configTICK_RATE_HZ)>=session.operation_budget;
}
static unsigned space(const ring_t *r){return RING_BYTES-r->used;}
static void push(ring_t *r,const uint8_t *data,unsigned length){for(unsigned i=0;i<length;i++)r->data[(r->head+r->used+i)%RING_BYTES]=data[i];r->used+=length;}
static unsigned pop(ring_t *r,uint8_t *data,unsigned length){if(length>r->used)length=r->used;for(unsigned i=0;i<length;i++){data[i]=r->data[r->head];r->data[r->head]=0;r->head=(r->head+1)%RING_BYTES;}r->used-=length;return length;}
/* Called with lock held. Persistent IDLE still receives scheduler turns, so
 * each bounded uint32 tick delta is accumulated before the next tick wrap.
 * The trusted UTC origin and original session.started are never renewed. */
static void advance_persistent_clock(void){
    if(session.active&&session.persistent){
        TickType_t now=xTaskGetTickCount();session.clock_ticks+=(TickType_t)(now-session.clock_tick);session.clock_tick=now;
    }
}

/* Mbed TLS also serves the unmodified recovery task. Only this worker sees the
 * CPU's validated per-session UTC; recovery and other users keep libc time(). */
static mbedtls_time_t trusted_time(mbedtls_time_t *output){
    mbedtls_time_t value;
    if(xTaskGetCurrentTaskHandle()==worker){
        portENTER_CRITICAL(&lock);advance_persistent_clock();
        value=(mbedtls_time_t)(session.utc+(session.persistent?session.clock_ticks/configTICK_RATE_HZ:elapsed_ms()/1000U));portEXIT_CRITICAL(&lock);
    }else value=(mbedtls_time_t)time(NULL);
    if(output)*output=value;
    return value;
}
static int entropy(void *unused,unsigned char *output,size_t length){
    (void)unused;
    /* CPU contributes a fresh durable-journal-derived 64-byte private value for
     * each BEGIN. Hardware randomness supplements it even when RF is disabled. */
    if(length>sizeof(session.entropy))return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    esp_fill_random(output,length);
    for(size_t i=0;i<length;i++)output[i]^=session.entropy[i];
    return 0;
}
static int send_record(void *unused,const unsigned char *data,size_t length){
    (void)unused;int result;
    portENTER_CRITICAL(&lock);
    if(session.abort||expired())result=MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    else{unsigned n=space(&session.encrypted_out);if(n>length)n=(unsigned)length;if(n){push(&session.encrypted_out,data,n);result=(int)n;}else result=MBEDTLS_ERR_SSL_WANT_WRITE;}
    portEXIT_CRITICAL(&lock);return result;
}
static int receive_record(void *unused,unsigned char *data,size_t length){
    (void)unused;int result;
    portENTER_CRITICAL(&lock);
    if(session.abort||expired())result=MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    else if(session.encrypted_in.used)result=(int)pop(&session.encrypted_in,data,(unsigned)length);
    else result=session.transport_eof?MBEDTLS_ERR_SSL_CONN_EOF:MBEDTLS_ERR_SSL_WANT_READ;
    portEXIT_CRITICAL(&lock);return result;
}
static void destroy_crypto(void){
    if(crypto_initialized){mbedtls_ssl_free(&ssl);mbedtls_ssl_config_free(&config);mbedtls_ctr_drbg_free(&random_context);crypto_initialized=false;}
    wipe(&ssl,sizeof(ssl));wipe(&config,sizeof(config));wipe(&random_context,sizeof(random_context));
}
static int create_crypto(void){
    mbedtls_ssl_init(&ssl);mbedtls_ssl_config_init(&config);mbedtls_ctr_drbg_init(&random_context);crypto_initialized=true;
    int result=mbedtls_platform_set_time(trusted_time);if(result)return result;
    static const unsigned char label[]="Ultimate-P18-TLS-BIO-v1";
    result=mbedtls_ctr_drbg_seed(&random_context,entropy,NULL,label,sizeof(label)-1);if(result)return result;
    result=mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);if(result)return result;
    mbedtls_ssl_conf_authmode(&config,MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&config,mbedtls_ctr_drbg_random,&random_context);
    result=p18_ca_attach(&config);if(result)return result;
    result=mbedtls_ssl_setup(&ssl,&config);if(result)return result;
    result=mbedtls_ssl_set_hostname(&ssl,session.host);if(result)return result;
    mbedtls_ssl_set_bio(&ssl,NULL,send_record,receive_record,NULL);
    return 0;
}
static bool wants(int result){return result==MBEDTLS_ERR_SSL_WANT_READ||result==MBEDTLS_ERR_SSL_WANT_WRITE;}
static void fail_crypto(int result){
    uint32_t verify=mbedtls_ssl_get_verify_result(&ssl);
    portENTER_CRITICAL(&lock);
    if(!session.abort){session.terminal=verify||result==MBEDTLS_ERR_X509_CERT_VERIFY_FAILED?P18_TLS_VERIFY:P18_TLS_FAILED;session.detail=result;}
    portEXIT_CRITICAL(&lock);
}
/* One bounded scheduler turn. A cryptographic primitive may occupy this worker
 * longer, but never holds the dispatcher lock or a UART buffer while doing so. */
static void worker_step_active(void){
    bool active,abort,terminal,initialize;
    portENTER_CRITICAL(&lock);
    active=session.active;abort=session.abort;
    if(active&&!abort&&expired()){session.terminal=P18_TLS_TIMEOUT;session.abort=true;abort=true;}
    terminal=session.terminal!=0;initialize=session.initializing;
    portEXIT_CRITICAL(&lock);
    if(!active)return;
    if(abort||terminal){
        destroy_crypto();
        portENTER_CRITICAL(&lock);
        wipe(session.entropy,sizeof(session.entropy));wipe(session.write_data,sizeof(session.write_data));
        wipe(&session.encrypted_in,sizeof(session.encrypted_in));wipe(&session.encrypted_out,sizeof(session.encrypted_out));wipe(&session.plaintext,sizeof(session.plaintext));
        session.ready=false;session.write_busy=false;session.active=false;session.initializing=false;
        if(!session.terminal)session.terminal=P18_TLS_CLOSED;
        portEXIT_CRITICAL(&lock);return;
    }
    if(initialize){
        int result=create_crypto();
        portENTER_CRITICAL(&lock);session.initializing=false;portEXIT_CRITICAL(&lock);
        if(result){fail_crypto(result);return;}
    }
    portENTER_CRITICAL(&lock);bool ready=session.ready;portEXIT_CRITICAL(&lock);
    if(!ready){
        int result=mbedtls_ssl_handshake(&ssl);
        if(result==0){
            if(mbedtls_ssl_get_verify_result(&ssl)){fail_crypto(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);return;}
            portENTER_CRITICAL(&lock);if(!session.abort&&!expired())session.ready=true;portEXIT_CRITICAL(&lock);
        }else if(!wants(result))fail_crypto(result);
        return;
    }
    portENTER_CRITICAL(&lock);bool writing=session.write_busy;unsigned offset=session.write_offset,length=session.write_size;portEXIT_CRITICAL(&lock);
    if(writing){
        int result=mbedtls_ssl_write(&ssl,session.write_data+offset,length-offset);
        if(result>0){
            portENTER_CRITICAL(&lock);
            if((unsigned)result>session.write_size-session.write_offset){session.terminal=P18_TLS_FAILED;session.detail=MBEDTLS_ERR_SSL_INTERNAL_ERROR;}
            else{session.write_offset+=(unsigned)result;if(session.write_offset==session.write_size){wipe(session.write_data,sizeof(session.write_data));session.write_busy=false;session.write_done=true;}}
            portEXIT_CRITICAL(&lock);
        }else if(!wants(result))fail_crypto(result?result:MBEDTLS_ERR_SSL_INTERNAL_ERROR);
        return;
    }
    portENTER_CRITICAL(&lock);unsigned available=space(&session.plaintext);bool eof=session.clean_eof;
    bool ending=session.persistent&&session.operation_ending;portEXIT_CRITICAL(&lock);
    if(!available||eof||ending)return;
    uint8_t bytes[P18_TLS_CHUNK];if(available>sizeof(bytes))available=sizeof(bytes);
    int result=mbedtls_ssl_read(&ssl,bytes,available);
    if(result>0){portENTER_CRITICAL(&lock);if(!session.abort&&!expired())push(&session.plaintext,bytes,(unsigned)result);portEXIT_CRITICAL(&lock);}
    else if(result==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){portENTER_CRITICAL(&lock);session.clean_eof=true;portEXIT_CRITICAL(&lock);}
    else if(!wants(result))fail_crypto(result?result:MBEDTLS_ERR_SSL_CONN_EOF);
    wipe(bytes,sizeof(bytes));
}
static void worker_step(void){
    /* END is acknowledged only after this complete unlocked crypto turn has
     * returned. Its legitimate plaintext/output remains owned by the session;
     * a later operation must never adopt an earlier in-flight primitive. */
    portENTER_CRITICAL(&lock);
    advance_persistent_clock();
    bool scheduled=session.active&&(session.abort||session.terminal||expired()||
        !session.persistent||(session.operation_active&&(!session.operation_ending||session.write_busy)));
    if(scheduled)session.worker_inflight=true;
    portEXIT_CRITICAL(&lock);
    if(!scheduled)return;
    worker_step_active();
    portENTER_CRITICAL(&lock);session.worker_inflight=false;portEXIT_CRITICAL(&lock);
}
static void tls_worker(void *unused){(void)unused;for(;;){worker_step();vTaskDelay(1);}}
static bool ensure_worker(void){
    portENTER_CRITICAL(&lock);if(worker){portEXIT_CRITICAL(&lock);return true;}if(starting){portEXIT_CRITICAL(&lock);return false;}starting=true;portEXIT_CRITICAL(&lock);
    TaskHandle_t created=NULL;
    BaseType_t result=xTaskCreate(tls_worker,"P18 TLS",TLS_STACK_BYTES,NULL,tskIDLE_PRIORITY+1,&created);
    portENTER_CRITICAL(&lock);if(result==pdPASS)worker=created;starting=false;portEXIT_CRITICAL(&lock);
    return result==pdPASS;
}
static bool valid_hostname(const uint8_t *name,unsigned length){
    if(length<2||length>254||name[length-1]!=0)return false;
    unsigned label=0;bool has_letter=false;
    for(unsigned i=0;i<length-1;i++){
        uint8_t c=name[i];
        if(c=='.'){if(!label||label>63||name[i-1]=='-')return false;label=0;continue;}
        if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'))return false;
        if(!label&&c=='-')return false;
        label++;
        if(label>63)return false;
        if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||c=='-')has_letter=true;
    }
    return has_letter&&label&&name[length-2]!='-';
}
static unsigned flags(void){return (session.ready?P18_TLS_FLAG_READY:0)|(session.write_done?P18_TLS_FLAG_WRITE_DONE:0)|(session.clean_eof?P18_TLS_FLAG_CLEAN_EOF:0);}
static void reply(command_buf_t *buffer,uint8_t status,uint16_t length,uint64_t token,uint32_t state,int detail){
    /* Retired request bytes can include seed or plaintext even on rejection.
     * Preserve the actual reply body, wipe only the bounded old request tail,
     * and finish before transferring ownership to the UART. */
    unsigned old_length=buffer->size>0?(unsigned)buffer->size:0;
    if(old_length>CMD_BUF_SIZE)old_length=CMD_BUF_SIZE;
    unsigned new_length=P18_TLS_HEADER+length;
    if(old_length>new_length)wipe(buffer->data+new_length,old_length-new_length);
    p18_envelope(buffer->data,status,length,token,state,(uint32_t)detail);buffer->size=new_length;
    my_uart_transmit_packet(UART_NUM_1,buffer); /* UART now owns buffer, including on failure. */
}
void cmd_p18_tls(command_buf_t *buffer){
    uint8_t *data=buffer->data;unsigned length=0;uint8_t op=0;uint64_t token=0;uint32_t arg=0,budget=0;
    if(buffer->size<4){memset(data,0,4);data[0]=P18_TLS_COMMAND;data[1]=0xff;reply(buffer,P18_TLS_BAD,0,0,0,0);return;}
    if(buffer->size<P18_TLS_HEADER||buffer->size>P18_TLS_HEADER+P18_TLS_CHUNK||!p18_magic(data)||data[8]!=P18_TLS_VERSION){reply(buffer,P18_TLS_BAD,0,0,0,0);return;}
    length=p18_get16(data+10);op=data[9];token=p18_get64(data+12);arg=p18_get32(data+20);budget=p18_get32(data+24);
    if(length>P18_TLS_CHUNK||(unsigned)buffer->size!=P18_TLS_HEADER+length||op>P18_TLS_OPERATION){reply(buffer,P18_TLS_BAD,0,token,0,0);return;}
    if(op==P18_TLS_CAPS){
        if(length||token||(arg&&arg!=P18_TLS_OPERATION_QUERY&&arg!=P18_TLS_CA_QUERY)||budget){reply(buffer,P18_TLS_BAD,0,0,0,0);return;}
        /* The ordinary v1 CAPS response stays exact for existing CFW clients. */
        p18_put32(data+P18_TLS_HEADER,P18_TLS_CAP_FEATURES|(arg?P18_TLS_CAP_OPERATION_WINDOWS:0)|(arg==P18_TLS_CA_QUERY?P18_TLS_CAP_TRUSTED_CA:0));p18_put16(data+P18_TLS_HEADER+4,P18_TLS_CHUNK);p18_put16(data+P18_TLS_HEADER+6,0);
        reply(buffer,P18_TLS_OK,8,0,0,0);return;
    }
    if(op==P18_TLS_BOOTSTRAP){
        if(length||token||arg||budget){reply(buffer,P18_TLS_BAD,0,0,0,0);return;}
        uint8_t status=p18_bootstrap_get_seed(data+P18_TLS_HEADER);
        reply(buffer,status,status==P18_TLS_OK?32:0,0,0,0);return;
    }
    if(op==P18_TLS_BEGIN){
        if(token||(arg&&arg!=P18_TLS_BEGIN_PERSISTENT)||!budget||budget>P18_TLS_MAX_BUDGET||length<74||!valid_hostname(data+P18_TLS_HEADER+72,length-72)){reply(buffer,P18_TLS_BAD,0,0,0,0);return;}
        uint64_t utc=p18_get64(data+P18_TLS_HEADER);uint8_t any=0;for(unsigned i=0;i<64;i++)any|=data[P18_TLS_HEADER+8+i];
        if(utc<1609459200ULL||utc>4102444800ULL||!any){reply(buffer,P18_TLS_BAD,0,0,0,0);return;}
        if(!ensure_worker()){reply(buffer,P18_TLS_BUSY,0,0,0,0);return;}
        portENTER_CRITICAL(&lock);
        if(session.active||session.worker_inflight||generation==UINT32_MAX){
            /* A validated new BEGIN declares a new single-session owner. Both
             * legacy HTTP and persistent OPEN may retire an orphaned persistent
             * IDLE context (e.g. after RAM CFW reload or a lost CLOSE). No BEGIN
             * may steal legacy, handshake or active operation work. Reply BUSY
             * until the worker has destroyed the old context; allocation and a
             * fresh token are allowed only after its inflight fence clears. */
            if(generation!=UINT32_MAX&&session.active&&session.persistent&&session.ready&&
               !session.operation_active&&!session.operation_ending&&!session.worker_inflight&&
               !session.write_busy&&!session.encrypted_out.used){
                session.abort=true;if(!session.terminal)session.terminal=P18_TLS_CLOSED;
            }
            portEXIT_CRITICAL(&lock);reply(buffer,P18_TLS_BUSY,0,0,0,0);return;
        }
        if(!boot_nonce){boot_nonce=esp_random();if(!boot_nonce)boot_nonce=1;}
        memset(&session,0,sizeof(session));session.token=((uint64_t)boot_nonce<<32)|++generation;session.utc=utc;session.budget=budget;session.started=xTaskGetTickCount();
        session.persistent=arg==P18_TLS_BEGIN_PERSISTENT;
        session.clock_tick=session.started;
        session.operation_active=session.persistent;session.operation_started=session.started;session.operation_budget=budget;
        memcpy(session.entropy,data+P18_TLS_HEADER+8,64);memcpy(session.host,data+P18_TLS_HEADER+72,length-72);session.initializing=true;session.active=true;token=session.token;
        portEXIT_CRITICAL(&lock);wipe(data+P18_TLS_HEADER,length);reply(buffer,P18_TLS_OK,0,token,0,0);return;
    }
    /* Only an explicit negotiated START from quiescent IDLE creates a new
     * immutable window. PUMP/STATUS/READ/WRITE never renew its deadline. */
    if(budget>P18_TLS_MAX_BUDGET||((op==P18_TLS_STATUS||op==P18_TLS_CLOSE)&&length)||
       (op==P18_TLS_WRITE&&(!length||arg))||(op==P18_TLS_READ&&(length||!arg||arg>P18_TLS_CHUNK))||
       (op==P18_TLS_PUMP&&(arg&~P18_TLS_PUMP_EOF))||((op==P18_TLS_STATUS||op==P18_TLS_CLOSE)&&arg)||
       (op==P18_TLS_OPERATION&&(!token||length))){
        reply(buffer,P18_TLS_BAD,0,token,0,0);return;
    }
    portENTER_CRITICAL(&lock);
    if(!token||token!=session.token){portEXIT_CRITICAL(&lock);reply(buffer,P18_TLS_CLOSED,0,token,0,0);return;}
    if(session.active&&!session.abort&&expired()){session.terminal=P18_TLS_TIMEOUT;session.abort=true;}
    uint8_t status=P18_TLS_OK;unsigned result_length=0;
    if(op==P18_TLS_CLOSE){session.abort=true;if(!session.terminal)session.terminal=P18_TLS_CLOSED;status=P18_TLS_OK;}
    else if(session.terminal)status=session.terminal;
    else if(!session.active)status=P18_TLS_CLOSED;
    else if(op==P18_TLS_OPERATION){
        if(!session.persistent)status=P18_TLS_BAD;
        else if(budget){
            if(session.operation_sequence==UINT32_MAX||arg!=session.operation_sequence+1)status=P18_TLS_BAD;
            else if(session.operation_active||session.worker_inflight)status=P18_TLS_BUSY;
            else{
                session.operation_sequence=arg;session.operation_started=xTaskGetTickCount();
                session.operation_budget=budget;session.operation_active=true;session.operation_ending=false;
            }
        }else if(arg!=session.operation_sequence||!session.ready)status=P18_TLS_BAD;
        else if(session.operation_active){
            session.operation_ending=true;
            if(session.worker_inflight||session.write_busy||session.encrypted_out.used)status=P18_TLS_BUSY;
            else{session.operation_active=false;session.operation_ending=false;}
        }
    }
    else if(session.persistent&&!session.operation_active&&op!=P18_TLS_STATUS)status=P18_TLS_BAD;
    else if(op==P18_TLS_PUMP){
        if((session.transport_eof&&length)||length>space(&session.encrypted_in))status=P18_TLS_BUSY;
        else{push(&session.encrypted_in,data+P18_TLS_HEADER,length);if(arg&P18_TLS_PUMP_EOF)session.transport_eof=true;result_length=pop(&session.encrypted_out,data+P18_TLS_HEADER,P18_TLS_CHUNK);}
    }else if(op==P18_TLS_WRITE){
        if(!session.ready||session.write_busy||session.clean_eof||session.operation_ending)status=P18_TLS_BUSY;
        else{memcpy(session.write_data,data+P18_TLS_HEADER,length);session.write_size=length;session.write_offset=0;session.write_busy=true;session.write_done=false;wipe(data+P18_TLS_HEADER,length);}
    }else if(op==P18_TLS_READ){
        result_length=pop(&session.plaintext,data+P18_TLS_HEADER,arg);
        if(!result_length)status=session.clean_eof?P18_TLS_EOF:P18_TLS_WANT;
    }
    uint32_t state=flags();int detail=session.detail;
    portEXIT_CRITICAL(&lock);
    reply(buffer,status,(uint16_t)result_length,token,state,detail);
}
#ifdef P18_TLS_HOST_TEST
/* Test code includes this production translation unit to drive scheduler turns;
 * no alternate trust or transport hooks are compiled into production firmware. */
#endif
