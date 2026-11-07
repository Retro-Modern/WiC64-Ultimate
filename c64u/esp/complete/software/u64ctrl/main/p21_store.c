/* Private bounded dispatcher plus exclusive NVS worker. Flash never runs under
 * a spinlock and the worker never retains a UART buffer or a TLS context. */
#include "p21_store.h"
#include "p21_store_wire.h"
#include "p21_store_backend.h"
#include "my_uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_random.h"
#include <string.h>
#include <stdbool.h>
#include <limits.h>
_Static_assert(CMD_BUF_SIZE>=P21_STORE_HEADER+P21_STORE_CHUNK,"Store frame exceeds UART capacity");
typedef struct {
 uint64_t token,generation,expected;
 uint32_t length,crc,offset,budget;
 TickType_t started;
 unsigned phase,status,job;
 int detail;
 bool inflight,abort;
 uint8_t data[P21_STORE_MAX];
} store_t;
static store_t state;
static portMUX_TYPE lock=portMUX_INITIALIZER_UNLOCKED;
static TaskHandle_t worker;
static bool starting;
static uint32_t nonce,serial;
static void wipe(void*p,size_t n){volatile uint8_t*b=p;while(n--)*b++=0;}
static bool expired(void){return (uint32_t)(xTaskGetTickCount()-state.started)*(1000U/configTICK_RATE_HZ)>=state.budget;}
static void stop(unsigned status){wipe(state.data,sizeof(state.data));state.status=status;state.phase=P21_STORE_STOPPED;state.job=0;}
static void meta(uint8_t*p){p21_put64(p,state.generation);p21_put32(p+8,state.length);p21_put32(p+12,state.crc);}
static void worker_step(void){
 unsigned job;uint64_t expected;uint32_t length,crc;
 portENTER_CRITICAL(&lock);
 if(!state.inflight&&state.token&&state.phase!=P21_STORE_DURABLE&&state.phase!=P21_STORE_STOPPED&&expired())stop(P21_STORE_TIMEOUT);
 job=state.job;
 if(!job||state.inflight){portEXIT_CRITICAL(&lock);return;}
 if(state.abort||expired()){stop(P21_STORE_TIMEOUT);portEXIT_CRITICAL(&lock);return;}
 state.inflight=true;state.job=0;expected=state.expected;length=state.length;crc=state.crc;
 portEXIT_CRITICAL(&lock);
 int detail=0,result;uint64_t generation=0;uint32_t gotlen=0,gotcrc=0;
 if(job==P21_STORE_COMMIT)result=p21_backend_commit(state.data,length,expected,crc,&detail);
 else result=p21_backend_load(state.data,&gotlen,&generation,&gotcrc,&detail);
 portENTER_CRITICAL(&lock);
 state.detail=detail;
 if(job==P21_STORE_COMMIT){
  wipe(state.data,sizeof(state.data));state.status=result;
  state.phase=result==P21_STORE_OK?P21_STORE_DURABLE:P21_STORE_STOPPED;
 }else if(state.abort||expired())stop(P21_STORE_TIMEOUT);
 else if(job==P21_STORE_LOAD){
  state.status=result;state.generation=generation;state.length=gotlen;state.crc=gotcrc;
  state.phase=(result==P21_STORE_OK||result==P21_STORE_EMPTY)?P21_STORE_LOADED:P21_STORE_STOPPED;
  if(result!=P21_STORE_OK)wipe(state.data,sizeof(state.data));
 }else{
  wipe(state.data,sizeof(state.data));
  if(result!=P21_STORE_OK&&result!=P21_STORE_EMPTY)stop(result);
  else if(generation!=expected)stop(P21_STORE_CONFLICT);
  else{state.generation=expected+1;state.phase=P21_STORE_STAGING;state.status=P21_STORE_OK;}
 }
 state.inflight=false;
 portEXIT_CRITICAL(&lock);
}
static void store_worker(void*unused){(void)unused;for(;;){worker_step();vTaskDelay(1);}}
static bool ensure_worker(void){
 portENTER_CRITICAL(&lock);if(worker){portEXIT_CRITICAL(&lock);return true;}if(starting){portEXIT_CRITICAL(&lock);return false;}starting=true;portEXIT_CRITICAL(&lock);
 TaskHandle_t created=NULL;BaseType_t ok=xTaskCreate(store_worker,"Private NVS",8192,NULL,tskIDLE_PRIORITY+1,&created);
 portENTER_CRITICAL(&lock);if(ok==pdPASS)worker=created;starting=false;portEXIT_CRITICAL(&lock);return ok==pdPASS;
}
static void reply(command_buf_t*b,unsigned status,unsigned count,uint64_t token,uint32_t arg,int detail){
 /* Wipe the entire retired request tail, not only the shorter reply size. */
 unsigned end=P21_STORE_HEADER+count;
 if(end<CMD_BUF_SIZE)wipe(b->data+end,CMD_BUF_SIZE-end);
 p21_envelope(b->data,(uint8_t)status,(uint16_t)count,token,arg,(uint32_t)detail);b->size=(int)end;
 my_uart_transmit_packet(UART_NUM_1,b);
}
void cmd_p21_store(command_buf_t*b){
 uint8_t*d=b->data;
 if(b->size<4){wipe(d,CMD_BUF_SIZE);d[0]=P21_STORE_COMMAND;d[1]=0xff;reply(b,P21_STORE_BAD,0,0,0,0);return;}
 if(b->size<P21_STORE_HEADER||b->size>P21_STORE_HEADER+P21_STORE_CHUNK||!p21_magic(d)||d[8]!=P21_STORE_VERSION){reply(b,P21_STORE_BAD,0,0,0,0);return;}
 unsigned op=d[9],n=p21_get16(d+10);uint64_t token=p21_get64(d+12);uint32_t arg=p21_get32(d+20),budget=p21_get32(d+24);
 if(op>P21_STORE_READ||n>P21_STORE_CHUNK||(unsigned)b->size!=P21_STORE_HEADER+n){reply(b,P21_STORE_BAD,0,token,0,0);return;}
 if(op==P21_STORE_CAPS){
  if(n||token||arg||budget){reply(b,P21_STORE_BAD,0,0,0,0);return;}
  p21_put32(d+28,P21_STORE_FEATURES);p21_put32(d+32,P21_STORE_MAX);p21_put16(d+36,P21_STORE_CHUNK);p21_put16(d+38,0);reply(b,P21_STORE_OK,12,0,0,0);return;
 }
 if(op==P21_STORE_LOAD||op==P21_STORE_BEGIN){
  if(token||arg||!budget||budget>P21_STORE_MAX_BUDGET||n!=(op==P21_STORE_BEGIN?P21_STORE_META:0)){reply(b,P21_STORE_BAD,0,0,0,0);return;}
  uint64_t expected=0;uint32_t length=0,crc=0;
  if(op==P21_STORE_BEGIN){expected=p21_get64(d+28);length=p21_get32(d+36);crc=p21_get32(d+40);if(expected==UINT64_MAX||length>P21_STORE_MAX){reply(b,P21_STORE_BAD,0,0,0,0);return;}}
  if(!ensure_worker()){reply(b,P21_STORE_BUSY,0,0,0,0);return;}
  portENTER_CRITICAL(&lock);
  if(state.inflight||state.job||serial==UINT32_MAX){portEXIT_CRITICAL(&lock);reply(b,P21_STORE_BUSY,0,0,0,0);return;}
  /* A new single-owner operation may retire a quiescent orphan from a RAM
   * application reload. It can never steal an in-flight flash operation. */
  if(!nonce){nonce=esp_random();if(!nonce)nonce=1;}
  wipe(&state,sizeof(state));state.token=((uint64_t)nonce<<32)|++serial;state.expected=expected;state.length=length;state.crc=crc;state.budget=budget;state.started=xTaskGetTickCount();
  state.phase=op==P21_STORE_LOAD?P21_STORE_LOADING:P21_STORE_CHECKING;state.status=P21_STORE_BUSY;state.job=op;token=state.token;
  portEXIT_CRITICAL(&lock);reply(b,P21_STORE_BUSY,0,token,op==P21_STORE_LOAD?P21_STORE_LOADING:P21_STORE_CHECKING,0);return;
 }
 if(!token||budget||((op==P21_STORE_STATUS||op==P21_STORE_COMMIT||op==P21_STORE_CLOSE)&&(n||arg))||
   (op==P21_STORE_WRITE&&(!n))||(op==P21_STORE_READ&&(n!=2||!p21_get16(d+28)||p21_get16(d+28)>P21_STORE_CHUNK))){reply(b,P21_STORE_BAD,0,token,0,0);return;}
 portENTER_CRITICAL(&lock);
 if(token!=state.token){portEXIT_CRITICAL(&lock);reply(b,P21_STORE_CLOSED,0,token,0,0);return;}
 if(!state.inflight&&!state.job&&state.phase!=P21_STORE_DURABLE&&state.phase!=P21_STORE_STOPPED&&expired())stop(P21_STORE_TIMEOUT);
 unsigned status=state.status,count=0,phase=state.phase;int detail=state.detail;
 if(op==P21_STORE_CLOSE){
  if(state.inflight){state.abort=true;status=state.phase==P21_STORE_COMMITTING?P21_STORE_UNKNOWN:P21_STORE_BUSY;}
  else{stop(P21_STORE_CLOSED);status=P21_STORE_OK;phase=state.phase;}
 }else if(state.inflight||state.job){status=state.phase==P21_STORE_COMMITTING&&expired()?P21_STORE_UNKNOWN:P21_STORE_BUSY;}
 else if(op==P21_STORE_WRITE){
  if(state.phase!=P21_STORE_STAGING)status=state.status==P21_STORE_OK?P21_STORE_BAD:state.status;
  else if(arg!=state.offset||n>state.length-state.offset)status=P21_STORE_BAD;
  else{memcpy(state.data+state.offset,d+28,n);state.offset+=n;status=P21_STORE_OK;phase=state.offset;}
 }else if(op==P21_STORE_COMMIT){
  if(state.phase==P21_STORE_STAGING){
   if(state.offset!=state.length||p21_crc32(state.data,state.length)!=state.crc)status=P21_STORE_BAD;
   else{state.phase=P21_STORE_COMMITTING;state.status=P21_STORE_BUSY;state.job=P21_STORE_COMMIT;status=P21_STORE_BUSY;phase=state.phase;}
  }else if(state.phase!=P21_STORE_DURABLE&&state.phase!=P21_STORE_STOPPED)status=P21_STORE_BAD;
 }else if(op==P21_STORE_READ){
  if(state.phase!=P21_STORE_LOADED||state.status!=P21_STORE_OK||arg>state.length)status=state.status==P21_STORE_OK?P21_STORE_BAD:state.status;
  else{count=p21_get16(d+28);if(count>state.length-arg)count=state.length-arg;memcpy(d+28,state.data+arg,count);status=P21_STORE_OK;phase=arg;}
 }
 if((op==P21_STORE_STATUS||op==P21_STORE_COMMIT)&&(status==P21_STORE_OK||status==P21_STORE_EMPTY)){meta(d+28);count=P21_STORE_META;}
 portEXIT_CRITICAL(&lock);reply(b,status,count,token,phase,detail);
}
