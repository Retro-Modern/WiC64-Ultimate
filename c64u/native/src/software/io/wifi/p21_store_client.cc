#include "p21_store_client.h"
#include <stdlib.h>
#include <string.h>
namespace p21_store {
namespace {
void wipe(void *p,unsigned n){volatile uint8_t *q=static_cast<volatile uint8_t*>(p);while(n--)*q++=0;}
struct Frame {uint8_t *p;Frame():p(static_cast<uint8_t*>(calloc(1,P21_STORE_HEADER+P21_STORE_CHUNK))){}~Frame(){if(p){wipe(p,P21_STORE_HEADER+P21_STORE_CHUNK);free(p);}}};
struct Deadline {const Ops &ops;uint32_t start,budget,epoch;Deadline(const Ops &o,uint32_t ms):ops(o),start(o.milliseconds()),budget(ms),epoch(o.generation()){}
 uint32_t left()const{uint32_t used=ops.milliseconds()-start;return ops.generation()!=epoch||used>=budget?0:budget-used;}
 bool changed()const{return ops.generation()!=epoch;}};
Result code(uint8_t s){switch(s){case P21_STORE_BLOCKED:return BLOCKED;case P21_STORE_CONFLICT:return CONFLICT;case P21_STORE_TIMEOUT:return TIMEOUT;case P21_STORE_UNKNOWN:return UNCERTAIN;case P21_STORE_BUSY:return UNAVAILABLE;case P21_STORE_CLOSED:return UNAVAILABLE;case P21_STORE_FAILED:return IO_ERROR;default:return MALFORMED;}}
Result request(const Ops &ops,Deadline &d,uint8_t *f,uint8_t op,uint16_t n,uint64_t token,uint32_t arg,uint32_t budget,uint16_t &received){
 received=0;uint32_t left=d.left();if(!left)return d.changed()?CHANGED:TIMEOUT;
 p21_envelope(f,op,n,token,arg,budget);if(left>100)left=100;
 int r=ops.exchange(f,P21_STORE_HEADER+n,P21_STORE_HEADER+P21_STORE_CHUNK,&received,left);
 if(d.changed())return CHANGED;if(!d.left())return TIMEOUT;
 if(r==-2)return UNSUPPORTED;if(r)return r==-3?MALFORMED:UNAVAILABLE;
 if(received<P21_STORE_HEADER||received>P21_STORE_HEADER+P21_STORE_CHUNK||!p21_magic(f)||f[8]!=P21_STORE_VERSION||p21_get16(f+10)!=received-P21_STORE_HEADER||f[9]>P21_STORE_CLOSED)return MALFORMED;
 if((f[9]==P21_STORE_OK||f[9]==P21_STORE_BUSY||f[9]==P21_STORE_EMPTY||f[9]==P21_STORE_CLOSED)&&p21_get32(f+24))return MALFORMED;
 return OK;
}
Result poll(const Ops &ops,Deadline &d,uint8_t *f,uint64_t token,uint32_t phase,uint16_t &n){
 for(;;){Result r=request(ops,d,f,P21_STORE_STATUS,0,token,0,0,n);if(r!=OK)return r;
  if(p21_get64(f+12)!=token)return MALFORMED;
  if(f[9]==P21_STORE_BUSY){if(n!=P21_STORE_HEADER||p21_get32(f+20)!=phase-1)return MALFORMED;ops.pause();continue;}
  if(f[9]!=P21_STORE_OK&&f[9]!=P21_STORE_EMPTY)return code(f[9]);
  if(p21_get32(f+20)!=phase||n!=P21_STORE_HEADER+P21_STORE_META)return MALFORMED;return OK;}
}
void close(const Ops &ops,Deadline &d,uint8_t *f,uint64_t token){if(!token||!d.left())return;uint16_t n;request(ops,d,f,P21_STORE_CLOSE,0,token,0,0,n);}
}
int Client::probe(uint32_t budget){
 if(!budget||budget>100)return -1;Frame f;if(!f.p)return -1;Deadline d(ops,budget);uint16_t n;
 Result r=request(ops,d,f.p,P21_STORE_CAPS,0,0,0,0,n);if(r!=OK)return r==UNSUPPORTED?-2:r==MALFORMED?-3:-1;
 if(n!=P21_STORE_HEADER+12||f.p[9]!=P21_STORE_OK||p21_get64(f.p+12)||p21_get32(f.p+20)||
    p21_get32(f.p+28)!=P21_STORE_FEATURES||p21_get32(f.p+32)!=P21_STORE_MAX||p21_get16(f.p+36)!=P21_STORE_CHUNK||p21_get16(f.p+38))return -3;
 return 0;
}
Result Client::load(uint8_t *out,uint16_t capacity,uint16_t &length,uint64_t &generation,uint32_t budget){
 length=0;generation=0;if(!out||capacity<P21_STORE_MAX||!budget||budget>P21_STORE_MAX_BUDGET)return MALFORMED;
 Frame f;if(!f.p)return NO_MEMORY;Deadline d(ops,budget);uint16_t n;uint64_t token=0;
 Result r=request(ops,d,f.p,P21_STORE_LOAD,0,0,0,d.left(),n);if(r!=OK)return r;
 if(f.p[9]!=P21_STORE_BUSY||n!=P21_STORE_HEADER||p21_get32(f.p+20)!=P21_STORE_LOADING||!(token=p21_get64(f.p+12)))return code(f.p[9]);
 r=poll(ops,d,f.p,token,P21_STORE_LOADED,n);if(r!=OK){close(ops,d,f.p,token);return r;}
 uint64_t gen=p21_get64(f.p+28);uint32_t total=p21_get32(f.p+36),crc=p21_get32(f.p+40);
 if(f.p[9]==P21_STORE_EMPTY){bool empty=!gen&&!total&&!crc;close(ops,d,f.p,token);return empty?EMPTY:MALFORMED;}
 if(!gen||!total||total>P21_STORE_MAX||total>capacity){close(ops,d,f.p,token);return MALFORMED;}
 for(uint32_t offset=0;offset<total;){uint16_t count=uint16_t(total-offset>P21_STORE_CHUNK?P21_STORE_CHUNK:total-offset);p21_put16(f.p+28,count);
  r=request(ops,d,f.p,P21_STORE_READ,2,token,offset,0,n);
  if(r!=OK||f.p[9]!=P21_STORE_OK||p21_get64(f.p+12)!=token||p21_get32(f.p+20)!=offset||n!=P21_STORE_HEADER+count){wipe(out,total);close(ops,d,f.p,token);return r!=OK?r:MALFORMED;}
  memcpy(out+offset,f.p+28,count);offset+=count;}
 if(p21_crc32(out,total)!=crc){wipe(out,total);close(ops,d,f.p,token);return MALFORMED;}
 if(d.changed()){wipe(out,total);return CHANGED;}close(ops,d,f.p,token);if(d.changed()){wipe(out,total);return CHANGED;}length=uint16_t(total);generation=gen;return OK;
}
Result Client::save(const uint8_t *bytes,uint16_t length,uint64_t expected,uint64_t &next,uint32_t budget){
 next=0;if(!bytes||!length||length>P21_STORE_MAX||expected==UINT64_MAX||!budget||budget>P21_STORE_MAX_BUDGET)return MALFORMED;
 Frame f;if(!f.p)return NO_MEMORY;Deadline d(ops,budget);uint16_t n;uint64_t token=0;
 const uint32_t crc=p21_crc32(bytes,length);p21_put64(f.p+28,expected);p21_put32(f.p+36,length);p21_put32(f.p+40,crc);
 Result r=request(ops,d,f.p,P21_STORE_BEGIN,P21_STORE_META,0,0,d.left(),n);if(r!=OK)return r;
 if(f.p[9]!=P21_STORE_BUSY||n!=P21_STORE_HEADER||p21_get32(f.p+20)!=P21_STORE_CHECKING||!(token=p21_get64(f.p+12)))return code(f.p[9]);
 r=poll(ops,d,f.p,token,P21_STORE_STAGING,n);if(r!=OK){close(ops,d,f.p,token);return r;}
 if(f.p[9]!=P21_STORE_OK||p21_get64(f.p+28)!=expected+1||p21_get32(f.p+36)!=length||p21_get32(f.p+40)!=crc){close(ops,d,f.p,token);return MALFORMED;}
 for(uint32_t offset=0;offset<length;){uint16_t count=uint16_t(length-offset>P21_STORE_CHUNK?P21_STORE_CHUNK:length-offset);memcpy(f.p+28,bytes+offset,count);
  r=request(ops,d,f.p,P21_STORE_WRITE,count,token,offset,0,n);
  if(r!=OK||f.p[9]!=P21_STORE_OK||p21_get64(f.p+12)!=token||n!=P21_STORE_HEADER||p21_get32(f.p+20)!=offset+count){close(ops,d,f.p,token);return r!=OK?r:code(f.p[9]);}offset+=count;}
 // COMMIT is sent once. Any lost/malformed result after this boundary is
 // uncertain; never replay a write or claim that an old record was restored.
 r=request(ops,d,f.p,P21_STORE_COMMIT,0,token,0,0,n);
 if(r!=OK)return UNCERTAIN;
 if(f.p[9]==P21_STORE_BUSY)r=poll(ops,d,f.p,token,P21_STORE_DURABLE,n);
 else if(f.p[9]!=P21_STORE_OK)r=code(f.p[9]);
 if(r!=OK)return UNCERTAIN;
 if(f.p[9]!=P21_STORE_OK||p21_get64(f.p+12)!=token||p21_get32(f.p+20)!=P21_STORE_DURABLE||n!=P21_STORE_HEADER+16||p21_get64(f.p+28)!=expected+1||p21_get32(f.p+36)!=length||p21_get32(f.p+40)!=crc||d.changed())return UNCERTAIN;
 close(ops,d,f.p,token);if(d.changed())return UNCERTAIN;next=expected+1;return OK;
}
const char *result_name(Result r){static const char *v[]={"OK","EMPTY","UNSUPPORTED","UNAVAILABLE","MALFORMED","BLOCKED","CONFLICT","TIMEOUT","UNCERTAIN","MODULE_CHANGED","CANCELLED","NO_MEMORY","IO_ERROR"};return unsigned(r)<sizeof(v)/sizeof(*v)?v[r]:"STORE_ERROR";}
}
#if !defined(P21_STORE_HOST_TEST)
#include "p18m_esp_firmware.h"
extern "C" {
#include "FreeRTOS.h"
#include "task.h"
}
namespace p21_store {
namespace {uint32_t milliseconds(){return uint32_t(uint64_t(xTaskGetTickCount())*1000/configTICK_RATE_HZ);}void pause(){vTaskDelay(1);}const Ops platform={p21_store_rpc_exchange,milliseconds,pause,p18m_esp::module_generation};}
const Ops &native_ops(){return platform;}
int probe(uint32_t budget){Client client(platform);return client.probe(budget);}
}
#endif
