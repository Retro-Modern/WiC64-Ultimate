#include "p21_preferences.h"
#if defined(C64U_ESP_PERSIST) && C64U_ESP_PERSIST
#if C64U_ESP_PERSIST != 1 || !C64U_ESP_TLS || !P05_RAM_DIAGNOSTIC || U64 != 2
#error ESP preferences require the qualified C64U RAM/ESP TLS profile
#endif
#include "p08_http.h"
#include "p21_store_client.h"
#include "p18_log.h"
#include <stdlib.h>
#include <string.h>
#include <new>
#if !defined(P21_STORE_HOST_TEST)
extern "C" {
#include "FreeRTOS.h"
#include "task.h"
}
#endif
namespace p21prefs {
namespace {
using namespace p08;
const unsigned HEADER=16,MAX_CREDENTIALS=3265,MAX_SERVER=480;
const uint32_t OPERATION_BUDGET=8000;
void wipe(void *p,unsigned n){volatile uint8_t *q=static_cast<volatile uint8_t*>(p);while(n--)*q++=0;}
struct Buffer {uint8_t *p;explicit Buffer(unsigned n):p(static_cast<uint8_t*>(calloc(1,n))),size(n){}unsigned size;~Buffer(){if(p){wipe(p,size);free(p);}}};
struct Preferences {
 BackendContext *backend;Status status,cache;uint8_t *durable;uint16_t durable_length;
 uint32_t retry_at;bool ever_loaded;uint8_t zone,log_level;bool previews;
 char server[481];
 Preferences():backend(0),durable(0),durable_length(0),retry_at(0),ever_loaded(false),zone(0),log_level(2),previews(false){memset(&status,0,sizeof(status));status.state=WAITING;cache=status;strcpy(server,"http://x.wic64.net/prg/");}
} prefs;
uint32_t configuration_revision=0,durable_revision=0;
uint32_t revision(){
#if !defined(P21_STORE_HOST_TEST)
 portENTER_CRITICAL();
#endif
 uint32_t value=configuration_revision;
#if !defined(P21_STORE_HOST_TEST)
 portEXIT_CRITICAL();
#endif
 return value;
}
void committed(uint32_t value){
#if !defined(P21_STORE_HOST_TEST)
 portENTER_CRITICAL();
#endif
 durable_revision=value;
#if !defined(P21_STORE_HOST_TEST)
 portEXIT_CRITICAL();
#endif
}
const p21_store::Ops &ops(){return p21_store::native_ops();}
void publish(){
#if !defined(P21_STORE_HOST_TEST)
 portENTER_CRITICAL();
#endif
 prefs.cache=prefs.status;
#if !defined(P21_STORE_HOST_TEST)
 portEXIT_CRITICAL();
#endif
}
void state(State value,const char *error=""){
 prefs.status.state=value;unsigned n=0;while(error[n]&&n<sizeof(prefs.status.error)-1){prefs.status.error[n]=error[n];n++;}prefs.status.error[n]=0;publish();
}
bool zero_secure(const uint8_t *p,uint16_t n){if(!p||n<67||n>MAX_CREDENTIALS||memcmp(p,"P12C",4)||p[4]!=2)return false;for(unsigned i=n-57;i<n;i++)if(p[i])return false;return validate_credentials(p,n);}
bool valid_server(const char *p,unsigned &n){n=0;while(n<=MAX_SERVER&&p[n]){uint8_t b=uint8_t(p[n]);if(b<0x20||b>0x7e)return false;n++;}return n&&n<=MAX_SERVER;}
uint16_t envelope(uint8_t *out,const uint8_t *credentials,uint16_t length){
 unsigned server_length;if(!zero_secure(credentials,length)||!valid_server(prefs.server,server_length)||prefs.zone>=32||prefs.log_level>3)return 0;
 const unsigned total=HEADER+length+server_length;if(total>P21_STORE_MAX)return 0;
 memset(out,0,HEADER);memcpy(out,"WCP1",4);out[4]=1;out[5]=prefs.zone;out[6]=prefs.log_level;out[7]=prefs.previews?1:0;
 p21_put16(out+8,length);p21_put16(out+10,uint16_t(server_length));memcpy(out+HEADER,credentials,length);memcpy(out+HEADER+length,prefs.server,server_length);return uint16_t(total);
}
bool decode(const uint8_t *bytes,uint16_t n,bool apply){
 if(!bytes||n<HEADER+67+1||n>P21_STORE_MAX||memcmp(bytes,"WCP1",4)||bytes[4]!=1||bytes[5]>=32||bytes[6]>3||bytes[7]>1||p21_get32(bytes+12))return false;
 uint16_t credentials=p21_get16(bytes+8),server_length=p21_get16(bytes+10);
 if(!server_length||server_length>MAX_SERVER||unsigned(HEADER)+credentials+server_length!=n||!zero_secure(bytes+HEADER,credentials))return false;
 const uint8_t *server=bytes+HEADER+credentials;for(unsigned i=0;i<server_length;i++)if(server[i]<0x20||server[i]>0x7e)return false;
 if(apply){
  // Full envelope validation is complete before any live setting changes.
  if(!deserialize_credentials(*prefs.backend,bytes+HEADER,credentials))return false;
  memcpy(prefs.server,server,server_length);prefs.server[server_length]=0;strcpy(prefs.backend->server,prefs.server);prefs.zone=bytes[5];prefs.log_level=bytes[6];prefs.previews=bytes[7]!=0;
#if defined(P18_LOG) && P18_LOG
  if(!p18log::restore_configuration(p18log::Level(prefs.log_level),prefs.previews))return false;
#endif
 }
 return true;
}
bool persist(void*,const uint8_t *credentials,uint16_t length){
 BackendContext &c=*prefs.backend;prefs.status.dirty=true;prefs.status.saved=false;
 if(!prefs.status.loaded||!prefs.status.writable||!c.preferences_ready||ops().generation()!=prefs.status.module_generation){state(BLOCKED,"PREFERENCES_NOT_READY");return false;}
 uint32_t saved_revision=revision();
#if defined(P18_LOG) && P18_LOG
 p18log::Level level;bool previews;if(!p18log::configuration(level,previews)||saved_revision!=revision()){state(READY,"LOG_BUSY");return false;}
 prefs.log_level=uint8_t(level);prefs.previews=previews;
#endif
 Buffer bytes(P21_STORE_MAX);uint16_t n=bytes.p?envelope(bytes.p,credentials,length):0;
 if(!n){state(BLOCKED,bytes.p?"PREFERENCES_SCHEMA":"PREFERENCES_MEMORY");prefs.status.writable=false;c.preferences_ready=false;publish();return false;}
 if(prefs.durable&&prefs.durable_length==n&&!memcmp(prefs.durable,bytes.p,n)){prefs.status.dirty=false;prefs.status.saved=true;committed(saved_revision);state(READY);return true;}
 state(SAVING);p21_store::Client client(ops());uint64_t generation=0;
 p21_store::Result r=client.save(bytes.p,n,prefs.status.generation,generation,OPERATION_BUDGET);
 if(r==p21_store::OK){
  if(!prefs.durable)prefs.durable=static_cast<uint8_t*>(calloc(1,P21_STORE_MAX));
  if(prefs.durable){wipe(prefs.durable,P21_STORE_MAX);memcpy(prefs.durable,bytes.p,n);prefs.durable_length=n;}
  prefs.status.generation=generation;prefs.status.dirty=false;prefs.status.saved=true;committed(saved_revision);state(READY);return true;
 }
 prefs.status.saved=false;prefs.status.dirty=true;
 // Re-read an uncertain/current generation before any later mutation. Never
 // replay COMMIT or replace a bad/unknown record with empty defaults.
 if(r==p21_store::UNCERTAIN||r==p21_store::CHANGED||r==p21_store::CONFLICT||r==p21_store::UNAVAILABLE||r==p21_store::TIMEOUT){
  prefs.status.loaded=false;prefs.status.writable=false;c.preferences_ready=false;prefs.retry_at=ops().milliseconds()+500;state(UNCERTAIN,p21_store::result_name(r));
 }else{prefs.status.writable=false;c.preferences_ready=false;state(BLOCKED,p21_store::result_name(r));}
 return false;
}
bool save_current(){if(!prefs.backend)return false;return credentials_changed(*prefs.backend);}
}
void initialize(BackendContext &c){
 prefs.backend=&c;prefs.status.module_generation=ops().generation();c.preferences_required=true;c.preferences_ready=false;c.persist_credentials=persist;c.persist_context=0;
 unsigned n;if(valid_server(c.server,n))strcpy(prefs.server,c.server);publish();
}
void step(BackendContext &c){
 if(prefs.backend!=&c)return;uint32_t epoch=ops().generation(),now=ops().milliseconds();
 if(epoch!=prefs.status.module_generation){
  prefs.status.module_generation=epoch;prefs.status.loaded=prefs.status.writable=prefs.status.saved=false;c.preferences_ready=false;c.credentials_saved=false;
  prefs.retry_at=now;state(WAITING,"MODULE_CHANGED");
 }
 if(!prefs.status.loaded){
  if(prefs.status.state==BLOCKED)return;
  if(int32_t(now-prefs.retry_at)<0)return;prefs.retry_at=now+500;
  p21_store::Client client(ops());int cap=client.probe(100);
  if(cap){state(cap==-2?BLOCKED:UNAVAILABLE,cap==-2?"STORE_UNSUPPORTED":"STORE_NOT_READY");return;}
  Buffer bytes(P21_STORE_MAX);if(!bytes.p){state(UNAVAILABLE,"PREFERENCES_MEMORY");return;}
  uint16_t n=0;uint64_t generation=0;p21_store::Result r=client.load(bytes.p,P21_STORE_MAX,n,generation,OPERATION_BUDGET);
  if(r!=p21_store::OK&&r!=p21_store::EMPTY){
   bool blocked=r==p21_store::BLOCKED||r==p21_store::MALFORMED||r==p21_store::UNSUPPORTED;
   state(blocked?BLOCKED:UNAVAILABLE,p21_store::result_name(r));return;
  }
  if(r==p21_store::OK&&!decode(bytes.p,n,false)){state(BLOCKED,"PREFERENCES_SCHEMA");return;}
  const bool preserve=prefs.ever_loaded&&(c.credentials_dirty||prefs.status.dirty);
  if(r==p21_store::OK&&!preserve&&!decode(bytes.p,n,true)){state(BLOCKED,"PREFERENCES_APPLY");return;}
  if(r==p21_store::EMPTY&&!preserve){
   uint8_t empty[67]={};memcpy(empty,"P12C",4);empty[4]=2;empty[6]=2;
   if(!deserialize_credentials(c,empty,sizeof(empty))){state(UNAVAILABLE,"PREFERENCES_MEMORY");return;}
   strcpy(prefs.server,"http://x.wic64.net/prg/");strcpy(c.server,prefs.server);prefs.zone=0;prefs.log_level=2;prefs.previews=false;
#if defined(P18_LOG) && P18_LOG
   if(!p18log::restore_configuration(p18log::INFO,false)){state(UNAVAILABLE,"LOG_NOT_READY");return;}
#endif
  }
  if(!prefs.durable)prefs.durable=static_cast<uint8_t*>(calloc(1,P21_STORE_MAX));
  if(!prefs.durable){state(UNAVAILABLE,"PREFERENCES_MEMORY");return;}
  wipe(prefs.durable,P21_STORE_MAX);if(n)memcpy(prefs.durable,bytes.p,n);prefs.durable_length=n;
  prefs.status.generation=generation;prefs.status.loaded=prefs.status.writable=true;prefs.ever_loaded=true;c.preferences_ready=true;
  bool matches=false;
  if(preserve){
   Buffer current(6000);if(current.p){uint16_t size=serialize_credentials(c,current.p,6000);Buffer proposed(P21_STORE_MAX);uint16_t total=proposed.p?envelope(proposed.p,current.p,size):0;matches=total==n&&total&&!memcmp(proposed.p,bytes.p,total);}
  }else matches=r==p21_store::OK;
  prefs.status.saved=matches;prefs.status.dirty=preserve&&!matches;c.credentials_saved=matches;c.credentials_dirty=prefs.status.dirty;
  if(!prefs.status.dirty)committed(revision());
  refresh_network_info(c);state(r==p21_store::EMPTY?EMPTY:READY);return;
 }
#if defined(P18_LOG) && P18_LOG
 uint8_t level=uint8_t(p18log::level());bool preview=p18log::previews_enabled();
 if(level!=prefs.log_level||preview!=prefs.previews||revision()!=durable_revision){prefs.log_level=level;prefs.previews=preview;save_current();}
#endif
}
bool get_status(Status &out){
#if !defined(P21_STORE_HOST_TEST)
 portENTER_CRITICAL();
#endif
 out=prefs.cache;if(configuration_revision!=durable_revision){out.dirty=true;out.saved=false;}
 if(prefs.backend&&out.module_generation!=ops().generation()){out.loaded=false;out.writable=false;out.saved=false;out.state=WAITING;strcpy(out.error,"MODULE_CHANGED");}
#if !defined(P21_STORE_HOST_TEST)
 portEXIT_CRITICAL();
#endif
 return prefs.backend!=0;
}
const char *state_name(State s){static const char *v[]={"WAITING","EMPTY","READY","SAVING","BLOCKED","UNCERTAIN","UNAVAILABLE"};return unsigned(s)<sizeof(v)/sizeof(*v)?v[s]:"UNKNOWN";}
bool wifi_config_ready(){Status s={};return get_status(s)&&s.loaded&&s.writable&&s.module_generation==ops().generation();}
bool configuration_mutable(){return !prefs.backend||wifi_config_ready();}
void configuration_changed(){
#if !defined(P21_STORE_HOST_TEST)
 portENTER_CRITICAL();
#endif
 if(++configuration_revision==0)++configuration_revision;
#if !defined(P21_STORE_HOST_TEST)
 portEXIT_CRITICAL();
#endif
}
bool load_server(char *out,uint32_t cap){if(!prefs.backend||!out||cap<=strlen(prefs.server))return false;strcpy(out,prefs.server);return true;}
bool save_server(const char *server){unsigned n;if(!prefs.backend||!prefs.backend->preferences_ready||!valid_server(server,n))return false;strcpy(prefs.server,server);strcpy(prefs.backend->server,server);return save_current();}
uint8_t timezone(){return prefs.zone;}
bool save_timezone(uint8_t zone){if(zone>=32||!prefs.backend||!prefs.backend->preferences_ready)return false;prefs.zone=zone;return save_current();}
#if defined(P21_STORE_HOST_TEST)
namespace testing {void reset(){if(prefs.durable){wipe(prefs.durable,P21_STORE_MAX);free(prefs.durable);}prefs.~Preferences();new(&prefs) Preferences();configuration_revision=durable_revision=0;}}
#endif
}
#endif
