#include "p18_log.h"
#include "p17_trace.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
namespace p18log {
namespace {
const uint32_t MAX_COUNTER=0x7fffffffu;
static Entry *ring=0;
static bool allocation_attempted=false;
#if defined(P18_LOG_HOST_TEST)
static bool fail_allocation=false;
#endif
static_assert(sizeof(Entry)==256,"bounded log record layout");
static uint32_t lock_word=0,configured_level=INFO,missed=0,preview_enabled=0;
// Aligned load/store-only authorization stamps: no RV32 atomic RMW needed.
static uint32_t http_classified_request=0,http_private_request=0;
static uint32_t generation=1,next_sequence=1,overwritten=0,last_tick=0;
static unsigned head=0,count=0;
static bool have_tick=false;
bool claim(){
#if defined(P18_LOG_HOST_TEST) && !defined(P18_LOG_NATIVE_GUARD_TEST)
 uint32_t expected=0;return __atomic_compare_exchange_n(&lock_word,&expected,1U,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
#else
 // rv32im has no atomic RMW extension. Claim/release only the ownership word
 // in a short native critical section; all bounded copies run outside it.
 portENTER_CRITICAL();bool available=!lock_word;if(available)lock_word=1;portEXIT_CRITICAL();return available;
#endif
}
void release(){
#if defined(P18_LOG_HOST_TEST) && !defined(P18_LOG_NATIVE_GUARD_TEST)
 __atomic_store_n(&lock_word,0U,__ATOMIC_RELEASE);
#else
 portENTER_CRITICAL();lock_word=0;portEXIT_CRITICAL();
#endif
}
struct Guard {
 bool held;
 Guard():held(claim()){}
 ~Guard(){if(held)release();}
};
uint32_t bounded(uint32_t n){return n>MAX_COUNTER?MAX_COUNTER:n;}
void minimal_hex(uint32_t value,char out[9]){
 static const char digits[]="0123456789abcdef";unsigned first=0;
 for(unsigned i=0;i<8;++i)out[i]=digits[(value>>((7-i)*4))&15];out[8]=0;
 while(first<7&&out[first]=='0')++first;if(first)memmove(out,out+first,9-first);
}
void miss(){
#if defined(P18_LOG_HOST_TEST) && !defined(P18_LOG_NATIVE_GUARD_TEST)
 // Two bounded atomics. Temporary over-saturation is clamped by every reader;
 // with the bounded number of system tasks it cannot approach UINT32 rollover.
 uint32_t before=__atomic_fetch_add(&missed,1U,__ATOMIC_RELAXED);
 if(before>=MAX_COUNTER)__atomic_store_n(&missed,MAX_COUNTER,__ATOMIC_RELAXED);
#else
 portENTER_CRITICAL();if(missed<MAX_COUNTER)missed++;portEXIT_CRITICAL();
#endif
}
uint32_t read_missed(){
#if defined(P18_LOG_HOST_TEST) && !defined(P18_LOG_NATIVE_GUARD_TEST)
 return __atomic_load_n(&missed,__ATOMIC_RELAXED);
#else
 portENTER_CRITICAL();uint32_t value=missed;portEXIT_CRITICAL();return value;
#endif
}
void clear_missed(){
#if defined(P18_LOG_HOST_TEST) && !defined(P18_LOG_NATIVE_GUARD_TEST)
 __atomic_store_n(&missed,0U,__ATOMIC_RELAXED);
#else
 portENTER_CRITICAL();missed=0;portEXIT_CRITICAL();
#endif
}
void reset_ring(){
 __atomic_store_n(&http_classified_request,0U,__ATOMIC_RELEASE);
 if(ring)memset(ring,0,CAPACITY*sizeof(Entry));head=count=0;next_sequence=1;overwritten=0;
 generation=generation>=MAX_COUNTER?1:generation+1;
 clear_missed();have_tick=false;last_tick=0;
}
uint8_t safe_protocol(uint8_t p){return p=='W'||p=='R'||p=='E'?p:uint8_t('?');}
uint8_t severity(const Entry &e){
 if(e.event==PHASE||(e.event==PACKET&&(e.flags&CONTINUATION)))return DEBUG;
 return e.status||e.error||e.http_status>=400||e.lifecycle==p08::TRACE_ABANDONED?ERROR:INFO;
}
void append_locked(Entry &e){
 e.tick_ms&=MAX_COUNTER;e.request_id=bounded(e.request_id);e.length=bounded(e.length);
 e.elapsed_ms=bounded(e.elapsed_ms);e.tls_tx=bounded(e.tls_tx);e.tls_rx=bounded(e.tls_rx);
 e.protocol=safe_protocol(e.protocol);
 if(e.phase>=p08::TRACE_PHASE_COUNT)e.phase=p08::TRACE_NONE;
 if(e.lifecycle>p08::TRACE_ABANDONED)e.lifecycle=p08::TRACE_IDLE;
 e.level=severity(e);
 if(!ring||e.level>__atomic_load_n(&configured_level,__ATOMIC_RELAXED))return;
 if(next_sequence>MAX_COUNTER||(have_tick&&e.tick_ms<last_tick&&last_tick-e.tick_ms>MAX_COUNTER/2))reset_ring();
 e.seq=next_sequence++;if(!have_tick||e.tick_ms>last_tick)last_tick=e.tick_ms;have_tick=true;
 unsigned at=(head+count)%CAPACITY;
 if(count==CAPACITY){at=head;head=(head+1)%CAPACITY;if(overwritten<MAX_COUNTER)overwritten++;}
 else count++;
 ring[at]=e;
}
void append(Entry &e){
 e.level=severity(e);
 if(!ring||e.level>__atomic_load_n(&configured_level,__ATOMIC_RELAXED))return;
 Guard guard;if(!guard.held){miss();return;}append_locked(e);
}
Entry from_trace(Event event,const p08::RequestTrace &r){
 Entry e={};e.tick_ms=r.touched_tick_ms;e.request_id=r.request_id;
 e.command=r.command;e.protocol=r.protocol;e.event=uint8_t(event);e.phase=r.phase;
 e.lifecycle=r.lifecycle;e.status=r.status;e.error=r.error;e.http_status=r.http_status;
 e.length=r.response_length;e.elapsed_ms=r.elapsed_tick_ms;e.tls_tx=r.tls_sent_bytes;
 e.tls_rx=r.tls_received_bytes;e.engine_error=r.engine_error;return e;
}
void local_elapsed(Entry &e){
 for(unsigned i=0;i<count;i++){
  const Entry &prior=ring[(head+count-1-i)%CAPACITY];
  if(prior.request_id==bounded(e.request_id)&&prior.command==e.command&&prior.protocol==safe_protocol(e.protocol)&&prior.event==BEGIN){
   e.elapsed_ms=uint32_t((e.tick_ms&MAX_COUNTER)-prior.tick_ms)&MAX_COUNTER;return;
  }
 }
}
const char *event_name(unsigned event){static const char *names[]={"BEGIN","PHASE","FINISH","DELIVERY","PACKET","HTTP"};return event<=HTTP?names[event]:"UNKNOWN";}
}
Level level(){return Level(__atomic_load_n(&configured_level,__ATOMIC_ACQUIRE));}
bool initialize(uint32_t nonce){
 Guard guard;if(!guard.held)return false;
 if(!allocation_attempted){
  allocation_attempted=true;
#if defined(P18_LOG_HOST_TEST)
  if(!fail_allocation)
#endif
  ring=static_cast<Entry*>(malloc(CAPACITY*sizeof(Entry)));
 }
 reset_ring();
 if(!ring){__atomic_store_n(&configured_level,uint32_t(OFF),__ATOMIC_RELEASE);return false;}
 // Noncryptographic avalanche of public boot timing. It avoids a universal
 // epoch1 after reboot; browser transport recovery also discards old cursors.
 nonce^=nonce>>16;nonce*=0x7feb352du;nonce^=nonce>>15;nonce*=0x846ca68bu;nonce^=nonce>>16;
 generation=nonce&MAX_COUNTER;if(!generation)generation=1;return true;
}
bool previews_enabled(){return __atomic_load_n(&preview_enabled,__ATOMIC_ACQUIRE)!=0;}
bool configure_previews(bool enabled){return control(false,OFF,false,true,enabled);}
bool control(bool set_level,Level new_level,bool clear_ring,bool set_previews,bool new_previews){
 if(set_level&&(new_level<OFF||new_level>DEBUG))return false;
 Guard guard;if(!guard.held)return false;
 if(!ring&&((set_level&&new_level!=OFF)||(set_previews&&new_previews)))return false;
 if(set_previews)__atomic_store_n(&preview_enabled,new_previews?1U:0U,__ATOMIC_RELEASE);
 if(set_level)__atomic_store_n(&configured_level,uint32_t(new_level),__ATOMIC_RELEASE);
 if(clear_ring)reset_ring();return true;
}
bool configure(Level new_level){return control(true,new_level,false);}
bool clear(){return control(false,OFF,true);}
bool snapshot(uint32_t requested_generation,uint32_t after,uint8_t limit,Snapshot &out){
 memset(&out,0,sizeof(out));out.level=uint8_t(level());
 Guard guard;if(!guard.held){out.busy=true;return false;}
 out.level=uint8_t(level());out.generation=generation;out.available=ring!=0;out.previews_enabled=previews_enabled();
 out.dropped=bounded(read_missed());out.overwritten=overwritten;
 out.oldest_seq=count?ring[head].seq:0;
 out.newest_seq=count?ring[(head+count-1)%CAPACITY].seq:0;
 out.reset=requested_generation!=generation||after>MAX_COUNTER||after>out.newest_seq;
 if(!out.reset&&after&&count&&after<out.oldest_seq-1)out.reset=true;
 if(out.reset)after=0;
 unsigned maximum=limit?limit:1;if(maximum>PAGE_SIZE)maximum=PAGE_SIZE;
 out.next_after=after;
 for(unsigned i=0;i<count;i++){
  const Entry &e=ring[(head+i)%CAPACITY];if(e.seq<=after)continue;
  if(out.count==maximum){out.more=true;break;}
  out.entries[out.count++]=e;out.next_after=e.seq;
 }
 return true;
}
void record(Event event,const p08::RequestTrace &r){
 if(event>DELIVERY)return;Entry e=from_trace(event,r);append(e);
}
void local_begin(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms){
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.command=command;e.protocol=protocol;
 e.event=BEGIN;e.phase=p08::TRACE_COMMAND;e.lifecycle=p08::TRACE_EXECUTING;append(e);
}
void local_finish(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,
                  uint8_t status,uint8_t error,uint16_t http_status,uint32_t length){
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.command=command;e.protocol=protocol;
 e.event=FINISH;e.phase=p08::TRACE_COMMAND;e.lifecycle=p08::TRACE_BACKEND_DONE;
 e.status=status;e.error=error;e.http_status=http_status;e.length=length;
 if(severity(e)>uint8_t(level()))return;
 Guard guard;if(!guard.held){miss();return;}local_elapsed(e);append_locked(e);
}
void local_delivery(uint32_t request_id,uint8_t lifecycle,uint32_t tick_ms){
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.event=DELIVERY;e.lifecycle=lifecycle;e.phase=p08::TRACE_COMMAND;
 if(severity(e)>uint8_t(level()))return;
 Guard guard;if(!guard.held){miss();return;}
 bool found=false;for(unsigned i=0;i<count;i++){
  const Entry &prior=ring[(head+count-1-i)%CAPACITY];
  if(prior.request_id==bounded(request_id)){
   if(prior.event==DELIVERY&&(prior.lifecycle==p08::TRACE_COMPLETE||prior.lifecycle==p08::TRACE_ABANDONED))return;
   if(prior.event==DELIVERY&&prior.lifecycle==lifecycle)return;
   found=true;e.command=prior.command;e.protocol=prior.protocol;e.status=prior.status;e.error=prior.error;
   e.http_status=prior.http_status;e.length=prior.length;break;
  }
 }
 if(!found)return;
 local_elapsed(e);append_locked(e);
}
const char *command_name(uint8_t command){
 switch(command){
#define P18_NAME(value,name) case value:return "WIC64_CMD_" #name
 P18_NAME(0x00,GET_VERSION_STRING);P18_NAME(0x01,HTTP_GET);
 P18_NAME(0x02,CONNECT_WITH_SSID_STRING);P18_NAME(0x06,GET_IP);
 P18_NAME(0x08,SET_SERVER);P18_NAME(0x0a,UDP_GET);P18_NAME(0x0b,UDP_SEND);
 P18_NAME(0x0c,SCAN_WIFI_NETWORKS);P18_NAME(0x0d,CONNECT_WITH_SSID_INDEX);
 P18_NAME(0x0e,UDP_SET_PORT);P18_NAME(0x0f,HTTP_GET_ENCODED);
 P18_NAME(0x10,GET_SSID);P18_NAME(0x11,GET_RSSI);P18_NAME(0x12,GET_SERVER);
 P18_NAME(0x14,GET_MAC);P18_NAME(0x15,GET_LOCAL_TIME);P18_NAME(0x16,SET_TIMEZONE);
 P18_NAME(0x17,GET_TIMEZONE);P18_NAME(0x1e,UDP_GET);P18_NAME(0x1f,UDP_SEND);
 P18_NAME(0x21,TCP_OPEN);P18_NAME(0x22,TCP_READ);P18_NAME(0x23,TCP_WRITE);
 P18_NAME(0x26,GET_VERSION_NUMBERS);P18_NAME(0x27,UPDATE_FIRMWARE);
 P18_NAME(0x28,HTTP_POST_URL);P18_NAME(0x29,REBOOT);P18_NAME(0x2a,GET_STATUS_MESSAGE);
 P18_NAME(0x2b,HTTP_POST_DATA);P18_NAME(0x2c,IS_CONNECTED);P18_NAME(0x2d,SET_TRANSFER_TIMEOUT);
 P18_NAME(0x2e,TCP_CLOSE);P18_NAME(0x2f,IS_CONFIGURED);P18_NAME(0x30,TCP_AVAILABLE);
 P18_NAME(0x31,IS_HARDWARE);P18_NAME(0x32,SET_REMOTE_TIMEOUT);
 P18_NAME(0x33,UDP_SET_PORT);P18_NAME(0x34,UDP_SEND);P18_NAME(0x35,UDP_GET);
 P18_NAME(0x36,WPS_START);P18_NAME(0x37,WPS_STATUS);P18_NAME(0x38,WPS_CANCEL);
 P18_NAME(0x39,ERASE_WIFI_CONFIG);P18_NAME(0x3a,GET_IP_CONFIG);P18_NAME(0x3b,ENABLE_DHCP);
 P18_NAME(0x3c,SET_STATIC_IP);P18_NAME(0x3d,WIFI_CONNECT_STATUS);P18_NAME(0x3e,PING);
 P18_NAME(0x3f,SPEEDTEST);P18_NAME(0x40,TCP_OPEN_TLS);
 P18_NAME(0x41,GET_BUILD_INFO);P18_NAME(0x42,AUTH_TOKEN);P18_NAME(0x43,WEB_ADMIN_CODE);
 P18_NAME(0xfc,FORCE_TIMEOUT);P18_NAME(0xfd,FORCE_ERROR);P18_NAME(0xfe,ECHO);
#undef P18_NAME
 default:return "WIC64_CMD_UNKNOWN";
 }
}
const char *protocol_name(uint8_t p){return p=='W'?"legacy protocol (W)":p=='R'?"new/standard protocol (R)":p=='E'?"new/extended protocol (E)":"unknown protocol (?)";}
uint8_t record_color(const Entry &e){
 if(e.level==ERROR||e.status||e.error||e.http_status>=400||e.lifecycle==p08::TRACE_ABANDONED)return FAILURE;
 if(e.event==PACKET||(e.event==HTTP&&e.color==HOST))return e.color==HOST?HOST:e.color==DEVICE?DEVICE:DEFAULT;
 return DEFAULT;
}
namespace {
void sample_byte(Entry &e,uint8_t value){if(e.sample_length<SAMPLE_CAPACITY)e.sample[e.sample_length++]=value;}
// This allowlist intentionally rejects opaque bodies, including ECHO. Neither
// a content type nor a successful HTTP status proves a response is public.
bool public_reply(uint8_t command,const uint8_t *p,uint32_t length,uint32_t offset){
 if(offset||!p)return false;
 if(command==0x26){static const uint8_t numbers[]={2,4,4,1};return length==4&&!memcmp(p,numbers,4);}
 if(command==0x00){
  if(!length||length>40)return false;
  static const char prefix[]="2.4.4";
  if(length<sizeof(prefix)-1||memcmp(p,prefix,sizeof(prefix)-1))return false;
  for(unsigned i=0;i<length;++i){uint8_t c=p[i];if(c&&!(c>='0'&&c<='9')&&c!='.'&&c!='-'&&c!=' '&&c!='('&&c!=')'&&c!='U'&&c!='C'&&c!='F'&&c!='W')return false;}
  return true;
 }
 if(command==0x06){
  if(!length||length>16)return false;
  for(unsigned i=0;i<length;++i)if(p[i]&&p[i]!='.'&&(p[i]<'0'||p[i]>'9'))return false;
  return true;
 }
 return false;
}
bool contains_word(const uint8_t *p,uint32_t length,const char *word){
 if(!p)return false;unsigned n=unsigned(strlen(word));if(n>length)return false;
 for(uint32_t i=0;i+n<=length;++i){bool same=true;for(unsigned k=0;k<n;++k){uint8_t c=p[i+k];if(c>='A'&&c<='Z')c+=32;if(c!=uint8_t(word[k])){same=false;break;}}if(same)return true;}
 return false;
}
bool protected_bytes(const uint8_t *p,uint32_t length){
 // Deliberately conservative. Encodings and URL/template identities are not
 // decoded into a raw logging buffer; unknown encoded material fails closed.
 static const char *words[]={"password","passwd","token","bearer","authorization","cookie","ssid","psk","secret","login","auth","portal","seed","private","session","sid","m64","mac","wic64.net"};
 for(unsigned i=0;i<sizeof(words)/sizeof(words[0]);++i)if(contains_word(p,length,words[i]))return true;
 return false;
}
bool public_static_prg_url(const uint8_t *p,uint32_t length){
 // One public static portal launcher, never the portal's dynamic endpoints.
 // Exact bytes exclude queries, fragments, userinfo, encodings and suffixes.
 if(!p)return false;if(length&&p[length-1]==0)--length;
 static const char *urls[]={"http://x.wic64.net/menue.prg","https://x.wic64.net/menue.prg"};
 for(unsigned i=0;i<sizeof(urls)/sizeof(urls[0]);++i){unsigned n=unsigned(strlen(urls[i]));if(length==n&&!memcmp(p,urls[i],n))return true;}
 return false;
}
bool preview_command(uint8_t command,bool reply){
 // Opaque socket/datagram/POST/echo data is never captured, even with opt-in.
 return reply&&(command==0x01||command==0x0f);
}
bool request_is_protected(uint8_t command,const uint8_t *payload,uint32_t length){
 if((command==0x01||command==0x0f)&&public_static_prg_url(payload,length))return false;
 if(protected_bytes(payload,length))return true;
 if(command==0x01||command==0x0f){
  // Only a literal printable absolute URL can be shown. Encoded URL binary,
  // query values, fragments and userinfo can hold credentials under any name.
  for(uint32_t i=0;payload&&i<length;++i){uint8_t c=payload[i];if(!c&&i+1==length)break;if(c<33||c>126||c=='?'||c=='%'||c=='@'||c=='#')return true;}
  if(!payload||length<7)return true;
  static const char *schemes[]={"http://","https://"};
  for(unsigned which=0;which<2;++which){unsigned n=which?8:7;if(length<n)continue;bool same=true;for(unsigned i=0;i<n;++i){uint8_t c=payload[i];if(c>='A'&&c<='Z')c+=32;if(c!=uint8_t(schemes[which][i]))same=false;}if(same)return false;}
  return true;
 }
 return !preview_command(command,false);
}
// Called only while the logger ownership word is held. A lost or overwritten
// context cannot authorize an opaque response, and protection is sticky across
// the URL expansion/redirect records for one request.
bool preview_context(const Entry &e){
 bool request=false;
 if(e.command==0x01||e.command==0x0f){
  if(!e.request_id||__atomic_load_n(&http_classified_request,__ATOMIC_ACQUIRE)!=e.request_id||__atomic_load_n(&http_private_request,__ATOMIC_ACQUIRE)==e.request_id)return false;
 }
 for(unsigned i=0;i<count;++i){const Entry &prior=ring[(head+i)%CAPACITY];
  if(prior.request_id!=e.request_id||prior.command!=e.command||prior.protocol!=e.protocol)continue;
  if(prior.flags&PROTECTED)return false;
  if(prior.event==PACKET&&prior.color==HOST)request=true;
 }
 return request;
}
bool public_prg_context(const Entry &e,const uint8_t *payload,uint16_t published_count){
 bool result=false,binary=false;
 for(unsigned i=0;i<count;++i){const Entry &prior=ring[(head+i)%CAPACITY];
  if(prior.request_id!=e.request_id||prior.command!=e.command||prior.protocol!=e.protocol)continue;
  if(prior.flags&PROTECTED)return false;
  if(prior.event==HTTP&&prior.color==DEFAULT&&prior.http_status==200&&prior.length==e.length&&(prior.flags&PUBLIC_PRG)&&(prior.flags&HTTP_COMPLETE))result=true;
  if(prior.event==PACKET&&prior.color==DEVICE&&(prior.flags&PUBLIC_PRG))binary=true;
 }
 if(!result)return false;
 // The reviewed launcher is an $0801 PRG. A textual token/auth response from
 // the same URL is not a binary PRG and must retain the keyword protection.
 if(!e.packet_offset)return e.length>=14&&published_count>=14&&payload&&payload[0]==1&&payload[1]==8;
 return binary;
}
void sanitized_url(Entry &e,const uint8_t *p,uint32_t length,bool allow_preview=true,bool protected_flow=false){
 bool secure=false,absolute=false,query=false;
 unsigned prefix=0;
 if(p){
  const char *schemes[]={"http://","https://"};
  for(unsigned which=0;which<2;++which){unsigned n=which?8:7;if(length<n)continue;bool match=true;
   for(unsigned i=0;i<n;++i){uint8_t c=p[i];if(c>='A'&&c<='Z')c+=32;if(c!=uint8_t(schemes[which][i]))match=false;}
   if(match){absolute=true;secure=which!=0;prefix=n;break;}
  }
  for(uint32_t i=0;i<length;++i)if(p[i]=='?'){query=true;break;}
 }
 bool public_prg=(e.command==0x01||e.command==0x0f)&&public_static_prg_url(p,length);
 bool protect=protected_flow||(protected_bytes(p,length)&&!public_prg)||query||!absolute;
 for(uint32_t i=0;p&&i<length;++i){if(!p[i]&&i+1==length)break;if(p[i]<33||p[i]>126||p[i]=='%'||p[i]=='@'){protect=true;break;}}
 if(protect)e.flags|=PROTECTED;
 if(allow_preview&&previews_enabled()&&!protect){
  unsigned at=0;const char *scheme=secure?"https://":"http://";
  for(unsigned i=0;scheme[i]&&at+1<URL_CAPACITY;++i)e.url[at++]=scheme[i];
  uint32_t i=prefix;
  for(;i<length&&p[i]&&p[i]!='?'&&p[i]!='#'&&at+1<URL_CAPACITY;++i){
   e.url[at++]=char(p[i]);
  }
  if(!(e.flags&PROTECTED)){e.url[at]=0;if(i<length&&p[i]&&p[i]!='?'&&p[i]!='#')e.flags|=TRUNCATED;return;}
 }
 // Default mode and every protected flow copy fixed replacement text only.
 const char *text=absolute?(secure?"https://[host redacted]/[path redacted]":"http://[host redacted]/[path redacted]"):"[URL redacted]";
 unsigned at=0;while(text[at]&&at+1<URL_CAPACITY){e.url[at]=text[at];++at;}
 const char *tail=query?"?[query redacted]":"";for(unsigned i=0;tail[i]&&at+1<URL_CAPACITY;++i)e.url[at++]=tail[i];e.url[at]=0;
 e.flags|=URL_REDACTED;
}
void append_http(Entry &e){
 if(e.flags&PROTECTED)__atomic_store_n(&http_private_request,e.request_id,__ATOMIC_RELEASE);
 Guard guard;if(!guard.held){miss();return;}
 append_locked(e);
 if(ring&&e.request_id&&!(e.flags&PROTECTED)&&__atomic_load_n(&http_private_request,__ATOMIC_ACQUIRE)!=e.request_id)
  __atomic_store_n(&http_classified_request,e.request_id,__ATOMIC_RELEASE);
}
}
void request_packet(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,const uint8_t *payload,uint32_t length){
 if(command==0x01||command==0x0f){__atomic_store_n(&http_classified_request,0U,__ATOMIC_RELEASE);__atomic_store_n(&http_private_request,0U,__ATOMIC_RELEASE);}
 if((protocol!='W'&&protocol!='R'&&protocol!='E')||length>8192||(!payload&&length))return;
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.command=command;e.protocol=protocol;
 e.event=PACKET;e.color=HOST;e.length=length;
 e.wire_length=length+(protocol=='E'?6:4);
 if(request_is_protected(command,payload,length))e.flags|=PROTECTED;
 if(command==0x01||command==0x0f||command==0x28||command==0x08)sanitized_url(e,payload,length,false);
 if((command==0x01||command==0x0f)&&(e.flags&PROTECTED))__atomic_store_n(&http_private_request,request_id,__ATOMIC_RELEASE);
 Guard guard;if(!guard.held){miss();return;}
 if(length)e.flags|=REDACTED;
 append_locked(e);
}
void response_packet(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,uint8_t status,uint8_t response_flags,const uint8_t *payload,uint32_t total,uint32_t offset,uint16_t published_count){
 if((protocol!='W'&&protocol!='R'&&protocol!='E')||total>65536||(protocol!='E'&&total>65535)||offset>total||published_count>total-offset||published_count>256||(!payload&&published_count)||(response_flags&~1)||(response_flags&&(protocol!='W'||total<=2)))return;
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.command=command;e.protocol=protocol;
 e.event=PACKET;e.color=DEVICE;e.status=status;e.length=total;e.packet_offset=offset;
 if(!offset){
  e.flags|=FRAME_HEADER;
  uint32_t reported=protocol=='W'&&(response_flags&1)&&total>2?total-2:total;
  if(protocol=='W'&&(response_flags&1)&&total>2)e.flags|=PRG_LENGTH_ADJUSTED;
  if(protocol=='W'){sample_byte(e,uint8_t(reported>>8));sample_byte(e,uint8_t(reported));}
  else {sample_byte(e,status);sample_byte(e,uint8_t(reported));sample_byte(e,uint8_t(reported>>8));if(protocol=='E'){sample_byte(e,uint8_t(reported>>16));sample_byte(e,uint8_t(reported>>24));}}
 }else e.flags|=CONTINUATION;
 e.wire_length=uint32_t(published_count)+e.sample_length;
 Guard guard;if(!guard.held){miss();return;}
 if(published_count){
  bool known_public=!status&&total==published_count&&public_reply(command,payload,total,offset);
  bool context=preview_context(e);
  bool public_prg=context&&public_prg_context(e,payload,published_count);
  bool preview=previews_enabled()&&preview_command(command,true)&&context&&(public_prg||!protected_bytes(payload,published_count));
  if(preview&&public_prg)e.flags|=PUBLIC_PRG;
  if(known_public||preview){
   unsigned limit=published_count;if(limit>unsigned(SAMPLE_CAPACITY-e.sample_length)){limit=SAMPLE_CAPACITY-e.sample_length;e.flags|=TRUNCATED;}
   for(unsigned i=0;i<limit;++i)sample_byte(e,payload[i]);
  }else {e.flags|=REDACTED;if(!preview_context(e)||protected_bytes(payload,published_count))e.flags|=PROTECTED;}
 }
 append_locked(e);
}
void http_detail(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,const uint8_t *url,uint32_t length,uint16_t status,bool protected_flow,const uint8_t *raw_request,uint32_t raw_length){
 // Invalidate authorization before any work. Contention, oversize URLs or a
 // dropped redirect classification must never authorize an opaque HTTP body.
 __atomic_store_n(&http_classified_request,0U,__ATOMIC_RELEASE);
 if(length>8192||(!url&&length)){url=0;length=0;protected_flow=true;}
 if(request_id&&__atomic_load_n(&http_private_request,__ATOMIC_ACQUIRE)==request_id)protected_flow=true;
 bool have_raw=raw_request||raw_length;
 if(raw_length>8192||(!raw_request&&raw_length)){raw_request=0;raw_length=0;protected_flow=true;}
 if(have_raw&&request_is_protected(command,raw_request,raw_length))protected_flow=true;
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.command=command;e.protocol=protocol;
 e.event=HTTP;e.http_status=status;sanitized_url(e,url,length,true,protected_flow);
 if(have_raw){
  e.color=HOST;e.length=raw_length;
  if(raw_length&&previews_enabled()&&!(e.flags&PROTECTED)&&(command==0x01||command==0x0f)){
   unsigned limit=raw_length>SAMPLE_CAPACITY?unsigned(SAMPLE_CAPACITY):unsigned(raw_length);
   for(unsigned i=0;i<limit;++i)sample_byte(e,raw_request[i]);
   if(raw_length>limit)e.flags|=TRUNCATED;
  }else if(raw_length)e.flags|=REDACTED;
 }
 append_http(e);
}
void http_result(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,const uint8_t *url,uint32_t length,uint16_t status,uint32_t body_length,bool protected_flow){
 __atomic_store_n(&http_classified_request,0U,__ATOMIC_RELEASE);
 if(length>8192||(!url&&length)){url=0;length=0;protected_flow=true;}
 if(request_id&&__atomic_load_n(&http_private_request,__ATOMIC_ACQUIRE)==request_id)protected_flow=true;
 Entry e={};e.tick_ms=tick_ms;e.request_id=request_id;e.command=command;e.protocol=protocol;
 e.event=HTTP;e.http_status=status;e.length=body_length;e.flags|=HTTP_COMPLETE;
 sanitized_url(e,url,length,true,protected_flow);
 if(!(e.flags&PROTECTED)&&status==200&&(command==0x01||command==0x0f)&&public_static_prg_url(url,length))e.flags|=PUBLIC_PRG;
 append_http(e);
}
unsigned format_line(const Entry &e,char *out,unsigned capacity,bool compact){
 if(!out||!capacity)return 0;
 char length_hex[9],wire_hex[9];minimal_hex(e.length,length_hex);minimal_hex(e.wire_length,wire_hex);
 if(compact){snprintf(out,capacity,"WiC64: %u $%02X/%c %c S%u E%u",unsigned(bounded(e.seq)),unsigned(e.command),char(safe_protocol(e.protocol)),event_name(e.event)[0],unsigned(e.status),unsigned(e.error));if(capacity>39)out[39]=0;}
 else if(e.event==PACKET){
  if(e.color==HOST)snprintf(out,capacity,"WiC64: command %s (len=%u/0x%s, using %s)",command_name(e.command),unsigned(e.length),length_hex,protocol_name(e.protocol));
  else if(e.flags&CONTINUATION)snprintf(out,capacity,"WiC64: sends window offset %u, %u/0x%s bytes, %s %s ($%02X)",unsigned(e.packet_offset),unsigned(e.wire_length),wire_hex,protocol_name(e.protocol),command_name(e.command),unsigned(e.command));
  else snprintf(out,capacity,"WiC64: sends %u/0x%s bytes, %s %s ($%02X), status %u",unsigned(e.length),length_hex,protocol_name(e.protocol),command_name(e.command),unsigned(e.command),unsigned(e.status));
 }else if(e.event==HTTP){
  if(e.color==HOST)snprintf(out,capacity,"WiC64: HTTP GET request URL bytes (len=%u/0x%s, using %s)",unsigned(e.length),length_hex,protocol_name(e.protocol));
  else if(e.flags&HTTP_COMPLETE)snprintf(out,capacity,"WiC64: HTTP %s: got %u bytes, URL: '%s', http code = %u",e.command==0x2b?"POST":"GET",unsigned(e.length),e.url[0]?e.url:"[URL redacted]",unsigned(e.http_status));
  else snprintf(out,capacity,"WiC64: HTTP %s URL %s, status %u",e.command==0x2b?"POST":"GET",e.url[0]?e.url:"[URL redacted]",unsigned(e.http_status));
 }
 else snprintf(out,capacity,"WiC64: #%u %s %s ($%02X), %s, %s/%s, status %u error %u HTTP %u, length %u (0x%08X), %u ms, engine%d",unsigned(bounded(e.seq)),event_name(e.event),command_name(e.command),unsigned(e.command),protocol_name(e.protocol),p08::trace_phase_name(e.phase),p08::trace_lifecycle_name(e.lifecycle),unsigned(e.status),unsigned(e.error),unsigned(e.http_status),unsigned(bounded(e.length)),unsigned(bounded(e.length)),unsigned(bounded(e.elapsed_ms)),int(e.engine_error));
 out[capacity-1]=0;return unsigned(strlen(out));
}
unsigned format_record(const Entry &e,unsigned line,char *out,unsigned capacity){
 if(!out||!capacity)return 0;out[0]=0;if(line>=MAX_RECORD_LINES)return 0;
 if(e.event==PACKET&&(e.flags&PRG_LENGTH_ADJUSTED)){
  if(!line){snprintf(out,capacity,"WiC64: prg URL -> reducing reported len by 2");out[capacity-1]=0;return unsigned(strlen(out));}
  --line;
 }
 if(!line)return format_line(e,out,capacity);
 unsigned current=1;
 bool url_capped=e.event==HTTP&&(e.flags&TRUNCATED)&&e.url[URL_CAPACITY-2]&&e.url[URL_CAPACITY-1]==0;
 if(e.event==HTTP&&e.color!=HOST){
  if(url_capped&&line==current){snprintf(out,capacity,"WiC64: ... (URL display capped at 71 bytes)");out[capacity-1]=0;return unsigned(strlen(out));}
  return 0;
 }
 if(e.event==PACKET||(e.event==HTTP&&e.color==HOST)){
  const unsigned sample=e.sample_length>SAMPLE_CAPACITY?unsigned(SAMPLE_CAPACITY):unsigned(e.sample_length);
  bool pending_get=e.event==PACKET&&e.color==HOST&&(e.command==0x01||e.command==0x0f)&&!sample&&!(e.flags&PROTECTED);
  unsigned rows=(sample+15)/16;
  if(line>=current&&line<current+rows){
   unsigned offset=(line-current)*16;char text[96],offset_hex[9];minimal_hex(e.packet_offset+offset,offset_hex);
   const char zeros[]="0000";unsigned offset_digits=unsigned(strlen(offset_hex));
   unsigned at=unsigned(snprintf(text,sizeof(text),"WiC64: %s%s: ",zeros+(offset_digits<4?offset_digits:4),offset_hex));
   static const char digits[]="0123456789abcdef";
   for(unsigned i=0;i<16;++i){if(offset+i<sample){uint8_t b=e.sample[offset+i];text[at++]=digits[b>>4];text[at++]=digits[b&15];}else{text[at++]=' ';text[at++]=' ';}text[at++]=' ';}
   text[at++]=' ';text[at++]='|';
   for(unsigned i=0;i<16;++i){if(offset+i<sample){uint8_t b=e.sample[offset+i];text[at++]=b>=32&&b<127?char(b):'.';}else text[at++]=' ';}text[at++]='|';text[at]=0;
   snprintf(out,capacity,"%s",text);out[capacity-1]=0;return unsigned(strlen(out));
  }
  current+=rows;
  bool sample_capped=(e.flags&TRUNCATED)&&(e.event==PACKET||(sample==SAMPLE_CAPACITY&&e.length>sample));
  if(sample_capped){if(line==current){snprintf(out,capacity,"WiC64: ... (dump capped at 128 bytes)");out[capacity-1]=0;return unsigned(strlen(out));}++current;}
  if(e.flags&REDACTED){if(line==current){snprintf(out,capacity,"WiC64: %s",pending_get?"[GET URL bytes follow HTTP validation; Data On required]":"[payload redacted: opaque or sensitive data]");out[capacity-1]=0;return unsigned(strlen(out));}++current;}
  if(url_capped){if(line==current){snprintf(out,capacity,"WiC64: ... (URL display capped at 71 bytes)");out[capacity-1]=0;return unsigned(strlen(out));}++current;}
  if(!pending_get&&e.url[0]&&line==current){snprintf(out,capacity,"WiC64: URL %s",e.url);out[capacity-1]=0;return unsigned(strlen(out));}
 }
 return 0;
}
#if defined(P18_LOG_HOST_TEST)
void test_reset(){Guard guard;if(!guard.held)return;if(!ring&&!fail_allocation)ring=static_cast<Entry*>(malloc(CAPACITY*sizeof(Entry)));allocation_attempted=true;if(ring)memset(ring,0,CAPACITY*sizeof(Entry));head=count=0;generation=next_sequence=1;overwritten=last_tick=0;have_tick=false;__atomic_store_n(&configured_level,uint32_t(INFO),__ATOMIC_RELEASE);__atomic_store_n(&preview_enabled,0U,__ATOMIC_RELEASE);__atomic_store_n(&http_classified_request,0U,__ATOMIC_RELEASE);__atomic_store_n(&http_private_request,0U,__ATOMIC_RELEASE);clear_missed();}
bool test_force_sequence(uint32_t next){Guard guard;if(!guard.held||!next||next>MAX_COUNTER)return false;next_sequence=next;return true;}
bool test_force_counters(uint32_t epoch,uint32_t lost,uint32_t replaced){Guard guard;if(!guard.held||!epoch||epoch>MAX_COUNTER||lost>MAX_COUNTER||replaced>MAX_COUNTER)return false;generation=epoch;overwritten=replaced;
#if defined(P18_LOG_NATIVE_GUARD_TEST)
 portENTER_CRITICAL();missed=lost;portEXIT_CRITICAL();
#else
 __atomic_store_n(&missed,lost,__ATOMIC_RELAXED);
#endif
 return true;}
bool test_hold_lock(bool acquire){if(!acquire){release();return true;}return claim();}
bool test_contains(const uint8_t *bytes,unsigned length){
 Guard guard;if(!guard.held||!ring||!bytes||!length||length>CAPACITY*sizeof(Entry))return false;
 const uint8_t *p=reinterpret_cast<const uint8_t*>(ring);
 for(unsigned i=0;i+length<=CAPACITY*sizeof(Entry);++i)if(!memcmp(p+i,bytes,length))return true;
 return false;
}
void test_fail_allocation(bool fail){Guard guard;if(!guard.held)return;if(ring){memset(ring,0,CAPACITY*sizeof(Entry));free(ring);ring=0;}head=count=0;allocation_attempted=false;fail_allocation=fail;}
#endif
}
