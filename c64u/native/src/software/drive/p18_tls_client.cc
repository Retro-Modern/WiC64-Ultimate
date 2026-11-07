#ifndef C64U_ESP_TLS
#define C64U_ESP_TLS 0
#endif
#if C64U_ESP_TLS != 0 && C64U_ESP_TLS != 1
#error C64U_ESP_TLS must be 0 or 1
#endif
#if C64U_ESP_TLS
#if U64 != 2 || !C64U_API22_ALPHA || !P05_RAM_DIAGNOSTIC || !P14_TLS || !P18_TLS
#error C64U ESP-only TLS requires the C64U RAM Alpha profile and P14/P18 TLS
#endif
#if !defined(P14_TLS_HOST_TEST) && (!RISCV || !C64U_CORE49_FENCELESS)
#error Native C64U ESP-only TLS requires RISC-V and the qualified Core49 profile
#endif
#endif
#include "p64_ordering.h"
#if defined(P18_TLS) && P18_TLS
#include "p18_tls.h"
#include "p18_tls_rpc.h"
#include "p14_platform.h"
#include <string.h>
#include <limits.h>
namespace p18 {
static unsigned selected_engine;
const char *engine_name(){
#if C64U_ESP_TLS
    // Configured engine path only; this does not claim a completed handshake.
    return "ESP TLS (BIO)";
#else
    return p64_ordering::load(&selected_engine,__ATOMIC_ACQUIRE)?"ESP TLS (BIO)":"wolfSSL";
#endif
}
void native_engine_selected(){p64_ordering::store(&selected_engine,0U,__ATOMIC_RELEASE);}
static void wipe(void *m,unsigned n){volatile uint8_t*p=(volatile uint8_t*)m;while(n--)*p++=0;}
bool bootstrap_seed(uint8_t out[32],uint32_t timeout_ms){
    if(!out)return false;wipe(out,32);
    if(!timeout_ms||timeout_ms>100)return false;
    uint8_t frame[P18_TLS_HEADER+32]={};
    struct Clear {uint8_t *p;unsigned n;~Clear(){wipe(p,n);}} clear={frame,sizeof(frame)};
    p18_envelope(frame,P18_TLS_BOOTSTRAP,0,0,0,0);
    uint16_t size=0;
    int result=p18_tls_rpc_exchange(frame,P18_TLS_HEADER,sizeof(frame),&size,timeout_ms);
    if(result||size!=sizeof(frame)||!p18_magic(frame)||frame[8]!=P18_TLS_VERSION||frame[9]!=P18_TLS_OK||
       p18_get16(frame+10)!=32||p18_get64(frame+12)||p18_get32(frame+20)||p18_get32(frame+24))return false;
    uint8_t any=0;for(unsigned i=0;i<32;i++)any|=frame[P18_TLS_HEADER+i];
    if(!any)return false;memcpy(out,frame+P18_TLS_HEADER,32);return true;
}
Stream::Stream(const p14::TlsIo &io,p08::BackendContext &backend,bool persistent):io_(io),backend_(&backend),error_(p14::TLS_OK),token_(0),flags_(0),operation_sequence_(0),tcp_eof_(false),eof_sent_(false),started_(false),drain_next_(false),persistent_(persistent),operation_active_(false),input_n_(0),output_n_(0),output_at_(0),body_n_(0){memset(frame_,0,sizeof(frame_));memset(input_,0,sizeof(input_));memset(output_,0,sizeof(output_));}
Stream::~Stream(){
    if(token_){
        memset(frame_,0,P18_TLS_HEADER);
        p18_envelope(frame_,P18_TLS_CLOSE,0,token_,0,0);
        uint16_t n=0;(void)p18_tls_rpc_exchange(frame_,P18_TLS_HEADER,sizeof(frame_),&n,50);
    }
    wipe(frame_,sizeof(frame_));wipe(input_,sizeof(input_));wipe(output_,sizeof(output_));
}
bool Stream::budget(){
    if(io_.cancelled(io_.context)){error_=p14::TLS_CANCELLED;return false;}
    if(!io_.remaining_ms(io_.context)){error_=p14::TLS_DEADLINE;return false;}
    return true;
}
bool Stream::healthy()const{return error_==p14::TLS_OK;}
bool Stream::status_ok(){
    switch(frame_[9]){
    case P18_TLS_OK:case P18_TLS_WANT:case P18_TLS_BUSY:return true;
    case P18_TLS_EOF:if(flags_&P18_TLS_FLAG_CLEAN_EOF)return true;error_=p14::TLS_READ;return false;
    case P18_TLS_TIMEOUT:error_=p14::TLS_DEADLINE;return false;
    case P18_TLS_VERIFY:error_=p14::TLS_VERIFY;return false;
    default:error_=p14::TLS_HANDSHAKE;return false;
    }
}
bool Stream::transact(uint8_t op,uint32_t arg,const uint8_t *body,uint16_t count,bool begin,bool finish)
{
    if(!healthy()||!budget()||count>P18_TLS_CHUNK){if(healthy())error_=p14::TLS_ARGUMENT;return false;}
    uint32_t left=io_.remaining_ms(io_.context);if(left>P18_TLS_MAX_BUDGET)left=P18_TLS_MAX_BUDGET;
    if(body&&count)memmove(frame_+P18_TLS_HEADER,body,count);
    memset(frame_,0,P18_TLS_HEADER);
    p18_envelope(frame_,op,count,token_,arg,finish?0:left);
    uint16_t n=0;uint32_t wait=left<100?left:100;
    int result=p18_tls_rpc_exchange(frame_,(uint16_t)(P18_TLS_HEADER+count),sizeof(frame_),&n,wait);
    if(result||n<P18_TLS_HEADER||n>sizeof(frame_)||!p18_magic(frame_)||frame_[8]!=P18_TLS_VERSION||p18_get16(frame_+10)!=(uint16_t)(n-P18_TLS_HEADER)||frame_[9]>P18_TLS_CLOSED){error_=p14::TLS_HANDSHAKE;return false;}
    body_n_=(uint16_t)(n-P18_TLS_HEADER);flags_=p18_get32(frame_+20);
    if(flags_&~(P18_TLS_FLAG_READY|P18_TLS_FLAG_WRITE_DONE|P18_TLS_FLAG_CLEAN_EOF)){error_=p14::TLS_HANDSHAKE;return false;}
    uint64_t got=p18_get64(frame_+12);
    if(begin){
        // Explicit BUSY/token0 means no session was allocated. The preceding
        // connection's asynchronous CLOSE may still be finishing; this is the
        // only safe BEGIN retry. Lost replies remain fatal and are never retried.
        if(frame_[9]==P18_TLS_BUSY&&!got&&!body_n_)return budget();
        if((frame_[9]==P18_TLS_OK||frame_[9]==P18_TLS_WANT)&&got&&!body_n_){token_=got;started_=true;}
        else{error_=frame_[9]==P18_TLS_TIMEOUT?p14::TLS_DEADLINE:p14::TLS_HANDSHAKE;return false;}
    }else if(got!=token_){error_=p14::TLS_HANDSHAKE;return false;}
    if(!budget())return false;
    return status_ok();
}
ProbeResult Stream::probe(){
    if(!budget())return PROBE_FAILED;
    memset(frame_,0,P18_TLS_HEADER);p18_envelope(frame_,P18_TLS_CAPS,0,0,persistent_?P18_TLS_OPERATION_QUERY:0,0);
    uint16_t n=0;uint32_t ms=io_.remaining_ms(io_.context);if(ms>100)ms=100;
    int result=p18_tls_rpc_exchange(frame_,P18_TLS_HEADER,sizeof(frame_),&n,ms);
    if(result==-2||result==-1){if(!budget())return PROBE_FAILED;return PROBE_UNSUPPORTED;}
    // Older ESP services reject the optional query explicitly. No session or
    // plaintext exists yet; a clean unsupported response may select the native
    // engine. The existing absent-transport fallback above also stays before
    // BEGIN. Malformed replies remain fatal.
    if(persistent_&&!result&&n==P18_TLS_HEADER&&p18_magic(frame_)&&frame_[8]==P18_TLS_VERSION&&
       frame_[9]==P18_TLS_BAD&&!p18_get16(frame_+10)&&!p18_get64(frame_+12)&&!p18_get32(frame_+20)&&!p18_get32(frame_+24))
        return budget()?PROBE_UNSUPPORTED:PROBE_FAILED;
    if(result||n!=P18_TLS_HEADER+8||!p18_magic(frame_)||frame_[8]!=P18_TLS_VERSION||frame_[9]!=P18_TLS_OK||p18_get16(frame_+10)!=8||p18_get64(frame_+12)!=0||p18_get32(frame_+20)!=0||p18_get32(frame_+24)!=0||p18_get16(frame_+P18_TLS_HEADER+4)!=P18_TLS_CHUNK||p18_get16(frame_+P18_TLS_HEADER+6)!=0){error_=p14::TLS_HANDSHAKE;return PROBE_FAILED;}
    uint32_t features=p18_get32(frame_+P18_TLS_HEADER);
    if(persistent_&&features==P18_TLS_CAP_FEATURES)return budget()?PROBE_UNSUPPORTED:PROBE_FAILED;
    if(features!=(P18_TLS_CAP_FEATURES|(persistent_?P18_TLS_CAP_OPERATION_WINDOWS:0))){error_=p14::TLS_HANDSHAKE;return PROBE_FAILED;}
    return budget()?PROBE_SUPPORTED:PROBE_FAILED;
}
p14::TlsError Stream::connect(const char *host){
    if(started_||!host||!host[0]||strlen(host)>253){error_=p14::TLS_ARGUMENT;return error_;}
    p64_ordering::store(&selected_engine,1U,__ATOMIC_RELEASE);
    uint64_t utc=0;if(p14::utc_now(utc)!=p14::OK)return error_=p14::TLS_TIME_UNAVAILABLE;
    uint8_t begin[8+64+254];memset(begin,0,sizeof(begin));
    struct ClearBegin {uint8_t *p;unsigned n;~ClearBegin(){wipe(p,n);}} clear_begin={begin,sizeof(begin)};
#if C64U_ESP_TLS
    // The ESP's early SAR-seeded private DRBG advances on every BOOTSTRAP.
    // Obtain fresh bytes for this BEGIN only; never claim a host journal save
    // or retry an ambiguous entropy RPC with retained output.
    for(unsigned offset=0;offset<64;offset+=32){
        if(!budget())return error_;
        if(p14::utc_now(utc)!=p14::OK)return error_=p14::TLS_TIME_UNAVAILABLE;
        uint32_t left=io_.remaining_ms(io_.context);if(left>100)left=100;
        bool seeded=bootstrap_seed(begin+8+offset,left);
        if(!budget())return error_;
        if(p14::utc_now(utc)!=p14::OK)return error_=p14::TLS_TIME_UNAVAILABLE;
        if(!seeded)return error_=p14::TLS_UNSEEDED;
    }
#else
    if(p14::reserve_entropy(*backend_,begin+8,64)!=p14::OK)return error_=p14::TLS_UNSEEDED;
#endif
    p18_put64(begin,utc);
    unsigned length=(unsigned)strlen(host)+1;memcpy(begin+72,host,length);
    bool ok=false;
    for(;;){
        if(!transact(P18_TLS_BEGIN,persistent_?P18_TLS_BEGIN_PERSISTENT:0,begin,(uint16_t)(72+length),true))break;
        if(token_){ok=true;break;}
        if(frame_[9]!=P18_TLS_BUSY||!pause())break;
    }
    wipe(begin,sizeof(begin));
    wipe(frame_+P18_TLS_HEADER,sizeof(frame_)-P18_TLS_HEADER);
    if(!ok)return error_;
    while(!(flags_&P18_TLS_FLAG_READY)){
        if(!pump())return error_;
        if(!(flags_&P18_TLS_FLAG_READY)&&!pause())return error_;
    }
    // Handshake success may still have TLS Finished bytes awaiting socket send.
    while(output_at_<output_n_){if(!flush())return error_;if(output_at_<output_n_&&!pause())return error_;}
    if(!budget())return error_;
    operation_active_=persistent_;
    if(persistent_&&!end_operation())return error_;
    return error_=p14::TLS_OK;
}
bool Stream::begin_operation(){
    if(!persistent_)return healthy()&&budget();
    if(!healthy()||!budget())return false;
    if(!started_||operation_active_||operation_sequence_==UINT32_MAX){error_=p14::TLS_ARGUMENT;return false;}
    uint32_t next=operation_sequence_+1;
    if(!transact(P18_TLS_OPERATION,next,0,0))return false;
    if(frame_[9]!=P18_TLS_OK||body_n_||!(flags_&P18_TLS_FLAG_READY)){error_=p14::TLS_HANDSHAKE;return false;}
    operation_sequence_=next;operation_active_=true;return true;
}
bool Stream::end_operation(){
    if(!persistent_)return healthy()&&budget();
    if(!healthy()||!budget())return false;
    if(!started_||!operation_active_){error_=p14::TLS_ARGUMENT;return false;}
    // First drain any TCP output still owned by the CPU. END then fences the
    // worker. An explicit BUSY can be pumped; a lost RPC is never replayed.
    while(output_at_<output_n_){if(!flush())return false;if(output_at_<output_n_&&!pause())return false;}
    for(;;){
        if(!transact(P18_TLS_OPERATION,operation_sequence_,0,0,false,true))return false;
        if(body_n_){error_=p14::TLS_HANDSHAKE;return false;}
        if(frame_[9]==P18_TLS_OK){operation_active_=false;return budget();}
        if(frame_[9]!=P18_TLS_BUSY){error_=p14::TLS_HANDSHAKE;return false;}
        if(!pump()||!pause())return false;
    }
}
bool Stream::flush(){
    while(output_at_<output_n_){
        if(!budget())return false;
        int n=io_.send(io_.context,output_+output_at_,output_n_-output_at_);
        if(n==-2)return true;
        if(n<=0||(unsigned)n>output_n_-output_at_){error_=p14::TLS_WRITE;return false;}
        output_at_=(uint16_t)(output_at_+n);
    }
    output_n_=output_at_=0;return true;
}
bool Stream::pump(){
    if(!budget()||!flush())return false;
    if(output_at_<output_n_)return true;
    if(!input_n_&&!tcp_eof_){
        int n=io_.recv(io_.context,input_,sizeof(input_));
        if(n>0){if(n>(int)sizeof(input_)){error_=p14::TLS_READ;return false;}input_n_=(uint16_t)n;}
        else if(n==0)tcp_eof_=true;
        else if(n!=-2){error_=p14::TLS_READ;return false;}
    }
    // A BUSY input queue can coexist with a full encrypted output queue. An
    // empty pump must drain output before retrying the retained input, or both
    // peers could wait for each other's bounded ring forever.
    bool drain=drain_next_;drain_next_=false;
    uint32_t arg=!drain&&tcp_eof_&&!eof_sent_?P18_TLS_PUMP_EOF:0;
    uint16_t sent_input=drain?0:input_n_;
    if(!transact(P18_TLS_PUMP,arg,input_,sent_input))return false;
    // BUSY explicitly means the input was not accepted. Never retransmit after
    // a missing/ambiguous reply; transact has already made that fatal.
    if(frame_[9]==P18_TLS_BUSY){drain_next_=true;}
    else if(!drain){input_n_=0;if(arg)eof_sent_=true;}
    if(body_n_){memcpy(output_,frame_+P18_TLS_HEADER,body_n_);output_n_=body_n_;output_at_=0;}
    return flush();
}
bool Stream::pause(){
    if(!budget())return false;
    // A TCP readability wait can deadlock while the ESP is still producing
    // ClientHello or Finished. Poll its bounded queues after one scheduler tick
    // instead; the peer cannot answer bytes we have not drained and sent yet.
    p18_tls_rpc_pause();
    return budget();
}
int Stream::read(uint8_t *out,uint32_t capacity,bool available){
    if(!started_||(persistent_&&!operation_active_)||!out||!capacity||capacity>INT_MAX)return error_=p14::TLS_ARGUMENT,-1;
    uint32_t count=capacity<P18_TLS_CHUNK?capacity:P18_TLS_CHUNK;
    for(;;){
        if(!transact(P18_TLS_READ,count,0,0))return -1;
        if(body_n_){if(body_n_>count){error_=p14::TLS_READ;return -1;}memcpy(out,frame_+P18_TLS_HEADER,body_n_);return body_n_;}
        if(frame_[9]==P18_TLS_EOF&&(flags_&P18_TLS_FLAG_CLEAN_EOF))return 0;
        if(frame_[9]!=P18_TLS_WANT&&frame_[9]!=P18_TLS_BUSY){error_=p14::TLS_READ;return -1;}
        if(!pump())return -1;
        if(available)return -2;
        if(!pause())return -1;
    }
}
int Stream::write(const uint8_t *bytes,uint32_t length){
    if(!started_||(persistent_&&!operation_active_)||!bytes||!length||length>INT_MAX)return error_=p14::TLS_ARGUMENT,-1;
    uint16_t count=(uint16_t)(length<P18_TLS_CHUNK?length:P18_TLS_CHUNK);
    for(;;){
        if(!transact(P18_TLS_WRITE,0,bytes,count))return -1;
        if(body_n_){error_=p14::TLS_WRITE;return -1;}
        if(frame_[9]!=P18_TLS_BUSY)break;
        if(!pump()||!pause())return -1;
    }
    while(!(flags_&P18_TLS_FLAG_WRITE_DONE)){
        if(!pump())return -1;
        if(!(flags_&P18_TLS_FLAG_WRITE_DONE)&&!pause())return -1;
    }
    while(output_at_<output_n_){if(!flush())return -1;if(output_at_<output_n_&&!pause())return -1;}
    return budget()?count:-1;
}
}
#endif
