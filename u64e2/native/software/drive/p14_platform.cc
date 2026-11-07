#include "p14_platform.h"
#include "p08_http.h"
#include "p12_storage.h"
#include <string.h>

#if defined(P14_PLATFORM_HOST_TEST)
#include <mutex>
#else
#include "FreeRTOS.h"
#include "task.h"
#include "iomap.h"
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>

namespace p14 {
namespace {
static const uint32_t MIN_UTC=1793232000u; // P14 release floor: 2026-10-29 UTC
static const uint32_t MAX_UTC=4102444799u; // 2099-12-31, including post-2038 dates
static const char ID_DOMAIN[]="C64U-WiC64-P14-bootstrap-id-v1";
static const char NEXT_DOMAIN[]="C64U-WiC64-P14-next-seed-v1";
static const char ENTROPY_DOMAIN[]="C64U-WiC64-P14-entropy-v1";

bool initialized=false,storage_blocked=false,storage_writable=false;
bool cached_provisioned=false;
bool auto_boot_clean=false,auto_inflight=false;
const p08::BackendContext *bound_context=0;
Result blocked_reason=STORAGE_BLOCKED;
Result entropy_error=UNSEEDED;
bool setup_attempted=false;
Result setup_attempt_result=OK;
bool bootstrap_attempted=false;
Result bootstrap_attempt_result=OK;
bool clock_valid=false;
uint32_t clock_anchor=0,clock_raw_highwater=0,clock_tick=0,clock_highwater=0;
Result clock_error=CLOCK_UNAVAILABLE;

#if defined(P14_PLATFORM_HOST_TEST)
TestClock test_clock={0,0,0,0};
std::mutex clock_mutex;
struct ClockLock {std::lock_guard<std::mutex> lock;ClockLock():lock(clock_mutex){}};
uint32_t ticks(){return test_clock.ticks?test_clock.ticks(test_clock.context):0;}
uint32_t tick_rate(){return test_clock.ticks_per_second;}
bool rtc_value(uint32_t &out){return test_clock.utc&&test_clock.utc(test_clock.context,out);}
#else
struct ClockLock {ClockLock(){portENTER_CRITICAL();}~ClockLock(){portEXIT_CRITICAL();}};
uint32_t ticks(){return uint32_t(xTaskGetTickCount());}
uint32_t tick_rate(){return configTICK_RATE_HZ;}
bool rtc_value(uint32_t &out){out=*reinterpret_cast<volatile uint32_t*>(RTC_TIMER_BASE);return true;}
#endif

void wipe(void *buffer,unsigned length){volatile uint8_t *p=static_cast<volatile uint8_t*>(buffer);while(length--)*p++=0;}
bool nonzero(const uint8_t *p,unsigned n){uint8_t any=0;while(n--)any|=*p++;return any!=0;}
bool valid_state(const SecureState &s){
    if(s.provisioned)return nonzero(s.seed,32)&&nonzero(s.bootstrap_id,16)&&s.epoch;
    return !nonzero(s.seed,32)&&!nonzero(s.bootstrap_id,16)&&!s.epoch;
}
uint32_t le32(const uint8_t *p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
void put64(uint8_t *p,uint64_t value){for(unsigned i=0;i<8;i++){p[i]=uint8_t(value);value>>=8;}}
uint32_t crc32(const uint8_t *p,unsigned n){uint32_t crc=0xffffffffu;while(n--){crc^=*p++;for(unsigned bit=0;bit<8;bit++)crc=(crc>>1)^((0u-(crc&1u))&0xedb88320u);}return crc^0xffffffffu;}

bool bootstrap_id(const uint8_t seed[32],uint8_t out[16]){
    wc_Sha256 hash={};uint8_t digest[32]={};
    int result=wc_InitSha256(&hash);bool ready=result==0;
    if(!result)result=wc_Sha256Update(&hash,reinterpret_cast<const uint8_t*>(ID_DOMAIN),sizeof(ID_DOMAIN));
    if(!result)result=wc_Sha256Update(&hash,seed,32);
    if(!result)result=wc_Sha256Final(&hash,digest);
    if(!result)memcpy(out,digest,16);
    if(ready)wc_Sha256Free(&hash);wipe(&hash,sizeof(hash));wipe(digest,sizeof(digest));return result==0;
}
bool derive(const SecureState &source,const char *domain,unsigned domain_length,uint64_t epoch,uint16_t requested,unsigned block,uint8_t out[32]){
    Hmac hash={};uint8_t suffix[14]={};alignas(8) uint8_t key[32]={},digest[32]={};
    memcpy(key,source.seed,32);put64(suffix,epoch);
    suffix[8]=uint8_t(requested);suffix[9]=uint8_t(requested>>8);
    suffix[10]=uint8_t(block);suffix[11]=uint8_t(block>>8);suffix[12]=uint8_t(block>>16);suffix[13]=uint8_t(block>>24);
    int result=wc_HmacInit(&hash,0,INVALID_DEVID);bool ready=result==0;
    if(!result)result=wc_HmacSetKey(&hash,WC_SHA256,key,32);
    if(!result)result=wc_HmacUpdate(&hash,reinterpret_cast<const uint8_t*>(domain),domain_length);
    if(!result)result=wc_HmacUpdate(&hash,source.bootstrap_id,16);
    if(!result)result=wc_HmacUpdate(&hash,suffix,sizeof(suffix));
    if(!result)result=wc_HmacFinal(&hash,digest);
    if(!result)memcpy(out,digest,32);
    if(ready)wc_HmacFree(&hash);wipe(&hash,sizeof(hash));wipe(suffix,sizeof(suffix));wipe(key,sizeof(key));wipe(digest,sizeof(digest));return result==0;
}

bool writable_now(){
    p12::Status status={};
    if(!p12::get_status(status))return false;
    ClockLock lock;
    storage_writable=status.initialized&&status.writable;
    return storage_writable;
}
// A writable flash window alone does not prove that existing private data was
// loaded. Corrupt/unknown/unreadable credentials must never be replaced by an
// automatic seed after a later ordinary preference save repairs status flags.
bool clean_journal(const p08::BackendContext &context,const p12::Status &s){
    if(!s.initialized||!s.writable||s.recovered||s.dirty)return false;
    if(s.state==p12::EMPTY_STATE)return s.last_error==p12::EMPTY&&!s.persisted&&!s.generation&&!s.length;
    return s.state==p12::READY&&s.last_error==p12::OK&&s.persisted&&s.generation&&s.length&&
        context.credentials_saved&&!context.credentials_dirty;
}
Result bootstrap_gate(const p08::BackendContext &context,bool &needed,p12::Status *snapshot=0){
    needed=false;
    {
        ClockLock lock;
        if(!initialized||bound_context!=&context)return UNSEEDED;
        if(!valid_state(context.secure))return BAD_SETUP;
        if(storage_blocked)return blocked_reason;
        if(!storage_writable||!context.persist_credentials)return STORAGE_UNAVAILABLE;
        if(context.secure.provisioned)return cached_provisioned?OK:UNSEEDED;
        if(cached_provisioned||!auto_boot_clean)return STORAGE_BLOCKED;
    }
    p12::Status current={};
    if(!p12::get_status(current))return STORAGE_UNAVAILABLE;
    if(!clean_journal(context,current))return STORAGE_BLOCKED;
    {
        ClockLock lock;
        if(!initialized||bound_context!=&context)return UNSEEDED;
        if(!valid_state(context.secure))return BAD_SETUP;
        if(storage_blocked)return blocked_reason;
        if(!storage_writable||!context.persist_credentials)return STORAGE_UNAVAILABLE;
        if(context.secure.provisioned)return cached_provisioned?OK:UNSEEDED;
        if(cached_provisioned||!auto_boot_clean)return STORAGE_BLOCKED;
        needed=true;
    }
    if(snapshot)*snapshot=current;
    return OK;
}
Result entropy_fail(Result result){ClockLock lock;entropy_error=result;return result;}
Result setup_result(Result result){ClockLock lock;setup_attempted=true;setup_attempt_result=result;return result;}
void mark_entropy_blocked(Result result){ClockLock lock;storage_blocked=true;blocked_reason=entropy_error=result;}
Result clock_fail(Result result){clock_valid=false;clock_error=result;return result;}
bool coherent_utc(uint32_t &out){
    // The native register is byte-wide behind the CPU's 32-bit bus adapter.
    // Repeated equal reads avoid a carry across a mixed-byte second value.
    for(unsigned attempt=0;attempt<4;attempt++){
        uint32_t first=0,second=0;
        if(!rtc_value(first)||!rtc_value(second))return false;
        if(first==second){out=first;return true;}
    }return false;
}
}

void initialize(const p08::BackendContext &context,bool recovered,bool writable){
    // Sticky for this complete management-program lifetime. Normal saves may
    // clear Storage::recovered, but must never clear this RNG prohibition.
    p12::Status initial={};
    const bool clean=p12::get_status(initial)&&clean_journal(context,initial)&&context.persist_credentials;
    ClockLock lock;
    if(!initialized){storage_blocked=recovered||!writable;auto_boot_clean=clean&&!recovered&&writable;initialized=true;}
    else {
        // Never promote a failed initial load after a later normal save.
        if(recovered||!writable||!clean||bound_context!=&context)auto_boot_clean=false;
        if(recovered||!writable){if(!storage_blocked)blocked_reason=STORAGE_BLOCKED;storage_blocked=true;}
    }
    bound_context=&context;cached_provisioned=context.secure.provisioned;
    storage_writable=writable;
    if(!valid_state(context.secure)){storage_blocked=true;blocked_reason=BAD_SETUP;}
    entropy_error=storage_blocked?blocked_reason:context.secure.provisioned?OK:UNSEEDED;
}

bool entropy_available(const p08::BackendContext &context){
    ClockLock lock;
    return initialized&&bound_context==&context&&!storage_blocked&&storage_writable&&
        cached_provisioned&&context.persist_credentials;
}
void block_entropy(Result result){mark_entropy_blocked(result);}

Result import_setup(p08::BackendContext &context,const uint8_t *file,uint32_t length){
    // A rejected file does not invalidate an already committed seed. Keep
    // its attempt result separate from current entropy/readiness failures.
    if(!file||length!=SETUP_BYTES||memcmp(file,"W14S",4)||file[4]!=1||file[5]||file[6]!=64||file[7]||le32(file+56))return setup_result(BAD_SETUP);
    if(crc32(file,60)!=le32(file+60))return setup_result(SETUP_CHECKSUM);
    if(!nonzero(file+8,32)||!nonzero(file+40,16))return setup_result(BAD_SETUP);
    uint8_t expected[16]={};
    if(!bootstrap_id(file+8,expected)){wipe(expected,sizeof(expected));return setup_result(entropy_fail(CRYPTO_ERROR));}
    bool matches=!memcmp(expected,file+40,16);wipe(expected,sizeof(expected));
    if(!matches)return setup_result(SETUP_ID);
    if(context.secure.provisioned&&!memcmp(context.secure.bootstrap_id,file+40,16))return setup_result(SETUP_REUSED);
    bool context_ready=false;
    {ClockLock lock;context_ready=initialized&&bound_context==&context;}
    if(!context_ready)return setup_result(entropy_fail(STORAGE_UNAVAILABLE));
    if(!context.persist_credentials||!writable_now())return setup_result(entropy_fail(STORAGE_UNAVAILABLE));
    SecureState before=context.secure,next={};
    next.provisioned=true;memcpy(next.seed,file+8,32);memcpy(next.bootstrap_id,file+40,16);next.epoch=1;
    {ClockLock lock;context.secure=next;cached_provisioned=true;}
    // credentials_changed() calls the existing private journal, whose success
    // includes complete bank readback. A bare RAM mutation is not success.
    bool saved=p08::credentials_changed(context);
    {ClockLock lock;
        if(!saved){context.secure=before;cached_provisioned=before.provisioned;storage_blocked=true;blocked_reason=entropy_error=STORAGE_WRITE_FAILED;}
        else {storage_blocked=false;storage_writable=true;blocked_reason=entropy_error=OK;}
    }
    wipe(&before,sizeof(before));wipe(&next,sizeof(next));return setup_result(saved?OK:STORAGE_WRITE_FAILED);
}

Result ensure_entropy(p08::BackendContext &context,const BootstrapSource &source){
    bool needed=false;Result gate=bootstrap_gate(context,needed);
    if(gate!=OK){
        if(gate==STORAGE_BLOCKED||gate==STORAGE_UNAVAILABLE||gate==BAD_SETUP)mark_entropy_blocked(gate);
        return entropy_fail(gate);
    }
    if(!needed)return OK; // No RPC and no write for any existing valid seed.
    if(!source.read||!source.permitted||!source.permitted(source.context))return entropy_fail(UNSEEDED);
    {
        ClockLock lock;if(auto_inflight)return UNSEEDED;auto_inflight=true;
    }
    struct Release {~Release(){ClockLock lock;auto_inflight=false;}} release;
    struct Candidate {
        uint8_t seed[32];SecureState before,next;
        Candidate(){memset(this,0,sizeof(*this));}
        ~Candidate(){wipe(this,sizeof(*this));}
    } candidate;
    Result final_result=UNSEEDED;
    struct Attempt {Result &result;~Attempt(){ClockLock lock;bootstrap_attempted=true;bootstrap_attempt_result=result;}} attempt={final_result};
    auto finish=[&](Result value)->Result{final_result=value;return value;};
    if(!source.read(source.context,candidate.seed)||!source.permitted(source.context)||!nonzero(candidate.seed,32))return finish(entropy_fail(UNSEEDED));
    // The source callback may have yielded to storage/configuration work. Check
    // eligibility again; a newly provisioned seed always wins over this value.
    p12::Status previous={};gate=bootstrap_gate(context,needed,&previous);
    if(gate!=OK){
        if(gate==STORAGE_BLOCKED||gate==STORAGE_UNAVAILABLE||gate==BAD_SETUP)mark_entropy_blocked(gate);
        return finish(entropy_fail(gate));
    }
    if(!needed)return finish(OK);
    if(!source.permitted(source.context))return finish(entropy_fail(UNSEEDED));
    if(!bootstrap_id(candidate.seed,candidate.next.bootstrap_id)||!nonzero(candidate.next.bootstrap_id,16))return finish(entropy_fail(CRYPTO_ERROR));
    candidate.next.provisioned=true;memcpy(candidate.next.seed,candidate.seed,32);candidate.next.epoch=1;
    if(!source.permitted(source.context))return finish(entropy_fail(UNSEEDED));
    {
        ClockLock lock;
        if(!valid_state(context.secure)||context.secure.provisioned||cached_provisioned||storage_blocked||!auto_boot_clean)return finish(UNSEEDED);
        candidate.before=context.secure;context.secure=candidate.next;
        // cached_provisioned deliberately stays false until verified commit.
    }
    bool saved=p08::credentials_changed(context);
    p12::Status committed={};
    saved=saved&&p12::get_status(committed)&&clean_journal(context,committed)&&committed.state==p12::READY&&committed.generation>previous.generation;
    {
        ClockLock lock;
        if(!saved){context.secure=candidate.before;cached_provisioned=false;storage_blocked=true;blocked_reason=entropy_error=STORAGE_WRITE_FAILED;}
        else {cached_provisioned=true;storage_writable=true;entropy_error=OK;}
    }
    return finish(saved?OK:STORAGE_WRITE_FAILED);
}

Result reserve_entropy(p08::BackendContext &context,uint8_t *out,uint16_t length){
    if(out&&length<=MAX_ENTROPY_BYTES)wipe(out,length);
    if(!out||!length||length>MAX_ENTROPY_BYTES)return entropy_fail(ARGUMENT);
    {ClockLock lock;
        if(!initialized||bound_context!=&context||!valid_state(context.secure)||!context.secure.provisioned){entropy_error=UNSEEDED;return UNSEEDED;}
        if(storage_blocked){entropy_error=blocked_reason;return STORAGE_BLOCKED;}
    }
    if(!context.persist_credentials||!writable_now()){mark_entropy_blocked(STORAGE_UNAVAILABLE);return STORAGE_UNAVAILABLE;}
    if(context.secure.epoch==UINT64_MAX){mark_entropy_blocked(EPOCH_EXHAUSTED);return EPOCH_EXHAUSTED;}
    SecureState before=context.secure,next=before;
    uint8_t pending[MAX_ENTROPY_BYTES]={},block[32]={};next.epoch++;
    bool derived=derive(before,NEXT_DOMAIN,sizeof(NEXT_DOMAIN),next.epoch,32,0,next.seed);
    for(unsigned offset=0;derived&&offset<length;offset+=32){
        derived=derive(before,ENTROPY_DOMAIN,sizeof(ENTROPY_DOMAIN),next.epoch,length,offset/32,block);
        unsigned n=length-offset>32?32:length-offset;if(derived)memcpy(pending+offset,block,n);
        wipe(block,sizeof(block));
    }
    if(!derived){wipe(&before,sizeof(before));wipe(&next,sizeof(next));wipe(pending,sizeof(pending));return entropy_fail(CRYPTO_ERROR);}
    {ClockLock lock;context.secure=next;}
    bool saved=p08::credentials_changed(context);
    {ClockLock lock;
        if(!saved){context.secure=before;storage_blocked=true;blocked_reason=entropy_error=STORAGE_WRITE_FAILED;}
        else {memcpy(out,pending,length);entropy_error=OK;}
    }
    wipe(&before,sizeof(before));wipe(&next,sizeof(next));wipe(pending,sizeof(pending));wipe(block,sizeof(block));
    return saved?OK:STORAGE_WRITE_FAILED;
}

bool utc_snapshot(uint32_t &seconds){ClockLock lock;seconds=0;return coherent_utc(seconds);}
void note_sntp(uint32_t seconds){note_sntp(seconds,0,false);}
void note_sntp(uint32_t seconds,uint32_t previous,bool previous_valid){
    ClockLock lock;
    uint32_t hardware=0;
    if(seconds<MIN_UTC||seconds>MAX_UTC){clock_fail(CLOCK_RANGE);return;}
    if(clock_anchor){
        // Compare against the actual prewrite hardware value even when no TLS
        // request has sampled time for hours or the RTOS tick counter wrapped.
        if(!previous_valid){clock_fail(CLOCK_UNAVAILABLE);return;}
        uint32_t floor=clock_raw_highwater;
        if(previous>=MIN_UTC&&previous<=MAX_UTC&&previous>floor)floor=previous;
        if(seconds<floor&&uint64_t(floor)-seconds>2){clock_fail(CLOCK_ROLLBACK);return;}
    }
    if(!tick_rate()||!coherent_utc(hardware)){clock_fail(CLOCK_UNAVAILABLE);return;}
    // The callback is after the native UTC register write, not before it.
    if(hardware<seconds||uint64_t(hardware)-seconds>1){clock_fail(CLOCK_CHANGED);return;}
    clock_anchor=clock_raw_highwater=seconds;
    clock_tick=ticks();clock_valid=true;clock_error=OK;
    if(seconds>clock_highwater)clock_highwater=seconds;
}

Result utc_now(uint64_t &seconds){
    seconds=0;ClockLock lock;
    if(!clock_valid)return clock_error;
    uint32_t now=0;
    if(!coherent_utc(now)||!tick_rate())return clock_fail(CLOCK_UNAVAILABLE);
    if(now<MIN_UTC||now>MAX_UTC)return clock_fail(CLOCK_RANGE);
    if(now<clock_anchor||now<clock_raw_highwater)return clock_fail(CLOCK_ROLLBACK);
    uint64_t elapsed=uint64_t(now)-clock_anchor;
    // This independent hardware interval rejects an old SNTP anchor even if
    // the 32-bit FreeRTOS tick counter has wrapped since the last TLS request.
    if(elapsed>CLOCK_MAX_AGE_SECONDS)return clock_fail(CLOCK_STALE);
    uint64_t monotonic=uint64_t(uint32_t(ticks()-clock_tick))/tick_rate();
    if(elapsed>monotonic+2||monotonic>elapsed+2)return clock_fail(CLOCK_CHANGED);
    // Freeze briefly after a <=2-second explicit SNTP correction rather than
    // accumulate an offset on every resync or return an earlier TLS time.
    clock_raw_highwater=now;if(now>clock_highwater)clock_highwater=now;
    seconds=uint64_t(clock_highwater);return OK;
}

bool get_last_setup_result(Result &out){
    ClockLock lock;out=setup_attempt_result;return setup_attempted;
}
bool get_last_bootstrap_result(Result &out){
    ClockLock lock;out=bootstrap_attempt_result;return bootstrap_attempted;
}

void get_status(const p08::BackendContext &context,Status &out){
    uint64_t now=0;Result time=utc_now(now);
    ClockLock lock;
    out.provisioned=bound_context==&context&&cached_provisioned;
    out.entropy_ready=initialized&&bound_context==&context&&!storage_blocked&&storage_writable&&cached_provisioned&&context.persist_credentials;
    out.storage_blocked=storage_blocked;out.time_ready=time==OK;
    out.last_error=out.storage_blocked?blocked_reason:entropy_error!=OK?entropy_error:time;
}

const char *result_name(Result result){
    static const char *names[]={"OK","UNSEEDED","STORAGE_BLOCKED","STORAGE_UNAVAILABLE","STORAGE_WRITE_FAILED",
        "BAD_SETUP","SETUP_CHECKSUM","SETUP_ID","SETUP_REUSED","CRYPTO_ERROR","EPOCH_EXHAUSTED","ARGUMENT",
        "CLOCK_UNAVAILABLE","CLOCK_RANGE","CLOCK_ROLLBACK","CLOCK_STALE","CLOCK_CHANGED"};
    return unsigned(result)<sizeof(names)/sizeof(names[0])?names[result]:"PLATFORM_ERROR";
}

#if defined(P14_PLATFORM_HOST_TEST)
void test_set_clock(const TestClock &clock){ClockLock lock;test_clock=clock;}
void test_reset(){ClockLock lock;initialized=storage_blocked=storage_writable=false;blocked_reason=STORAGE_BLOCKED;entropy_error=UNSEEDED;
    cached_provisioned=false;auto_boot_clean=auto_inflight=false;bound_context=0;setup_attempted=bootstrap_attempted=false;setup_attempt_result=bootstrap_attempt_result=OK;
    clock_valid=false;clock_anchor=clock_raw_highwater=clock_tick=clock_highwater=0;clock_error=CLOCK_UNAVAILABLE;test_clock=TestClock{0,0,0,0};}
#endif
}
