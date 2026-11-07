#if P14_TLS
#include "p14_tls.h"
#if defined(P18_TLS) && P18_TLS
#include "p18_tls.h"
#endif
#include "p14_platform.h"
#include "p08_http.h"
#include "p17e_crypto_trace.h"
#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
#include "p17f_cache.h"
#endif
#include "p14_trust_roots.h"
#if defined(P14_TLS_HOST_TEST)
#include <mutex>
#else
// Native integer.h declares FALSE/TRUE enum values; bring it in before
// wolfSSL's compatibility macros with the same names are defined.
#include "FreeRTOS.h"
#include "task.h"
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <new>
static_assert(sizeof(time_t)>=8,"TLS certificate time requires native 64-bit time_t");

namespace p14 {
namespace {
// The native service is one worker. The lease also rejects accidental extra
// callers, so SINGLE_THREADED wolfSSL and the global DRBG never run in parallel.
#if defined(P14_TLS_HOST_TEST)
std::mutex engine_mutex;
bool acquire_engine(){return engine_mutex.try_lock();}
void release_engine(){engine_mutex.unlock();}
#else
bool engine_busy=false;
bool acquire_engine(){portENTER_CRITICAL();bool ok=!engine_busy;if(ok)engine_busy=true;portEXIT_CRITICAL();return ok;}
void release_engine(){portENTER_CRITICAL();engine_busy=false;portEXIT_CRITICAL();}
#endif

WC_RNG root_rng;
uint8_t rng_bootstrap_id[16]={};
bool rng_ready=false,library_ready=false;
bool seed_failure=false;
p08::BackendContext *seed_context=0;
WOLFSSL_CTX *trust_context=0;

#if defined(P14_TLS_HOST_TEST)
uint8_t *test_roots=0;
uint32_t test_roots_length=0;
#endif

struct StreamState {
    WOLFSSL *ssl;
    TlsIo io;
    p08::BackendContext *backend;
    bool lease;
#if defined(P18_TLS) && P18_TLS
    p18::Stream *offload;
#endif
    StreamState():ssl(0),backend(0),lease(false)
#if defined(P18_TLS) && P18_TLS
       ,offload(0)
#endif
       {memset(&io,0,sizeof(io));}
};

void wipe(void *data,size_t length)
{volatile uint8_t *p=static_cast<volatile uint8_t *>(data);while(length--)*p++=0;}

bool budget(StreamState &s,TlsError &error)
{
    if(s.io.cancelled(s.io.context)){error=TLS_CANCELLED;return false;}
    if(!s.io.remaining_ms(s.io.context)){error=TLS_DEADLINE;return false;}
    return true;
}

#if defined(P18_TLS) && P18_TLS
bool bootstrap_permitted(void *opaque){
    StreamState *state=static_cast<StreamState *>(opaque);
    return state&&!state->io.cancelled(state->io.context)&&state->io.remaining_ms(state->io.context)>0;
}
bool bootstrap_read(void *opaque,uint8_t seed[32]){
    StreamState *state=static_cast<StreamState *>(opaque);
    if(!bootstrap_permitted(opaque))return false;
    uint32_t left=state->io.remaining_ms(state->io.context);if(left>100)left=100;
    return p18::bootstrap_seed(seed,left)&&bootstrap_permitted(opaque);
}
#endif

// Measure the complete callback, including early deadline/cancellation exits.
// This does not include readiness waits in wait_for() or synchronous TLS math.
struct CallbackTimer {
    p08::BackendContext *backend;
    uint32_t started;
    explicit CallbackTimer(StreamState *state):backend(state?state->backend:0),started(p08::trace_now_ms()){}
    ~CallbackTimer(){if(backend)p08::trace_tls_io_time(backend->trace,uint32_t(p08::trace_now_ms()-started));}
};

int send_callback(WOLFSSL *,char *data,int length,void *context)
{
    StreamState *s=static_cast<StreamState *>(context);CallbackTimer timing(s);
    if(!s||length<0||s->io.cancelled(s->io.context)||!s->io.remaining_ms(s->io.context))return WOLFSSL_CBIO_ERR_GENERAL;
    int result=s->io.send(s->io.context,reinterpret_cast<const uint8_t *>(data),uint32_t(length));
    p08::trace_tls_io(s->backend->trace,true,result>0&&result<=length?result:0);
    if(result==-2)return WOLFSSL_CBIO_ERR_WANT_WRITE;
    if(result<=0||result>length)return WOLFSSL_CBIO_ERR_GENERAL;
    return result;
}
int recv_callback(WOLFSSL *,char *data,int length,void *context)
{
    StreamState *s=static_cast<StreamState *>(context);CallbackTimer timing(s);
    if(!s||length<0||s->io.cancelled(s->io.context)||!s->io.remaining_ms(s->io.context))return WOLFSSL_CBIO_ERR_GENERAL;
    int result=s->io.recv(s->io.context,reinterpret_cast<uint8_t *>(data),uint32_t(length));
    p08::trace_tls_io(s->backend->trace,false,result>0&&result<=length?result:0);
    if(result==-2)return WOLFSSL_CBIO_ERR_WANT_READ;
    if(result==0)return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    if(result<0||result>length)return WOLFSSL_CBIO_ERR_GENERAL;
    return result;
}

bool init_library()
{
    if(library_ready)return true;
    if(wolfSSL_Init()!=WOLFSSL_SUCCESS)return false;
    library_ready=true;return true;
}
bool init_rng(p08::BackendContext &backend)
{
    if(!entropy_available(backend))return false;
    seed_context=&backend;
    // A committed new setup must not reuse an earlier setup's live master,
    // even if an integration accidentally omitted the explicit forget call.
    if(rng_ready&&memcmp(rng_bootstrap_id,backend.secure.bootstrap_id,sizeof(rng_bootstrap_id))){
        wc_FreeRng(&root_rng);wipe(&root_rng,sizeof(root_rng));rng_ready=false;
        wipe(rng_bootstrap_id,sizeof(rng_bootstrap_id));
    }
    if(rng_ready)return true;
    memset(&root_rng,0,sizeof(root_rng));
    if(wc_InitRng(&root_rng)!=0){wc_FreeRng(&root_rng);wipe(&root_rng,sizeof(root_rng));return false;}
    memcpy(rng_bootstrap_id,backend.secure.bootstrap_id,sizeof(rng_bootstrap_id));
    rng_ready=true;return true;
}

bool init_trust(StreamState &state,TlsError &error)
{
    if(!budget(state,error))return false;
    if(trust_context)return true;
    WOLFSSL_CTX *ctx=wolfSSL_CTX_new(wolfTLS_client_method());if(!ctx)return false;
    wolfSSL_CTX_set_verify(ctx,WOLFSSL_VERIFY_PEER,0);
    wolfSSL_CTX_SetIORecv(ctx,recv_callback);wolfSSL_CTX_SetIOSend(ctx,send_callback);
    // Prefer the optimized portable key exchanges and exclude P-224 below
    // the existing 256-bit floor. Retain P-521 last: TLS1.2 peers can also use
    // supported_groups to constrain ECDSA certificates. Certificate functions
    // and mandatory signature/name/date/chain validation remain enabled.
    int groups[]={WOLFSSL_ECC_SECP256R1,WOLFSSL_ECC_SECP384R1,WOLFSSL_ECC_SECP521R1};
    bool ok=wolfSSL_CTX_SetMinVersion(ctx,WOLFSSL_TLSV1_2)==WOLFSSL_SUCCESS&&
        wolfSSL_CTX_SetMinRsaKey_Sz(ctx,2048)==WOLFSSL_SUCCESS&&
        wolfSSL_CTX_SetMinEccKey_Sz(ctx,256)==WOLFSSL_SUCCESS&&
        wolfSSL_CTX_set_groups(ctx,groups,3)==WOLFSSL_SUCCESS&&
        wolfSSL_CTX_set_cipher_list(ctx,"TLS13-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")==WOLFSSL_SUCCESS;
#if defined(P14_TLS_HOST_TEST)
    if(ok&&test_roots){
        ok=budget(state,error)&&wolfSSL_CTX_load_verify_buffer(ctx,test_roots,test_roots_length,WOLFSSL_FILETYPE_PEM)==WOLFSSL_SUCCESS;
        if(!budget(state,error))ok=false;
    }
    else
#endif
    if(ok){
        // Date validation also runs when loading each trust anchor. An aged
        // bundled root must not prevent independent, still-valid roots from
        // working. Skip only expired anchors from this immutable bundle;
        // every other load error remains fatal. Peer chain/leaf validation
        // retains the normal mandatory date checks and no bypass callback.
        unsigned loaded=0;
        for(unsigned i=0;i<TRUST_ROOT_COUNT&&ok;i++){
            if(!budget(state,error)){ok=false;break;}
            p08::trace_phase(state.backend->trace,p08::TRACE_TLS_TRUST,uint16_t(i+1),uint16_t(TRUST_ROOT_COUNT));
            const TrustRootIndex &r=trust_root_index[i];
            int result=wolfSSL_CTX_load_verify_buffer(ctx,trust_root_der+r.offset,r.length,WOLFSSL_FILETYPE_ASN1);
            if(result==WOLFSSL_SUCCESS)++loaded;
            else if(result!=ASN_AFTER_DATE_E){p08::trace_engine_error(state.backend->trace,result);ok=false;}
            if(!budget(state,error)){ok=false;break;}
#if !defined(P14_TLS_HOST_TEST)
            // Let other native tasks run between immutable anchors. There is
            // no fixed per-anchor delay and no partial context publication.
            if(ok&&i+1<TRUST_ROOT_COUNT)taskYIELD();
#endif
            if(!budget(state,error)){ok=false;break;}
        }
        ok=ok&&loaded>0;
    }
    if(!budget(state,error))ok=false;
    if(!ok){wolfSSL_CTX_free(ctx);return false;}
    trust_context=ctx;return true;
}

TlsError failure(StreamState &s,int wolf_error,TlsError fallback)
{
    TlsError result=fallback;if(!budget(s,result))return result;
    if(!entropy_available(*s.backend))return TLS_UNSEEDED;
    if(seed_failure)return TLS_UNSEEDED;
    uint64_t utc=0;if(utc_now(utc)!=OK)return TLS_TIME_UNAVAILABLE;
    switch(wolf_error){
    case DOMAIN_NAME_MISMATCH:case IPADDR_MISMATCH:case ASN_BEFORE_DATE_E:
    case ASN_AFTER_DATE_E:case ASN_NO_SIGNER_E:case ASN_SIG_CONFIRM_E:
        return TLS_VERIFY;
    default:return fallback;
    }
}

bool wait_for(StreamState &s,int wolf_error,TlsError &error)
{
    if(!budget(s,error))return false;
    if(wolf_error!=WOLFSSL_ERROR_WANT_READ&&wolf_error!=WOLFSSL_ERROR_WANT_WRITE)return false;
    if(s.io.wait(s.io.context,wolf_error==WOLFSSL_ERROR_WANT_WRITE))return budget(s,error);
    if(!budget(s,error))return false;
    return false; // caller retains the appropriate handshake/read/write error
}

#if defined(P18_TLS) && P18_TLS
void release_offload(StreamState *state)
{
    if(!state->offload)return;
    state->offload->~Stream();wipe(state->offload,sizeof(p18::Stream));
    free(state->offload);state->offload=0;
}
#endif
void release_state(StreamState *state)
{
    if(!state)return;
    // No TLS shutdown or TCP I/O. The socket may already be closed; the P18
    // destructor only sends a bounded UART abort, never a close-notify exchange.
#if defined(P18_TLS) && P18_TLS
    release_offload(state);
#endif
    if(state->ssl)wolfSSL_free(state->ssl);
    bool lease=state->lease;state->~StreamState();wipe(state,sizeof(*state));free(state);
    if(lease){seed_context=0;release_engine();}
}
}

TlsStream::TlsStream():state_(0),error_(TLS_OK){}
TlsStream::~TlsStream(){release_state(static_cast<StreamState *>(state_));}

TlsError TlsStream::connect(const char *host,bool numeric_host,const TlsIo &io,p08::BackendContext &backend)
{
    return connect_mode(host,numeric_host,io,backend,false);
}
TlsError TlsStream::connect_persistent(const char *host,bool numeric_host,const TlsIo &io,p08::BackendContext &backend)
{
    return connect_mode(host,numeric_host,io,backend,true);
}
TlsError TlsStream::connect_mode(const char *host,bool numeric_host,const TlsIo &io,p08::BackendContext &backend,bool persistent)
{
#if !defined(P18_TLS) || !P18_TLS
    (void)persistent;
#endif
    if(state_||!host||!host[0]||strlen(host)>253||!io.send||!io.recv||!io.wait||!io.cancelled||!io.remaining_ms)return error_=TLS_ARGUMENT;
    error_=TLS_OK;
#if defined(P18_TLS) && P18_TLS
    p18::native_engine_selected();
#endif
    void *memory=malloc(sizeof(StreamState));if(!memory)return error_=TLS_MEMORY;
    StreamState *state=new(memory) StreamState();
    state_=state;state->io=io;state->backend=&backend;
    if(!acquire_engine()){release_state(state);state_=0;return error_=TLS_ARGUMENT;}
    state->lease=true;seed_context=&backend;
    seed_failure=false;
    auto stop=[&](TlsError reason)->TlsError{
        // Preserve cancellation/deadline when a synchronous init operation
        // also fails after its caller's complete-request budget has expired.
        budget(*state,reason);release_state(state);state_=0;return error_=reason;
    };
    if(!budget(*state,error_)){release_state(state);state_=0;return error_;}
    uint64_t utc=0;
    if(utc_now(utc)!=OK){release_state(state);state_=0;return error_=TLS_TIME_UNAVAILABLE;}
#if defined(P18_TLS) && P18_TLS
    if(!entropy_available(backend)){
        const BootstrapSource source={bootstrap_read,bootstrap_permitted,state};
        Result seeded=ensure_entropy(backend,source);
        if(!budget(*state,error_))return stop(error_);
        if(seeded!=OK)return stop(TLS_UNSEEDED);
    }
#endif
    if(!entropy_available(backend)){release_state(state);state_=0;return error_=TLS_UNSEEDED;}
    if(!budget(*state,error_))return stop(error_);
#if defined(P18_TLS) && P18_TLS
    if(!numeric_host){
        // Target ordinary new panics on OOM, and its delete uses a different
        // allocation domain. Pair checked malloc with explicit placement/free.
        void *offload_memory=malloc(sizeof(p18::Stream));
        if(!offload_memory)return stop(TLS_MEMORY);
        state->offload=new(offload_memory) p18::Stream(io,backend,persistent);
        p18::ProbeResult capability=state->offload->probe();
        if(capability==p18::PROBE_FAILED)return stop(state->offload->error());
        if(capability==p18::PROBE_SUPPORTED){
            p08::trace_phase(backend.trace,p08::TRACE_TLS_HANDSHAKE);
            p08::trace_tls_call_begin(backend.trace);
            TlsError result=state->offload->connect(host);
            p08::trace_tls_call_end(backend.trace);
            if(result!=TLS_OK)return stop(result);
            return error_=TLS_OK;
        }
        release_offload(state);
    }
#endif
#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
    // The SP text has a low execution address but is staged in high RAM.
    // No wolfSSL initialization or SP entry may run before this succeeds.
    if(!p17f::prepare_math_cache())return stop(TLS_MEMORY);
    if(!budget(*state,error_))return stop(error_);
#endif
    p08::trace_phase(backend.trace,p08::TRACE_TLS_LIBRARY);
    if(!init_library())return stop(TLS_MEMORY);
    if(!budget(*state,error_))return stop(error_);
    p08::trace_phase(backend.trace,p08::TRACE_TLS_ENTROPY);
    if(!init_rng(backend))return stop(TLS_UNSEEDED);
    if(!budget(*state,error_))return stop(error_);
    p08::trace_phase(backend.trace,p08::TRACE_TLS_TRUST);
    if(!init_trust(*state,error_))return stop(error_==TLS_OK?TLS_VERIFY:error_);
    if(!budget(*state,error_))return stop(error_);
    p08::trace_phase(backend.trace,p08::TRACE_TLS_SESSION);
    state->ssl=wolfSSL_new(trust_context);
    if(!state->ssl){TlsError why=seed_failure||!entropy_available(backend)?TLS_UNSEEDED:TLS_MEMORY;return stop(why);}
    if(!budget(*state,error_))return stop(error_);
    wolfSSL_SetIOReadCtx(state->ssl,state);wolfSSL_SetIOWriteCtx(state->ssl,state);
    int identity=numeric_host?wolfSSL_check_ip_address(state->ssl,host):wolfSSL_check_domain_name(state->ssl,host);
    if(identity!=WOLFSSL_SUCCESS||(!numeric_host&&wolfSSL_UseSNI(state->ssl,WOLFSSL_SNI_HOST_NAME,host,uint16_t(strlen(host)))!=WOLFSSL_SUCCESS)){
        release_state(state);state_=0;return error_=TLS_ARGUMENT;
    }
    p08::trace_phase(backend.trace,p08::TRACE_TLS_HANDSHAKE);
    for(;;){
        if(!budget(*state,error_)){release_state(state);state_=0;return error_;}
        p08::trace_tls_call_begin(backend.trace);
        int result;
        {
            // End the numeric primitive binding before any path releases the
            // shared engine lease. The wrappers forward every call unchanged.
            CryptoTraceScope crypto_timing(backend.trace);
            result=wolfSSL_connect(state->ssl);
        }
        p08::trace_tls_call_end(backend.trace);
        if(result==WOLFSSL_SUCCESS){
            // WOLFSSL_VERIFY_PEER with no callback is mandatory on the shared
            // context; successful connect therefore includes its verifier.
            if(!budget(*state,error_)){release_state(state);state_=0;return error_;}
            return error_=TLS_OK;
        }
        int wolf_error=wolfSSL_get_error(state->ssl,result);
        p08::trace_engine_error(backend.trace,wolf_error);
        if(wait_for(*state,wolf_error,error_))continue;
        error_=failure(*state,wolf_error,error_==TLS_OK?TLS_HANDSHAKE:error_);
        release_state(state);state_=0;return error_;
    }
}


TlsError TlsStream::begin_operation()
{
    StreamState *state=static_cast<StreamState *>(state_);
    if(!state)return error_=TLS_ARGUMENT;
#if defined(P18_TLS) && P18_TLS
    if(state->offload){
        if(error_!=TLS_OK)return error_;
        if(!state->offload->begin_operation())error_=state->offload->error();return error_;
    }
#endif
    // Native TLS has no ESP operation window. Preserve its stored record/EOF
    // error so already authenticated buffered TCP data can still be drained.
    return TLS_OK;
}
TlsError TlsStream::end_operation()
{
    StreamState *state=static_cast<StreamState *>(state_);
    if(!state)return error_=TLS_ARGUMENT;
#if defined(P18_TLS) && P18_TLS
    if(state->offload){
        if(error_!=TLS_OK)return error_;
        if(!state->offload->end_operation())error_=state->offload->error();return error_;
    }
#endif
    // Native TLS has no ESP operation window. Preserve its stored record/EOF
    // error so already authenticated buffered TCP data can still be drained.
    return TLS_OK;
}

int TlsStream::read(uint8_t *out,uint32_t capacity)
{
    StreamState *state=static_cast<StreamState *>(state_);
    if(!state||!out||!capacity||capacity>INT_MAX){error_=TLS_ARGUMENT;return -1;}
    seed_context=state->backend;
    for(;;){
        if(!budget(*state,error_))return -1;
        if(!entropy_available(*state->backend)){error_=TLS_UNSEEDED;return -1;}
        uint64_t utc=0;if(utc_now(utc)!=OK){error_=TLS_TIME_UNAVAILABLE;return -1;}
        // Attempt first: wolfSSL may already hold decrypted bytes even when
        // the underlying socket is not readable.
#if defined(P18_TLS) && P18_TLS
        if(state->offload){int n=state->offload->read(out,capacity);error_=state->offload->error();return n;}
#endif
        int result=wolfSSL_read(state->ssl,out,int(capacity));
        if(result>0)return result;
        int wolf_error=wolfSSL_get_error(state->ssl,result);
        if(wolf_error==WOLFSSL_ERROR_ZERO_RETURN)return 0;
        if(wait_for(*state,wolf_error,error_))continue;
        error_=failure(*state,wolf_error,error_==TLS_OK?TLS_READ:error_);return -1;
    }
}
int TlsStream::read_available(uint8_t *out,uint32_t capacity)
{
    StreamState *state=static_cast<StreamState *>(state_);
    if(!state||!out||!capacity||capacity>INT_MAX){error_=TLS_ARGUMENT;return -1;}
    seed_context=state->backend;
    if(!budget(*state,error_))return -1;
    if(!entropy_available(*state->backend)){error_=TLS_UNSEEDED;return -1;}
    uint64_t utc=0;if(utc_now(utc)!=OK){error_=TLS_TIME_UNAVAILABLE;return -1;}
#if defined(P18_TLS) && P18_TLS
    if(state->offload){int n=state->offload->read(out,capacity,true);error_=state->offload->error();return n;}
#endif
    int result=wolfSSL_read(state->ssl,out,int(capacity));
    if(result>0){error_=TLS_OK;return result;}
    int wolf_error=wolfSSL_get_error(state->ssl,result);
    if(wolf_error==WOLFSSL_ERROR_ZERO_RETURN){error_=TLS_OK;return 0;}
    if(wolf_error==WOLFSSL_ERROR_WANT_READ||wolf_error==WOLFSSL_ERROR_WANT_WRITE){error_=TLS_OK;return -2;}
    error_=failure(*state,wolf_error,TLS_READ);return -1;
}
int TlsStream::write(const uint8_t *data,uint32_t length)
{
    StreamState *state=static_cast<StreamState *>(state_);
    if(!state||!data||!length||length>INT_MAX){error_=TLS_ARGUMENT;return -1;}
    seed_context=state->backend;
    for(;;){
        if(!budget(*state,error_))return -1;
        if(!entropy_available(*state->backend)){error_=TLS_UNSEEDED;return -1;}
        uint64_t utc=0;if(utc_now(utc)!=OK){error_=TLS_TIME_UNAVAILABLE;return -1;}
#if defined(P18_TLS) && P18_TLS
        if(state->offload){int n=state->offload->write(data,length);error_=state->offload->error();return n;}
#endif
        int result=wolfSSL_write(state->ssl,data,int(length));
        if(result>0){if(!budget(*state,error_))return -1;return result;}
        int wolf_error=wolfSSL_get_error(state->ssl,result);
        if(wait_for(*state,wolf_error,error_))continue;
        error_=failure(*state,wolf_error,error_==TLS_OK?TLS_WRITE:error_);return -1;
    }
}

const char *tls_error_name(TlsError error)
{
    static const char *names[]={"OK","ARGUMENT","MEMORY","UNSEEDED","TIME_UNAVAILABLE","HANDSHAKE","VERIFY","READ","WRITE","DEADLINE","CANCELLED"};
    return unsigned(error)<sizeof(names)/sizeof(names[0])?names[unsigned(error)]:"UNKNOWN";
}
bool tls_forget_entropy()
{
    if(!acquire_engine())return false;
    if(rng_ready)wc_FreeRng(&root_rng);
    wipe(&root_rng,sizeof(root_rng));wipe(rng_bootstrap_id,sizeof(rng_bootstrap_id));
    rng_ready=false;seed_context=0;release_engine();return true;
}
#if defined(P14_TLS_HOST_TEST)
bool tls_test_trust_pem(const uint8_t *data,uint32_t length)
{
    if((!data&&length)||length>262144||!acquire_engine())return false;
    uint8_t *copy=length?static_cast<uint8_t *>(malloc(length)):0;
    if(length&&!copy){release_engine();return false;}
    if(length)memcpy(copy,data,length);
    if(trust_context){wolfSSL_CTX_free(trust_context);trust_context=0;}
    if(test_roots){wipe(test_roots,test_roots_length);free(test_roots);}
    test_roots=copy;test_roots_length=length;release_engine();return true;
}
void tls_test_reset_rng(){tls_forget_entropy();}
#endif
}

extern "C" int p14_wolf_seed(void *source,unsigned char *out,unsigned int length)
{
    using namespace p14;
    if(!out||!length||length>MAX_ENTROPY_BYTES||!seed_context){seed_failure=true;if(out&&length)wipe(out,length);return -1;}
    // Distinguish the real master Hash_DRBG's OS_Seed from every connection
    // RNG. A master reseed therefore reaches NVreserve directly, never itself.
    if(source==static_cast<void *>(&root_rng.seed)){
        if(reserve_entropy(*seed_context,out,uint16_t(length))==OK)return 0;
    }else if(rng_ready&&entropy_available(*seed_context)&&wc_RNG_GenerateBlock(&root_rng,out,length)==0)return 0;
    seed_failure=true;wipe(out,length);return -1;
}
extern "C" time_t p14_wolf_time(time_t *out)
{
    uint64_t utc=0;time_t value=p14::utc_now(utc)==p14::OK?time_t(utc):time_t(0);
    if(out)*out=value;
    return value;
}
extern "C" struct tm *p14_wolf_gmtime(const time_t *source,struct tm *out)
{return source&&out?gmtime_r(source,out):0;}
#endif
