#if P14_TLS
#include "p17e_crypto_trace.h"
#include "p17_trace.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>

namespace {
// The existing leased TLS engine has exactly one caller. Binding only during
// its synchronous connect call cannot overlap a second leased engine caller.
p08::RequestTrace *bound_trace=0;
unsigned primitive_depth=0;

uint16_t bounded_bits(int bits) {return bits>0&&bits<=65535?uint16_t(bits):0;}
uint16_t ecc_bits(const ecc_key *key,int curve_id=0) {
    int id=key&&key->dp?key->dp->id:curve_id;
    switch(id){
    case ECC_SECP256R1:return 256;
    case ECC_SECP384R1:return 384;
    case ECC_SECP521R1:return 521;
    default:return key&&key->dp&&key->dp->size>0&&key->dp->size<=8191?
        uint16_t(key->dp->size*8):0;
    }
}
uint16_t rsa_bits(const RsaKey *key) {
    // n is the public RSA modulus. Do not inspect private components.
    return key?bounded_bits(mp_count_bits(&key->n)):0;
}
class PrimitiveTimer {
    p08::RequestTrace *trace_;
    uint32_t sequence_;
    bool entered_;
public:
    PrimitiveTimer(p08::TraceCryptoKind kind,uint16_t bits):trace_(0),sequence_(0),entered_(false) {
        if(!bound_trace)return;
        entered_=true;
        if(primitive_depth++!=0)return;
        trace_=bound_trace;sequence_=p08::trace_crypto_call_begin(*trace_,kind,bits);
    }
    ~PrimitiveTimer(){
        if(trace_&&sequence_)p08::trace_crypto_call_end(*trace_,sequence_);
        if(entered_)--primitive_depth;
    }
};
}
namespace p14 {
CryptoTraceScope::CryptoTraceScope(p08::RequestTrace &trace):trace_(0) {
    if(!bound_trace){trace_=&trace;bound_trace=&trace;}
}
CryptoTraceScope::~CryptoTraceScope(){if(trace_&&bound_trace==trace_)bound_trace=0;}
}

extern "C" {
int __real_wc_ecc_make_key_ex(WC_RNG *,int,ecc_key *,int);
int __real_wc_ecc_verify_hash(const byte *,word32,const byte *,word32,int *,ecc_key *);
int __real_wc_ecc_shared_secret(ecc_key *,ecc_key *,byte *,word32 *);
int __real_wc_RsaSSL_VerifyInline(byte *,word32,byte **,RsaKey *);
int __real_wc_RsaPSS_VerifyInline(byte *,word32,byte **,enum wc_HashType,int,RsaKey *);
int __real_wc_RsaPSS_VerifyInline_ex(byte *,word32,byte **,enum wc_HashType,int,int,RsaKey *);

int __wrap_wc_ecc_make_key_ex(WC_RNG *rng,int keysize,ecc_key *key,int curve_id) {
    PrimitiveTimer timer(p08::TRACE_CRYPTO_ECC_KEYGEN,bound_trace?ecc_bits(0,curve_id):0);
    return __real_wc_ecc_make_key_ex(rng,keysize,key,curve_id);
}
int __wrap_wc_ecc_verify_hash(const byte *sig,word32 siglen,const byte *hash,word32 hashlen,int *res,ecc_key *key) {
    PrimitiveTimer timer(p08::TRACE_CRYPTO_ECC_VERIFY,bound_trace?ecc_bits(key):0);
    return __real_wc_ecc_verify_hash(sig,siglen,hash,hashlen,res,key);
}
int __wrap_wc_ecc_shared_secret(ecc_key *private_key,ecc_key *public_key,byte *out,word32 *outlen) {
    PrimitiveTimer timer(p08::TRACE_CRYPTO_ECC_SHARED,bound_trace?ecc_bits(private_key):0);
    return __real_wc_ecc_shared_secret(private_key,public_key,out,outlen);
}
int __wrap_wc_RsaSSL_VerifyInline(byte *in,word32 inLen,byte **out,RsaKey *key) {
    PrimitiveTimer timer(p08::TRACE_CRYPTO_RSA_PKCS1,bound_trace?rsa_bits(key):0);
    return __real_wc_RsaSSL_VerifyInline(in,inLen,out,key);
}
int __wrap_wc_RsaPSS_VerifyInline(byte *in,word32 inLen,byte **out,enum wc_HashType hash,int mgf,RsaKey *key) {
    PrimitiveTimer timer(p08::TRACE_CRYPTO_RSA_PSS,bound_trace?rsa_bits(key):0);
    return __real_wc_RsaPSS_VerifyInline(in,inLen,out,hash,mgf,key);
}
int __wrap_wc_RsaPSS_VerifyInline_ex(byte *in,word32 inLen,byte **out,enum wc_HashType hash,int mgf,int saltLen,RsaKey *key) {
    PrimitiveTimer timer(p08::TRACE_CRYPTO_RSA_PSS,bound_trace?rsa_bits(key):0);
    return __real_wc_RsaPSS_VerifyInline_ex(in,inLen,out,hash,mgf,saltLen,key);
}
}
#endif
