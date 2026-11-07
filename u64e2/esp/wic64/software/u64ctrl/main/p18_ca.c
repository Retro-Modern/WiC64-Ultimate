/* P18 trusted CA candidates. GPL-3.0-or-later.
 * Keep complete certificates in flash and let mbedTLS build and verify the
 * chain using every matching trusted signer. No verification flags are erased.
 */
#include "p18_ca.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include <stdint.h>
#include <string.h>

#if !defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
#error P18 requires the mbedTLS trusted certificate callback
#endif

extern const unsigned char p18_ca_start[] asm("_binary_p18_ca_store_bin_start");
extern const unsigned char p18_ca_end[] asm("_binary_p18_ca_store_bin_end");

typedef struct {
    const unsigned char *data;
    size_t size;
} ca_store_t;

static uint32_t read32(const unsigned char *p){
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}

static void free_candidates(mbedtls_x509_crt *candidates){
    mbedtls_x509_crt_free(candidates);
    mbedtls_free(candidates);
}

static int ca_candidates(void *context,const mbedtls_x509_crt *child,
                         mbedtls_x509_crt **output){
    const ca_store_t *store=context;
    const unsigned char *p;
    size_t remaining;
    mbedtls_x509_crt *candidates=NULL;
    int result=MBEDTLS_ERR_X509_INVALID_FORMAT;
    *output=NULL;
    if(!store||store->size<12||memcmp(store->data,"P18CAs01",8))return result;
    uint32_t count=read32(store->data+8);
    if(!count||count>200)return result;
    p=store->data+12;remaining=store->size-12;
    for(uint32_t i=0;i<count;i++){
        if(remaining<6)goto fail;
        size_t name_size=(size_t)p[0]|(size_t)p[1]<<8;
        size_t cert_size=read32(p+2);
        p+=6;remaining-=6;
        if(!name_size||!cert_size||name_size>remaining||cert_size>remaining-name_size)goto fail;
        /* A length filter also retains equivalent PrintableString/UTF8String
         * and case variants. mbedTLS itself checks the actual distinguished
         * name, CA constraints and signature before selecting a signer. */
        if(name_size==child->issuer_raw.len){
            if(!candidates){
                candidates=mbedtls_calloc(1,sizeof(*candidates));
                if(!candidates){result=MBEDTLS_ERR_X509_ALLOC_FAILED;goto fail;}
                mbedtls_x509_crt_init(candidates);
            }
            /* The table is immutable firmware flash and outlives the parsed
             * candidates. The normal parser/free routines own all other data. */
            result=mbedtls_x509_crt_parse_der_nocopy(candidates,p+name_size,cert_size);
            if(result)goto fail;
            result=MBEDTLS_ERR_X509_INVALID_FORMAT;
        }
        p+=name_size+cert_size;remaining-=name_size+cert_size;
    }
    if(remaining)goto fail;
    /* No match is not fatal: mbedTLS can try a supplied intermediate next.
     * It owns the returned list and releases it after chain verification. */
    *output=candidates;
    return 0;
fail:
    free_candidates(candidates);
    return result;
}

int p18_ca_attach(mbedtls_ssl_config *config){
    static ca_store_t store;
    store.data=p18_ca_start;
    store.size=(size_t)(p18_ca_end-p18_ca_start);
    if(store.size<12||memcmp(store.data,"P18CAs01",8))return MBEDTLS_ERR_X509_INVALID_FORMAT;
    mbedtls_ssl_conf_ca_cb(config,ca_candidates,&store);
    return 0;
}
