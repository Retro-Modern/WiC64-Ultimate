#ifndef P14_WOLFSSL_USER_SETTINGS_H
#define P14_WOLFSSL_USER_SETTINGS_H

#include <time.h>
#ifdef __cplusplus
extern "C" {
#endif
int p14_wolf_seed(void *,unsigned char *,unsigned int);
time_t p14_wolf_time(time_t *);
struct tm *p14_wolf_gmtime(const time_t *,struct tm *);
#ifdef __cplusplus
}
#endif

// A single explicitly leased native TLS client uses this library. Its socket
// callbacks, entropy callback and clock never use host OS or libc defaults.
#define SINGLE_THREADED
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_WOLFSSL_SERVER
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_GENERAL_ALIGNMENT 4
// RV32 does not auto-enable wolfSSL's unaligned-buffer memcpy paths.
#define WOLFSSL_USE_ALIGN
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_NO_ASM
#define CUSTOM_RAND_GENERATE_SEED_OS(os,out,len) p14_wolf_seed((void *)(os),(out),(len))
#define HAVE_HASHDRBG
#define TIME_OVERRIDES
#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE
#define XTIME p14_wolf_time
#define XGMTIME p14_wolf_gmtime

// Certificate-authenticated TLS1.2/1.3 only. No resumption, tickets, 0-RTT,
// PSK, raw-public-key trust, debugging, OpenSSL compatibility or server code.
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define WOLFSSL_IP_ALT_NAME
#define WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY
#define HAVE_HKDF
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define HAVE_AESGCM
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_OLD_TLS
#define NO_SESSION_CACHE
#define NO_SESSION_TICKET
#define NO_PSK
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_ERROR_STRINGS
// Verify the peer through an available trusted path; unused cross-signs need
// not validate, and are never promoted to trust anchors by this option.
#define WOLFSSL_ALT_CERT_CHAINS
#define MAX_CHAIN_DEPTH 6
#define WOLFSSL_MAX_CHAIN_DEPTH 6
#define MAX_CERTIFICATE_SZ 65536
#define MAX_HANDSHAKE_SZ 65536

// Portable 32-bit single-precision maths; no RISC-V assembly extension or
// 64-bit divide instruction is assumed. Use the full portable SP paths for
// P-256/P-384/P-521; SMALL_STACK still moves selected large temporaries to
// the heap. Native frame and linked RAM bounds are checked for this profile.
// RSA public verification through 4096 bits remains enabled.
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_DIV_32
#define SP_WORD_SIZE 32
#define WOLFSSL_SP_384
#define WOLFSSL_SP_521
#define WOLFSSL_SP_4096

#endif
