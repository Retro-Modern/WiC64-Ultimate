/* Narrow C64U ESP32-S3 application installer profile. GPL-3.0-or-later. */
#ifndef C64U_ESP_INSTALL_PROFILE_H
#define C64U_ESP_INSTALL_PROFILE_H
#include <stdint.h>
#include "c64u_esp_image_profile.h"

#ifndef C64U_ESP_TLS_INSTALL
#define C64U_ESP_TLS_INSTALL 0
#endif
#if C64U_ESP_RETURN_APP
#if !C64U_ESP_TLS_INSTALL || !defined(P18M_INITIALIZED_ESP_HEAP) || !P18M_INITIALIZED_ESP_HEAP
#error C64U standalone return requires the reviewed installer and initialized heap
#endif
#if defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
#error C64U standalone return cannot offer the main ESP application bundle
#endif
#endif
#if C64U_ESP_TLS_INSTALL != 0 && C64U_ESP_TLS_INSTALL != 1
#error C64U_ESP_TLS_INSTALL must be 0 or 1
#endif
#if C64U_ESP_TLS_INSTALL
#if !defined(RISCV) || !RISCV || !defined(U64) || U64 != 2 || \
    !defined(C64U_API22_ALPHA) || !C64U_API22_ALPHA || \
    !defined(C64U_CORE49_FENCELESS) || !C64U_CORE49_FENCELESS || \
    !defined(P05_RAM_DIAGNOSTIC) || !P05_RAM_DIAGNOSTIC || \
    !defined(P08_SERVICE) || !P08_SERVICE || !defined(P18_TLS) || !P18_TLS || \
    !defined(FLASH_EXTRA_PROTECTION) || defined(NO_ESP)
#error C64U ESP install requires the protected API22 Core49 RAM profile
#endif
#if defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
#if !defined(C64U_ESP_TLS) || !C64U_ESP_TLS || \
    !defined(P18M_INITIALIZED_ESP_HEAP) || !P18M_INITIALIZED_ESP_HEAP
#error C64U ESP offer requires ESP TLS and the reviewed initialized heap resource
#endif
#endif
#endif

#if defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE && \
    ((!P05_RAM_DIAGNOSTIC && !defined(FLASH_EXTRA_PROTECTION)) || C64U_ESP_TLS_INSTALL)
#define C64U_ESP_BUNDLE_OFFER_ENABLED 1
#else
#define C64U_ESP_BUNDLE_OFFER_ENABLED 0
#endif

/* Keep all host/private-flash protection enabled. Only these UART-ROM app
 * loader methods and the manual, allowlisted FileTypeESP action are exposed. */
#if !defined(FLASH_EXTRA_PROTECTION) || C64U_ESP_TLS_INSTALL
#define C64U_ESP_APP_LOADER_ENABLED 1
#else
#define C64U_ESP_APP_LOADER_ENABLED 0
#endif
#if (!P05_RAM_DIAGNOSTIC && !defined(FLASH_EXTRA_PROTECTION)) || C64U_ESP_TLS_INSTALL
#define C64U_ESP_MANUAL_INSTALL_ENABLED 1
#else
#define C64U_ESP_MANUAL_INSTALL_ENABLED 0
#endif

#define C64U_ESP_FACTORY_APP_ADDRESS UINT32_C(0x10000)
#define C64U_ESP_FACTORY_APP_BYTES UINT32_C(0x300000)
#define C64U_ESP_INSTALL_IDENTITY_REJECTED (-9)

static inline int c64u_esp_app_range_ok(uint32_t address, uint32_t length)
{
    return address == C64U_ESP_FACTORY_APP_ADDRESS && length >= 24 &&
           length <= C64U_ESP_FACTORY_APP_BYTES;
}
static inline int c64u_esp_app_image_ok(const uint8_t *bytes, uint32_t length)
{
    return bytes && c64u_esp_app_range_ok(C64U_ESP_FACTORY_APP_ADDRESS, length) &&
           bytes[0] == 0xe9 && bytes[12] == 9 && bytes[13] == 0;
}

/* Reviewed, source-built stock-1.11-based S3 applications. These raw app hashes
 * exclude the 12-byte SEGM container. Neither is a device/factory backup.
 * Identity 1 is TLS; identity 2 is the matching source-built return application.
 * The legacy 1.21 applications are deliberately absent from this allowlist. */
static inline unsigned c64u_esp_app_approval(const uint8_t digest[32], uint32_t length)
{
    static const uint8_t tls_sha256[32]={
        0x08,0x87,0x1c,0xaa,0x35,0xe3,0x69,0x28,0xd0,0x34,0xca,0xe3,0x77,0xf6,0x7e,0x86,
        0xbf,0x64,0xf4,0x4e,0x7c,0x40,0x90,0xbb,0x16,0xd0,0xea,0x38,0x03,0x37,0xf3,0xd1
    };
    static const uint8_t return_sha256[32]={
        0xf2,0xfc,0xa1,0x16,0xa6,0xb4,0x2b,0x24,0x84,0x91,0xaf,0xa3,0x7b,0xbc,0x95,0xc9,
        0x42,0x74,0xaa,0xcf,0x20,0x44,0x74,0x81,0xb1,0xd7,0x04,0xe3,0xd6,0xa2,0xa3,0x77
    };
    const uint8_t *expected=0;
    unsigned approved=0,difference=0;
    if(length==C64U_ESP_TLS_APP_BYTES){expected=tls_sha256;approved=1;}
    else if(length==C64U_ESP_RETURN_APP_BYTES){expected=return_sha256;approved=2;}
    if(!digest||!expected)return 0;
    for(unsigned i=0;i<32;++i)difference|=digest[i]^expected[i];
    if(!difference)return approved;
    return 0;
}
#endif
