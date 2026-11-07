/* C64U WiC64 WLAN configuration, separate from host flash protection. */
#ifndef C64U_WIFI_PROFILE_H
#define C64U_WIFI_PROFILE_H
#ifndef C64U_ESP_WIFI_CONFIG
#define C64U_ESP_WIFI_CONFIG 0
#endif
#if C64U_ESP_WIFI_CONFIG != 0 && C64U_ESP_WIFI_CONFIG != 1
#error C64U_ESP_WIFI_CONFIG must be 0 or 1
#endif
#if C64U_ESP_WIFI_CONFIG && !defined(P08_HTTP_HOST)
#if !defined(RISCV) || !RISCV || !defined(U64) || U64 != 2 || \
    !defined(C64U_API22_ALPHA) || !C64U_API22_ALPHA || \
    !defined(C64U_CORE49_FENCELESS) || !C64U_CORE49_FENCELESS || \
    !defined(P05_RAM_DIAGNOSTIC) || !P05_RAM_DIAGNOSTIC || \
    !defined(P08_SERVICE) || !P08_SERVICE || \
    !defined(C64U_ESP_PERSIST) || !C64U_ESP_PERSIST || \
    !defined(FLASH_EXTRA_PROTECTION) || \
    defined(NO_ESP)
#error C64U ESP WLAN configuration requires the protected API22 Core49 RAM profile
#endif
#endif
#endif
