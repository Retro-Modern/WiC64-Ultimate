#ifndef P21_STORE_PROFILE_H
#define P21_STORE_PROFILE_H
#ifndef C64U_ESP_PERSIST
#define C64U_ESP_PERSIST 0
#endif
#if C64U_ESP_PERSIST != 0 && C64U_ESP_PERSIST != 1
#error C64U_ESP_PERSIST must be 0 or 1
#endif
#if C64U_ESP_PERSIST
#if !C64U_ESP_TLS || !P05_RAM_DIAGNOSTIC || U64 != 2
#error ESP preferences require the qualified C64U RAM and ESP TLS profile
#endif
#if !defined(P21_STORE_HOST_TEST) && (!defined(RISCV) || !C64U_API22_ALPHA || !C64U_CORE49_FENCELESS || !P14_TLS || !P18_TLS)
#error Native ESP preferences require API22 Core49 RV32I and P14/P18 TLS
#endif
#endif
#endif
