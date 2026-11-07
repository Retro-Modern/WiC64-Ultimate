#ifndef C64U_BOOT_TRACE_H
#define C64U_BOOT_TRACE_H
#ifndef C64U_BOOT_TRACE_DISPLAY
#define C64U_BOOT_TRACE_DISPLAY 0
#endif
#if C64U_BOOT_TRACE_DISPLAY != 0 && C64U_BOOT_TRACE_DISPLAY != 1
#error C64U_BOOT_TRACE_DISPLAY must be 0 or 1
#endif
#ifdef __cplusplus
extern "C" {
#endif
void c64u_boot_stage(unsigned stage, unsigned detail);
void c64u_boot_poll(void);
void c64u_boot_ready(void);
/* Normal starts are silent by default. Explicit diagnostic builds may enable
 * stage display; fatal capture remains visible in both modes. */
/* Release the overlay before the normal UI owns the shared matrix. */
void c64u_boot_hide(void);
void c64u_boot_fault(unsigned cause, unsigned pc, unsigned value, unsigned original_sp) __attribute__((noreturn));
void c64u_boot_fail(unsigned reason, unsigned detail) __attribute__((noreturn));
#ifdef __cplusplus
}
#endif
#endif
