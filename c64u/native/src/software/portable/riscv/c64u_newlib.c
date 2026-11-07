/* Single-process newlib signal hooks for the API22 RAM application.
 * Newlib abort() falls through to the existing Stock _exit() trap loop.
 * No scheduler, IRQ, MMIO, flash, or process signal is emulated here. */
#if defined(C64U_API22_ALPHA) && C64U_API22_ALPHA
#include <errno.h>
int _getpid(void) { return 0; }
int _kill(int pid, int sig) {
    (void)sig;
    errno = pid > 0 ? ESRCH : ENOSYS;
    return -1;
}
#endif
