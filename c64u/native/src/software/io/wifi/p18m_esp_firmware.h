/* Optional, explicitly confirmed bundled ESP application. GPL-3.0-or-later. */
#ifndef P18M_ESP_FIRMWARE_H
#define P18M_ESP_FIRMWARE_H
#include <stdint.h>
#include "return_codes.h"
class UserInterface;
namespace p18m_esp {
// WiFi lifecycle hooks invalidate observations across a module restart. The
// launch gate always reads a fresh, bounded IDENTIFY and CAPS under a lease.
void note_reset();
void note_identified(uint16_t major,uint16_t minor,const char *name);
// Read-only aligned Core49 lifecycle snapshot; no RPC or state mutation.
uint32_t module_generation();
// Gate-only IDENTIFY exchange with one total buffer/reply budget. The ordinary
// WiFi detector keeps its existing API and diagnostics.
bool read_identity(uint16_t *major,uint16_t *minor,char *name,unsigned capacity,
                   uint32_t budget_ms);
// Called only by a direct GUI action, before acquiring the C64 subsystem lock.
// The optional bundle offers installation, never installs without consent.
// Paints progress before the bounded IDENTIFY (250 ms) and CAPS (100 ms)
// exchanges. Hashing, GUI consent and ROM flashing are separate phases.
// Consumes the one owned resource; every return releases it before dispatch.
SubsysResultCode_e prepare_launch(UserInterface *ui);
// The caller owns the Service ESP-maintenance lease and validated source.
// Borrows source bytes until return; recovery restarts the module on failure.
int flash_application(UserInterface *ui,const uint8_t *bytes,uint32_t length);
// Standalone return profile only. Explicit GUI consent, known live1.11 and
// maintenance are mandatory; a silent/unknown ESP is never overwritten.
SubsysResultCode_e restore_stock_application(UserInterface *ui);
}
#endif
