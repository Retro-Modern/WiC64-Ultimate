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
// Gate-only IDENTIFY exchange with one total buffer/reply budget. The ordinary
// WiFi detector keeps its existing API and diagnostics.
bool read_identity(uint16_t *major,uint16_t *minor,char *name,unsigned capacity,
                   uint32_t budget_ms);
// Called only by a direct GUI action, before acquiring the C64 subsystem lock.
// Consumes the one owned resource; every return releases it before dispatch.
SubsysResultCode_e prepare_launch(UserInterface *ui);
// The caller owns the Service ESP-maintenance lease and validated source.
// Borrows source bytes until return; recovery restarts the module on failure.
int flash_application(UserInterface *ui,const uint8_t *bytes,uint32_t length);
// Reader must authenticate each block before returning it to the ROM writer.
typedef bool (*FlashRead)(void *context,uint8_t *dest,uint32_t offset,uint32_t length);
int flash_application_from(UserInterface *ui,FlashRead read,void *read_context,uint32_t length);
}
#endif
