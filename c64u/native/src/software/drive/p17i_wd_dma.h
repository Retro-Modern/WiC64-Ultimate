#ifndef P17I_WD_DMA_H
#define P17I_WD_DMA_H
#include <stddef.h>
#include <stdint.h>
namespace p17i_wd_dma {
enum { SLOT_BYTES=8192, BUFFER_BYTES=6252, DRIVE_COUNT=2, REGION_BYTES=SLOT_BYTES*DRIVE_COUNT };
static_assert(SLOT_BYTES >= BUFFER_BYTES, "DMA slot too small");
uint8_t *buffer_for_irq(int irq);
bool usable(const uint8_t *buffer, size_t bytes);
void mark_hardware_ready();
#if defined(P17I_WD_DMA_HOST_TEST)
void bind_test_region(uint8_t *region, size_t bytes);
#endif
}
#endif
