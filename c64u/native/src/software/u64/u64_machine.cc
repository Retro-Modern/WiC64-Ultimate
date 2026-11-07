#include "u64.h"
#include "u64_machine.h"
#include "FreeRTOS.h"
#if U64 && P05_MAILBOX_DIAGNOSTIC
#include "task.h"
#endif
#include <string.h>

namespace {

static uint8_t read_frozen_byte(volatile uint8_t *ram, bool freezerMenu, uint32_t address,
                                uint32_t *screen_backup, uint32_t *ram_backup)
{
    if (freezerMenu) {
        if ((address >= 1024) && (address < 2048)) {
            return ((uint8_t *)screen_backup)[address - 1024];
        }
        if ((address >= 2048) && (address < 4096)) {
            return ((uint8_t *)ram_backup)[address - 2048];
        }
    }
    return ram[address];
}

static void write_frozen_byte(volatile uint8_t *ram, bool freezerMenu, uint32_t address, uint8_t value,
                              uint32_t *screen_backup, uint32_t *ram_backup)
{
    if (freezerMenu) {
        if ((address >= 1024) && (address < 2048)) {
            ((uint8_t *)screen_backup)[address - 1024] = value;
            return;
        } else if ((address >= 2048) && (address < 4096)) {
            ((uint8_t *)ram_backup)[address - 2048] = value;
            return;
        }
    }
    ram[address] = value;
}

static void override_cpu_port(volatile uint8_t *ram, bool freezerMenu, uint8_t cpu_port,
                              uint8_t *saved_ddr, uint8_t *saved_port,
                              uint32_t *screen_backup, uint32_t *ram_backup)
{
    *saved_ddr = read_frozen_byte(ram, freezerMenu, 0x0000, screen_backup, ram_backup);
    *saved_port = read_frozen_byte(ram, freezerMenu, 0x0001, screen_backup, ram_backup);
    write_frozen_byte(ram, freezerMenu, 0x0000, (uint8_t)((*saved_ddr & 0xF8) | 0x07), screen_backup, ram_backup);
    write_frozen_byte(ram, freezerMenu, 0x0001, (uint8_t)((*saved_port & 0xF8) | (cpu_port & 0x07)), screen_backup, ram_backup);
    ram[0x0001];
    ram[0x0001];
}

static void restore_cpu_port(volatile uint8_t *ram, bool freezerMenu, uint8_t saved_ddr,
                             uint8_t saved_port, uint32_t *screen_backup, uint32_t *ram_backup)
{
    write_frozen_byte(ram, freezerMenu, 0x0000, saved_ddr, screen_backup, ram_backup);
    write_frozen_byte(ram, freezerMenu, 0x0001, saved_port, screen_backup, ram_backup);
    ram[0x0001];
    ram[0x0001];
}

static uint8_t read_visible_byte(volatile uint8_t *ram, bool freezerMenu, uint32_t address,
                                 uint32_t *screen_backup, uint32_t *ram_backup)
{
    uint8_t saved_memonly = C64_DMA_MEMONLY;

    C64_DMA_MEMONLY = 0;
    uint8_t value = read_frozen_byte(ram, freezerMenu, address, screen_backup, ram_backup);
    C64_DMA_MEMONLY = saved_memonly;
    return value;
}

static void write_visible_byte(volatile uint8_t *ram, bool freezerMenu, uint32_t address, uint8_t value,
                               uint32_t *screen_backup, uint32_t *ram_backup)
{
    uint8_t saved_memonly = C64_DMA_MEMONLY;

    C64_DMA_MEMONLY = 0;
    write_frozen_byte(ram, freezerMenu, address, value, screen_backup, ram_backup);
    C64_DMA_MEMONLY = saved_memonly;
}

static uint8_t read_cpu_mapped_byte(volatile uint8_t *ram, bool freezerMenu, uint32_t address, uint8_t cpu_port,
                                    uint32_t *screen_backup, uint32_t *ram_backup, uint32_t *color_backup)
{
    uint8_t raw = read_frozen_byte(ram, freezerMenu, address, screen_backup, ram_backup);

    if (address == 0x0000) {
        return (uint8_t)((raw & 0xF8) | 0x07);
    }
    if (address == 0x0001) {
        return (uint8_t)((raw & 0xF8) | (cpu_port & 0x07));
    }
    if (address >= 0xA000 && address <= 0xBFFF) {
        if ((cpu_port & 0x03) == 0x03) {
            return ((volatile uint8_t *)U64_BASIC_BASE)[address - 0xA000];
        }
        return raw;
    }
    if (address >= 0xD000 && address <= 0xDFFF) {
        if ((cpu_port & 0x03) == 0x00) {
            return raw;
        }
        if (cpu_port & 0x04) {
            // While frozen the colour RAM holds the menu's colours; the C64's are in the backup.
            if (freezerMenu && address >= 0xD800 && address < 0xDC00) {
                return ((uint8_t *)color_backup)[address - 0xD800];
            }
            return read_visible_byte(ram, freezerMenu, address, screen_backup, ram_backup);
        }
        return ((volatile uint8_t *)U64_CHARROM_BASE)[address - 0xD000];
    }
    if (address >= 0xE000) {
        if (cpu_port & 0x02) {
            return ((volatile uint8_t *)U64_KERNAL_BASE)[address - 0xE000];
        }
        return raw;
    }
    return raw;
}

static void write_cpu_mapped_byte(volatile uint8_t *ram, bool freezerMenu, uint32_t address, uint8_t value, uint8_t cpu_port,
                                  uint32_t *screen_backup, uint32_t *ram_backup, uint32_t *color_backup)
{
    if (address >= 0xD000 && address <= 0xDFFF && (cpu_port & 0x03) != 0x00 && (cpu_port & 0x04)) {
        if (freezerMenu && address >= 0xD800 && address < 0xDC00) {
            ((uint8_t *)color_backup)[address - 0xD800] = value;
            return;
        }
        write_visible_byte(ram, freezerMenu, address, value, screen_backup, ram_backup);
        return;
    }
    write_frozen_byte(ram, freezerMenu, address, value, screen_backup, ram_backup);
}

static void copy_raw_block(volatile uint8_t *ram, bool freezerMenu, uint32_t address, uint8_t *dst, uint32_t len,
                           uint32_t *screen_backup, uint32_t *ram_backup)
{
    memcpy(dst, (const void *)(ram + address), len);

    if (freezerMenu) {
        uint32_t overlap;
        if ((address < 2048) && ((address + len) > 1024)) {
            uint32_t start = (address > 1024) ? address : 1024;
            overlap = address + len - start;
            if (overlap > 1024) {
                overlap = 1024;
            }
            memcpy(dst + (start - address), ((uint8_t *)screen_backup) + (start - 1024), overlap);
        }
        if ((address < 4096) && ((address + len) > 2048)) {
            uint32_t start = (address > 2048) ? address : 2048;
            overlap = address + len - start;
            if (overlap > 2048) {
                overlap = 2048;
            }
            memcpy(dst + (start - address), ((uint8_t *)ram_backup) + (start - 2048), overlap);
        }
    }
}

}

bool U64Machine :: before_memory_access(bool memOnly, bool *stopped_it) {
    bool freezerMenu = isFrozen;
    bool wasStopped = is_stopped();

    if (stopped_it) {
        *stopped_it = (!freezerMenu && !wasStopped);
    }
    if (!freezerMenu && !wasStopped) {
        stop(false);
    }
    portENTER_CRITICAL();
    C64_DMA_MEMONLY = memOnly ? 1 : 0;
    return freezerMenu;
}

void U64Machine :: after_memory_access(uint8_t *pb, bool freezerMenu, bool stopped_it) {
    C64_DMA_MEMONLY = 0;
    portEXIT_CRITICAL();
    if (!freezerMenu && stopped_it) {
        resume();
    } else if (pb && freezerMenu) {
        // if we were in freezer menu, the backup of the 1K-4K RAM should be used to restore memory
        memcpy(pb + 1024, screen_backup, 1024);
        memcpy(pb + 2048, ram_backup, 2048);
    }
}

void U64Machine :: get_all_memory(uint8_t *pb)
{
    bool freezerMenu = isFrozen;

    if (!freezerMenu) {
        stop(false);
    }
    portENTER_CRITICAL();
    C64_DMA_MEMONLY = 1;
    memcpy(pb, (uint8_t *)C64_MEMORY_BASE, 65536);
    C64_DMA_MEMONLY = 0;
    portEXIT_CRITICAL();

    if (!freezerMenu) {
        resume();
    } else { // if we were in freezer menu, the backup of the 1K-4K RAM should be used
        // restore memory
        memcpy(pb + 1024, screen_backup, 1024);
        memcpy(pb + 2048, ram_backup, 2048);
    }
}

void U64Machine :: read_block(uint16_t address, uint8_t *dst, uint32_t len)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(isFrozen, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;

    copy_raw_block(ram, freezerMenu, address, dst, len, screen_backup, ram_backup);

    after_memory_access(0, freezerMenu, stopped_it);
}

void U64Machine :: read_cpu_block(uint16_t address, uint8_t *dst, uint32_t len, uint8_t cpu_port)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(true, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;
    uint8_t saved_serve = C64_SERVE_CONTROL;

    C64_SERVE_CONTROL = saved_serve | SERVE_WHILE_STOPPED;
    for (uint32_t offset = 0; offset < len; offset++) {
        dst[offset] = read_cpu_mapped_byte(ram, freezerMenu, (uint16_t)(address + offset), cpu_port, screen_backup, ram_backup, color_backup);
    }
    C64_SERVE_CONTROL = saved_serve;
    after_memory_access(0, freezerMenu, stopped_it);
}

void U64Machine :: read_visible_block(uint16_t address, uint8_t *dst, uint32_t len)
{
    bool freezerMenu = isFrozen;
    bool wasStopped = is_stopped();
    uint8_t saved_memonly = C64_DMA_MEMONLY;
    if (!freezerMenu && !wasStopped) {
        stop(false);
    }
    portENTER_CRITICAL();
    C64_DMA_MEMONLY = 0;
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;
    uint8_t saved_serve = C64_SERVE_CONTROL;

    C64_SERVE_CONTROL = saved_serve | SERVE_WHILE_STOPPED;

    for (uint32_t offset = 0; offset < len; offset++) {
        uint32_t current = address + offset;
        uint8_t byte = ram[current];

        if (freezerMenu) {
            byte = read_frozen_byte(ram, true, current, screen_backup, ram_backup);
        }
        dst[offset] = byte;
    }

    C64_SERVE_CONTROL = saved_serve;
    C64_DMA_MEMONLY = saved_memonly;
    portEXIT_CRITICAL();

    if (!freezerMenu && !wasStopped) {
        resume();
    }
}

uint8_t U64Machine :: get_cpu_port(void)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(isFrozen, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;
    uint8_t ddr = read_frozen_byte(ram, freezerMenu, 0x0000, screen_backup, ram_backup) & 0x07;
    uint8_t port = read_frozen_byte(ram, freezerMenu, 0x0001, screen_backup, ram_backup) & 0x07;

    after_memory_access(0, freezerMenu, stopped_it);
    return (uint8_t)(((port & ddr) | ((uint8_t)(~ddr) & 0x07)) & 0x07);
}

uint8_t U64Machine :: peek(uint16_t address)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(isFrozen, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;
    uint8_t byte = read_frozen_byte(ram, freezerMenu, address, screen_backup, ram_backup);

    after_memory_access(0, freezerMenu, stopped_it);
    return byte;
}

uint8_t U64Machine :: peek_cpu(uint16_t address, uint8_t cpu_port)
{
    uint8_t byte = 0;
    read_cpu_block(address, &byte, 1, cpu_port);
    return byte;
}

uint8_t U64Machine :: peek_visible(uint16_t address)
{
    bool freezerMenu = isFrozen;
    bool wasStopped = is_stopped();
    uint8_t saved_memonly = C64_DMA_MEMONLY;
    if (!freezerMenu && !wasStopped) {
        stop(false);
    }
    portENTER_CRITICAL();
    C64_DMA_MEMONLY = 0;
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;
    uint8_t saved_serve = C64_SERVE_CONTROL;

    C64_SERVE_CONTROL = saved_serve | SERVE_WHILE_STOPPED;

    uint8_t byte = ram[address];

    if (freezerMenu) {
        byte = read_frozen_byte(ram, true, address, screen_backup, ram_backup);
    }

    C64_SERVE_CONTROL = saved_serve;
    C64_DMA_MEMONLY = saved_memonly;
    portEXIT_CRITICAL();

    if (!freezerMenu && !wasStopped) {
        resume();
    }
    return byte;
}

void U64Machine :: poke(uint16_t address, uint8_t byte)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(isFrozen, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;

    write_frozen_byte(ram, freezerMenu, address, byte, screen_backup, ram_backup);

    after_memory_access(0, freezerMenu, stopped_it);
}

void U64Machine :: poke_cpu(uint16_t address, uint8_t byte, uint8_t cpu_port)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(true, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;
    uint8_t saved_serve = C64_SERVE_CONTROL;

    C64_SERVE_CONTROL = saved_serve | SERVE_WHILE_STOPPED;
    write_cpu_mapped_byte(ram, freezerMenu, address, byte, cpu_port, screen_backup, ram_backup, color_backup);
    C64_SERVE_CONTROL = saved_serve;
    after_memory_access(0, freezerMenu, stopped_it);
}

void U64Machine :: poke_visible(uint16_t address, uint8_t byte)
{
    bool stopped_it = false;
    bool freezerMenu = before_memory_access(false, &stopped_it);
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;

    write_frozen_byte(ram, freezerMenu, address, byte, screen_backup, ram_backup);

    // Flush read, as dma_transfer_frozen documents: a write does not stall on
    // the bus, so without this it can still be on its way out when
    // after_memory_access puts the mode back, and is then lost.
    (void)ram[address];

    after_memory_access(0, freezerMenu, stopped_it);
}

void U64Machine :: clear_ram()
{
#ifndef RECOVERYAPP
    // Clear RAM from $0000 to $FFFF
    extern const uint8_t _raminit_bin_start[65536];
    volatile uint8_t *ram = (volatile uint8_t *)C64_MEMORY_BASE;

    bool freezerMenu = isFrozen;
    if (!freezerMenu) {
        stop(false);
    }
    portENTER_CRITICAL();
    C64_DMA_MEMONLY = 1;
    memcpy((uint8_t*)ram, _raminit_bin_start, 65536);
    C64_DMA_MEMONLY = 0;
    portEXIT_CRITICAL();
    if (!freezerMenu) {
        resume();
    } else { // if we were in freezer menu, the backup of the 1K-4K RAM should be used
        // restore memory
        memcpy(screen_backup, _raminit_bin_start + 1024, 1024);
        memcpy(ram_backup, _raminit_bin_start + 2048, 2048);
    }
#endif
}

#if U64 && P05_MAILBOX_DIAGNOSTIC
/* Unlike getMsTimer(), even a broken/noncoherent timer has bounded retries. */
static bool p05_read_ms(uint16_t &value)
{
    for (unsigned n = 0; n < 4; ++n) {
        uint8_t high = ioRead8(ITU_MS_TIMER_HI);
        uint8_t low = ioRead8(ITU_MS_TIMER_LO);
        if (high == ioRead8(ITU_MS_TIMER_HI)) {
            value = (uint16_t(high) << 8) | low;
            return true;
        }
    }
    return false;
}

p05::Result U64Machine::p05_measure(const uint8_t session[8], uint32_t request,
                                   p05::Measurement &measurement)
{
    uint8_t header[32];
    uint16_t started = 0, now = 0;
    p05::Result result = p05::BAD_C64;

    // The caller holds the C64 subsystem mutex. The menu's ownership path does
    // not share that mutex, so exclude scheduling for this bounded one-shot.
    // No allocation, printf, JSON, RTOS wait, FORCE stop or external call here.
    portENTER_CRITICAL();
    if (!available || isFrozen || (C64_STOP & (C64_DO_STOP | C64_HAS_STOPPED)) ||
        C64_MODE != MODE_NORMAL || c64_reset_detect()) {
        portEXIT_CRITICAL();
        return result;
    }
    if (!p05_read_ms(started)) {
        portEXIT_CRITICAL();
        return p05::TIMER_FAILURE;
    }
    const uint8_t saved_stop_mode = C64_STOP_MODE;
    C64_STOP_MODE = STOP_COND_RWSEQ;
    C64_STOP = C64_DO_STOP;
    bool stopped = false;
    bool timer_ok = true;
    // 3 ms timer budget plus an independent finite loop cap. A failing bus can
    // still stall a CPU load; this is not a general hard realtime guarantee.
    for (unsigned tries = 0; tries < 65536; ++tries) {
        if ((C64_STOP & C64_HAS_STOPPED) != 0) { stopped = true; break; }
        if (!p05_read_ms(now)) { timer_ok = false; break; }
        if (uint16_t(now - started) >= 3) break;
    }
    if (!stopped) {
        C64_STOP = 0; // Cancel only the request we placed above.
        C64_STOP_MODE = saved_stop_mode;
        portEXIT_CRITICAL();
        return timer_ok ? p05::STOP_TIMEOUT : p05::TIMER_FAILURE;
    }

    // Preserve the invariants expected by the existing non-raster resume().
    stop_mode = 2;
    raster = raster_hi = vic_irq_en = vic_irq = 0;
    const uint8_t saved_memonly = C64_DMA_MEMONLY;
    const uint8_t saved_serve = C64_SERVE_CONTROL;
    C64_SERVE_CONTROL = saved_serve | SERVE_WHILE_STOPPED;
    volatile uint8_t *ram = reinterpret_cast<volatile uint8_t *>(C64_MEMORY_BASE);
    C64_DMA_MEMONLY = 1;
    p05::barrier();
    for (unsigned n = 0; n < 32; ++n) header[n] = ram[p05::C64_ADDRESS+n];
    p05::Measurement declared = {header[20], header[21], header[22], 0, 0, 0};
    bool header_ok = p05::valid_c64(header, session, request, declared);
    if (header_ok) {
        C64_DMA_MEMONLY = 0;
        p05::barrier();
        // These reads deliberately do not touch PRB ($DD01) or ICR ($DD0D).
        measurement.pra = ram[0xDD00];
        measurement.ddra = ram[0xDD02];
        measurement.ddrb = ram[0xDD03];
        p05::barrier();
    }
    C64_DMA_MEMONLY = saved_memonly;
    C64_SERVE_CONTROL = saved_serve;
    timer_ok = p05_read_ms(now);
    measurement.stop_ms = uint16_t(now - started);
    measurement.sampled_at_ms = now;
    measurement.sampled_tick = uint32_t(xTaskGetTickCount());
    bool normal = !isFrozen && C64_MODE == MODE_NORMAL && !c64_reset_detect();
    if (header_ok && normal && timer_ok && p05::valid_c64(header, session, request, measurement)) result = p05::OK;
    else if (!timer_ok) result = p05::TIMER_FAILURE;

    if (normal) resume();
    else C64_STOP = 0; // An external reset must not be cleared by resume().
    C64_STOP_MODE = saved_stop_mode;
    portEXIT_CRITICAL();
    return result;
}
#endif

#if U64 && P08_SERVICE
#include "p08_machine.inc"
#endif
