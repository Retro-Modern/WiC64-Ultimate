#ifndef U64_MACHINE_H
#define U64_MACHINE_H

#include "c64.h"
#if U64 && P08_SERVICE
#include "p08_mailbox.h"
#endif
#if U64 && P05_MAILBOX_DIAGNOSTIC
#include "p05_mailbox.h"
#endif


class U64Machine : public C64
{
    U64Machine() { }
    ~U64Machine() { }

    bool before_memory_access(bool memOnly, bool *stopped_it);
    void after_memory_access(uint8_t *, bool, bool stopped_it);

    void get_all_memory(uint8_t *pb);
public:
    void clear_ram();
#if U64 && P08_SERVICE
    bool p08_start_eligible();
    bool p08_environment_safe();
    p08::Result p08_measure_publish(volatile uint8_t *drive_memory,
        const p08::Snapshot &before, const uint8_t session[8], uint32_t request,
        const uint8_t *payload, uint16_t length, uint32_t total, uint8_t status, uint8_t flags,
        uint32_t generation, p08::Measurement &measurement);
#endif
#if U64 && P05_MAILBOX_DIAGNOSTIC
    p05::Result p05_measure(const uint8_t session[8], uint32_t request, p05::Measurement &measurement);
#endif
    uint8_t get_cpu_port(void);
    uint8_t peek(uint16_t address);
    uint8_t peek_cpu(uint16_t address, uint8_t cpu_port);
    uint8_t peek_visible(uint16_t address);
    void poke(uint16_t address, uint8_t byte);
    void poke_cpu(uint16_t address, uint8_t byte, uint8_t cpu_port);
    void poke_visible(uint16_t address, uint8_t byte);
    void read_block(uint16_t address, uint8_t *dst, uint32_t len);
    void read_cpu_block(uint16_t address, uint8_t *dst, uint32_t len, uint8_t cpu_port);
    void read_visible_block(uint16_t address, uint8_t *dst, uint32_t len);
    friend class C64;
};

#endif
