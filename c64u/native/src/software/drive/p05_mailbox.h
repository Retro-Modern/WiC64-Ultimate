#ifndef P05_MAILBOX_H
#define P05_MAILBOX_H

/* Experimental P05 wire contract. No arbitrary memory address is accepted. */
#include <stdint.h>
#include "p64_ordering.h"
#include <string.h>

namespace p05 {
enum { DRIVE_ADDRESS = 0x0340, C64_ADDRESS = 0xC800, HALF_SIZE = 32,
       TOTAL_SIZE = 64, SCHEMA = 1, WAIT_ATTACH = 1, WAIT_SAMPLE = 2,
       ACCEPTED = 3, DONE = 4, ATTACH = 1, SAMPLE = 2,
       LOW_READY = 1, HIGH_HOLD = 2, INVALID_DIRECTION = 3 };

struct Snapshot { uint8_t drive[HALF_SIZE]; uint8_t host[HALF_SIZE]; };
struct Measurement { uint8_t pra, ddra, ddrb; uint16_t stop_ms; uint16_t sampled_at_ms; uint32_t sampled_tick; };
enum Result { OK, BUSY, NO_DRIVE, BAD_DRIVE, BAD_MAILBOX, STALE,
              BAD_C64, STOP_TIMEOUT, BAD_PARAMETER, TIMER_FAILURE, LOW_MEMORY };

inline void barrier()
{
#if defined(C64U_CORE49_FENCELESS) && C64U_CORE49_FENCELESS
    p64_ordering::mailbox_barrier();
#elif defined(__riscv)
    __asm__ volatile("fence iorw, iorw" ::: "memory");
#elif defined(__nios2__)
    __asm__ volatile("sync" ::: "memory");
#else
    /* Host tests exercise protocol ordering, not hardware cache coherence. */
    __asm__ volatile("" ::: "memory");
#endif
}

inline uint32_t u32(const uint8_t *p)
{ return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
inline uint16_t u16(const uint8_t *p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
inline void put32(uint8_t *p, uint32_t v)
{ for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8 * i)); }
inline bool nonzero(const uint8_t *p, unsigned n)
{ uint8_t v = 0; for (unsigned i = 0; i < n; ++i) v |= p[i]; return v != 0; }
inline bool committed(const uint8_t *p, unsigned first)
{ return p[first] && !(p[first] & 1) && p[first] == p[31]; }
inline bool valid_drive(const uint8_t *d)
{
    return !memcmp(d, "P5DM", 4) && d[4] == SCHEMA &&
           d[5] >= WAIT_ATTACH && d[5] <= DONE && committed(d, 6);
}
inline uint8_t outcome(uint8_t pra, uint8_t ddra, uint8_t ddrb)
{
    if (!(ddra & 4) || ddrb) return INVALID_DIRECTION;
    return (pra & 4) ? HIGH_HOLD : LOW_READY;
}

/* A bounded seqlock snapshot. The drive may be executing concurrently. */
inline bool snapshot(volatile const uint8_t *memory, Snapshot &out)
{
    for (unsigned attempt = 0; attempt != 3; ++attempt) {
        uint8_t ds = memory[6], hs = memory[32];
        barrier();
        if (!ds || (ds & 1) || (hs & 1)) continue;
        for (unsigned i = 0; i < HALF_SIZE; ++i) out.drive[i] = memory[i];
        for (unsigned i = 0; i < HALF_SIZE; ++i) out.host[i] = memory[32+i];
        barrier();
        if (ds == memory[6] && ds == memory[31] &&
            hs == memory[32] && hs == memory[63] &&
            out.drive[6] == ds && out.drive[31] == ds &&
            out.host[0] == hs && out.host[31] == hs && valid_drive(out.drive)) return true;
    }
    return false;
}

inline bool prepare(const Snapshot &s, bool attach, const uint8_t session[8],
                    uint32_t request, uint8_t command[HALF_SIZE])
{
    const uint8_t *d = s.drive, *h = s.host;
    if (!valid_drive(d) || !nonzero(session, 8)) return false;
    if (attach) {
        if (d[5] != WAIT_ATTACH || nonzero(d+8, 8) || u32(d+16) ||
            u32(d+20) || u16(d+28) || h[0] || request) return false;
    } else {
        if ((d[5] != WAIT_SAMPLE && d[5] != ACCEPTED) || memcmp(d+8, session, 8) ||
            request < 1 || request > 4 || u32(d+16) != request ||
            u32(d+20) != request-1 || u16(d+28) != request-1 ||
            !committed(h, 0) || memcmp(h+4, session, 8)) return false;
        if (request == 1) {
            if (h[1] != ATTACH || u32(h+12)) return false;
        } else if (h[1] != SAMPLE || u32(h+12) != request-1) return false;
    }
    if (h[0] > 250 || (h[0] & 1)) return false; // No wrap in this four-sample test.
    memset(command, 0, HALF_SIZE);
    command[0] = command[31] = uint8_t(h[0] + 2);
    command[1] = attach ? ATTACH : SAMPLE;
    memcpy(command+4, session, 8);
    put32(command+12, request);
    return true;
}

inline bool valid_c64(const uint8_t *c, const uint8_t session[8], uint32_t request,
                      const Measurement &m)
{
    if (memcmp(c, "P5CH", 4) || c[4] != SCHEMA || c[5] != 1 ||
        !committed(c, 6) || memcmp(c+8, session, 8) || u32(c+16) != request ||
        request < 1 || request > 4 || c[7] != (request & 1) ||
        c[23] != 0x37 || (c[24] & 7) != 7 || c[25] != request-1 ||
        c[27] || c[28] || c[29] || c[30]) return false;
    return ((c[20] ^ m.pra) & 4) == 0 && c[21] == m.ddra && c[22] == m.ddrb &&
           ((m.pra >> 2) & 1) == c[7] && (m.ddra & 4) && !m.ddrb;
}

inline bool publish(volatile uint8_t *memory, const Snapshot &before,
                    const uint8_t command[HALF_SIZE])
{
    Snapshot now;
    if (!snapshot(memory, now) || memcmp(&now, &before, sizeof(now))) return false;
    volatile uint8_t *h = memory + HALF_SIZE;
    h[0] = uint8_t(command[0] - 1); // Invalidate before any payload changes.
    barrier();
    for (unsigned i = 1; i < 31; ++i) h[i] = command[i];
    barrier();
    h[31] = command[31];
    barrier();
    h[0] = command[0];
    barrier();
    return true; // Publication only: the drive must acknowledge separately.
}

inline const char *result_name(Result r)
{
    switch (r) {
    case OK: return "OK"; case BUSY: return "BUSY";
    case NO_DRIVE: return "NO_DRIVE"; case BAD_DRIVE: return "BAD_DRIVE";
    case BAD_MAILBOX: return "BAD_MAILBOX"; case STALE: return "STALE";
    case BAD_C64: return "BAD_C64"; case STOP_TIMEOUT: return "STOP_TIMEOUT";
    case BAD_PARAMETER: return "BAD_PARAMETER"; case LOW_MEMORY: return "LOW_MEMORY";
    default: return "TIMER_FAILURE";
    }
}
} // namespace p05
#endif
