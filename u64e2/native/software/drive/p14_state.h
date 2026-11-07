#ifndef P14_STATE_H
#define P14_STATE_H
#include <stdint.h>

// Native lwIP headers can leave a four-byte packing scope active. These
// private types have one ABI regardless of the caller's include order.
#pragma pack(push, 8)
namespace p14 {
// This is PRIVATE persistence state, not a ConfigItem or a public status.
// bootstrap_id identifies the ORIGINAL setup seed, not the ratcheted seed.
struct SecureState {
    bool provisioned;
    uint8_t seed[32];
    uint8_t bootstrap_id[16];
    uint64_t epoch;
};
}
#pragma pack(pop)
#endif
