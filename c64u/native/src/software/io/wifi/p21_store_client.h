#ifndef P21_STORE_CLIENT_H
#define P21_STORE_CLIENT_H
#include <stdint.h>
#include "p21_store_profile.h"
#include "p21_store_wire.h"
namespace p21_store {
enum Result {OK,EMPTY,UNSUPPORTED,UNAVAILABLE,MALFORMED,BLOCKED,CONFLICT,TIMEOUT,UNCERTAIN,CHANGED,CANCELLED,NO_MEMORY,IO_ERROR};
struct Ops {
 int (*exchange)(uint8_t*,uint16_t,uint16_t,uint16_t*,uint32_t);
 uint32_t (*milliseconds)();void (*pause)();uint32_t (*generation)();
};
class Client {
 const Ops &ops;
public:
 explicit Client(const Ops &value):ops(value){}
 int probe(uint32_t budget_ms);
 Result load(uint8_t*,uint16_t capacity,uint16_t &length,uint64_t &generation,uint32_t budget_ms=15000);
 Result save(const uint8_t*,uint16_t length,uint64_t expected_generation,uint64_t &new_generation,uint32_t budget_ms=15000);
};
const Ops &native_ops();
// Read-only bounded CAPS: 0 compatible, -2 explicit stock NOT_SUPPORTED,
// -1 absent/timeout/lifecycle change, -3 malformed/incompatible response.
int probe(uint32_t budget_ms);
const char *result_name(Result);
}
int p21_store_rpc_exchange(uint8_t*,uint16_t,uint16_t,uint16_t*,uint32_t);
#endif
