#ifndef P21_PREFERENCES_H
#define P21_PREFERENCES_H
#include <stdint.h>
#include "p21_store_profile.h"
namespace p08 {struct BackendContext;}
#pragma pack(push,8)
namespace p21prefs {
enum State {WAITING,EMPTY,READY,SAVING,BLOCKED,UNCERTAIN,UNAVAILABLE};
struct Status {State state;bool loaded,writable,dirty,saved;uint32_t module_generation;uint64_t generation;char error[32];};
void initialize(p08::BackendContext &);
// Sole service worker, always outside Service/C64/Drive locks; no automatic
// empty-default write. Each RPC is bounded and no update is blindly retried.
void step(p08::BackendContext &);
bool get_status(Status &);
const char *state_name(State);
bool wifi_config_ready();
bool configuration_mutable();
void configuration_changed();
bool load_server(char*,uint32_t);
bool save_server(const char*);
uint8_t timezone();bool save_timezone(uint8_t);
#if defined(P21_STORE_HOST_TEST)
namespace testing {void reset();}
#endif
}
#pragma pack(pop)
#endif
