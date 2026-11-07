#ifndef P12_COMMANDS_H
#define P12_COMMANDS_H
#include <stdint.h>
namespace p08 {
// $41 provider "U64 " capability namespace, NOT Port64's bit meanings.
// Availability/capacity failures remain explicit runtime command errors.
enum U64Capabilities {
    U64_NATIVE_MENU=1, U64_ADAPTER_BOUND_PER_MAC=2,
    U64_PRIVATE_PROFILE_BACKEND=4, U64_NATIVE_WIFI_CONFIG_BRIDGE=8,
    U64_FIRMWARE_UPDATE_SIMULATION=16, // $27 never installs or flashes firmware
    U64_AUTH_PROFILE_MANAGEMENT_ONLY=32, // storage/status/delete, no TLS bearer send
    U64_VERIFIED_HTTPS=64, U64_HTTPS_BEARER_SEND=128
};
#if P14_TLS
static const uint64_t U64_CAPABILITIES=0xdf; // bits6/7 add TLS and bearer send; bit5 no longer applies
#else
static const uint64_t U64_CAPABILITIES=0x3f;
#endif
struct BackendContext;
struct BackendResult;
void p12_reset_commands(const uint8_t session[8]);
void p12_request_context(const uint8_t session[8],uint32_t request);
void p12_response_consumed(const uint8_t session[8],uint32_t request);
void p12_reset_session(BackendContext &);
bool p12_execute(BackendContext &,uint8_t command,uint8_t protocol,
    const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &);
struct P12CommandStatus { uint32_t simulated_updates; bool reboot_simulation_pending; };
void p12_command_status(P12CommandStatus &);
}
#endif
