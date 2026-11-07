#ifndef P08_HTTP_H
#define P08_HTTP_H
#include <stdint.h>
#include "p14_state.h"
#include "p17_trace.h"

#pragma pack(push, 8)
namespace p08 {
enum { MAX_URL = 8192, MAX_RESPONSE = 65536, MAX_REQUEST = 8192,
       LEGACY_PRG_MINUS2 = 1 };
// The separate native nonsecret page stores two bounded string records.
// Keep its format independent of the private credential/TLS journal.
enum { PUBLIC_SERVER_MAX = 480, PUBLIC_SERVER_PART = 240 };
bool p15_load_public_server(char *,uint32_t capacity);
bool p15_save_public_server(const char *);
enum NetworkMode { NETWORK_AUTO=0, NETWORK_LAN=1, NETWORK_WLAN=2 };
struct NetworkInfo {
    bool connected;
    bool mac_valid;
    uint8_t mac[6];
    char ip[16];
    bool wireless;
    void *adapter_handle; // transient native interface identity, never serialized
};
struct PortalCredentials {
    char token_key[65];
    char token[257];
    char token_keys[4][65];
    char token_values[4][257];
    uint8_t token_replacement;
};
struct AdapterProfile {
    bool used;
    uint8_t mac[6];
    PortalCredentials portal;
    char port64_bearer[65];
    char custom_bearer[65];
    char custom_origin[97];
};
struct BackendSummary {
    uint8_t preference, selected, mac[6], ipv4[4], profile_count;
    bool connected, mac_valid, portal_secret_present;
    bool port64_bearer_present, custom_bearer_present;
    bool credentials_dirty, credentials_saved;
};
struct BackendNetworkHooks {
    bool (*adapter_at)(void *, unsigned, NetworkInfo &);
    bool (*bind_socket)(void *, const NetworkInfo &, int);
};
struct BackendContext : PortalCredentials {
    RequestTrace trace;
    char server[MAX_URL+1];
    char post_url[MAX_URL+1];
    char post_url_template[MAX_URL+1]; // re-expand under the POST transaction adapter
    char last_status[40];
    uint32_t next_remote_timeout_ms, current_remote_timeout_ms;
    uint8_t next_transfer_timeout;
    volatile bool cancel_requested;
    bool (*should_cancel)(void *);
    void *cancel_context;
    NetworkInfo network;
    AdapterProfile profiles[2];
    p14::SecureState secure; // private TLS bootstrap/ratchet state; never public metadata
    uint8_t preference, selected_profile;
    bool transaction_active, credentials_dirty, credentials_saved;
    BackendSummary summary_cache;
    BackendNetworkHooks network_hooks;
    void *network_context;
    bool (*persist_credentials)(void *, const uint8_t *, uint16_t);
    void *persist_context;
};
struct BackendResult {
    uint8_t status;
    uint8_t error;
    uint8_t flags;
    bool http_performed;
    uint32_t length;
    uint16_t http_status;
};
enum HttpError { HTTP_NONE=0, HTTP_URL, HTTP_SOCKET, HTTP_CONNECT, HTTP_WRITE,
    HTTP_READ, HTTP_DEADLINE, HTTP_HEADERS, HTTP_LENGTH, HTTP_UNSUPPORTED,
    HTTP_REMOTE_STATUS, HTTP_DNS, HTTP_REDIRECT_LIMIT, HTTP_ARGUMENT, HTTP_CANCELLED,
    HTTP_TLS_UNSEEDED, HTTP_TLS_TIME, HTTP_TLS_CERTIFICATE, HTTP_TLS_HANDSHAKE,
    HTTP_TLS_RECORD, HTTP_TLS_DOWNGRADE };
// Cold initialization erases RAM credentials; a service/session reset must use
// reset_backend_session instead. It preserves the profile store and callbacks.
void reset_backend(BackendContext &context);
void reset_backend_session(BackendContext &context);
void p12_reset_session(BackendContext &context);
bool p12_execute(BackendContext &, uint8_t, uint8_t, const uint8_t *, uint32_t,
                 uint8_t *, uint32_t, BackendResult &);
void set_network_hooks(BackendContext &, const BackendNetworkHooks &, void *);
bool set_network_preference(BackendContext &, uint8_t mode);
void backend_summary(const BackendContext &, BackendSummary &);
AdapterProfile *active_profile(BackendContext &);
const AdapterProfile *active_profile(const BackendContext &);
bool credentials_changed(BackendContext &);
uint16_t serialize_credentials(const BackendContext &, uint8_t *, uint16_t capacity);
bool deserialize_credentials(BackendContext &, const uint8_t *, uint16_t length);
bool bind_selected_socket(BackendContext &, int socket);
bool bind_selected_socket_port(BackendContext &, int socket, uint16_t local_port);
bool resolve_backend_ipv4(BackendContext &, const char *, uint8_t out[4], uint32_t timeout_ms);
void refresh_network_info(BackendContext &context);
bool apply_security_header(BackendContext &context, bool is_key, const char *value);
bool portal_response_authorized(const char *url);
bool adapt_legacy_prefanswer(uint8_t protocol, const char *url, uint16_t code,
    uint8_t *body, uint32_t &length);
// HTTP GET01 and GET_ENCODED0f share bounded URL expansion and HTTP handling.
// Encoded requests use <$ + LE16 byte count + binary, converted to lowercase
// hexadecimal before ASCII-space removal and %mac/%ser expansion.
BackendResult execute_backend(BackendContext &context, uint8_t command, uint8_t protocol,
    const uint8_t *request, uint32_t length, uint8_t *response, uint32_t capacity);
// Bounded measurement transport. The body is discarded in 512-byte chunks;
// elapsed_ms measures the download phase, setup_ms DNS/TCP/TLS/headers.
// No redirects, Authorization or response credential updates are performed.
struct SpeedtestResult {
    uint32_t received_bytes, elapsed_ms, setup_ms, content_length;
    uint16_t http_status;
    uint8_t flags;
};
BackendResult http_speedtest(BackendContext &, const uint8_t *url, uint32_t url_length,
    uint8_t seconds, uint32_t target_bytes, SpeedtestResult &);
// Exposed separately for real host-socket regression tests. HTTPS requires a
// nonnull bound session with provisioned private entropy and a verified clock.
BackendResult http_request(const uint8_t *url, uint32_t url_length,
    const uint8_t *post, uint32_t post_length, bool is_post,
    uint8_t *body, uint32_t capacity=MAX_RESPONSE, uint32_t timeout_ms=5000,
    const volatile bool *cancel=0, bool (*should_cancel)(void *)=0,
    void *cancel_context=0, BackendContext *session=0, uint8_t protocol='R',
    const uint8_t *original_request=0, uint32_t original_request_length=0);
}
#pragma pack(pop)
#endif
