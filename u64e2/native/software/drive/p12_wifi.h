#ifndef P12_WIFI_H
#define P12_WIFI_H
#include <stdint.h>
namespace p08 {
struct WifiAP { uint8_t ssid[32], length, auth; int8_t rssi; };
struct WifiNativeSnapshot {
    bool available, linked, ip_ready;
    uint32_t association_generation;
    uint8_t ssid[32], ssid_length;
    char ip[16];
};
struct WifiNativeOps {
    void *context;
    uint32_t (*milliseconds)(void *);
    void (*delay)(void *,uint32_t);
    bool (*snapshot)(void *,WifiNativeSnapshot &);
    bool (*scan)(void *,uint16_t);
    bool (*connect)(void *,uint16_t,const uint8_t *,uint8_t,const uint8_t *,uint8_t,uint8_t);
    // 0=pending, 1=success, -1=failure. Scan copies at most ten records.
    int (*poll)(void *,uint16_t,WifiAP *,uint8_t &);
    void (*cancel)(void *);
    // Optional native CLEAR_APS RPC; deletes WiFi AP credentials only.
    bool (*forget)(void *,uint16_t);
};
struct WifiBridgeSnapshot {
    bool available, configured_known, configured, passphrase_length_known;
    uint8_t state, reason, passphrase_length, ssid_length;
    uint8_t ssid[32];
    char ip[16];
    bool job_pending, connection_intent;
    // source1 is a fresh scan sample matched to a unique visible SSID.
    // It is not an ESP station/current-BSSID RSSI query.
    bool rssi_known; int8_t rssi; uint8_t rssi_source; uint32_t rssi_age_ms;
    uint8_t forget_state; // 0=none,1=pending,2=confirmed,3=failed/unknown
};
// Host models supply an explicit adapter. Production installs its native RPC
// adapter lazily and runs the same bounded state machine in its own task.
void p12_wifi_set_ops(const WifiNativeOps &);
void p12_wifi_reset(const uint8_t session[8]);
void p12_wifi_tick();
uint8_t p12_wifi_scan(WifiAP out[10],uint8_t &count,uint32_t timeout_ms,
                     bool (*cancel)(void *),void *cancel_context);
uint8_t p12_wifi_stage(const uint8_t session[8],uint32_t request,
    const uint8_t *ssid,uint8_t ssid_length,const uint8_t *password,uint8_t password_length,
    int scan_index=-1);
uint8_t p15_wifi_rssi(int8_t &dbm,uint32_t timeout_ms,
    bool (*cancel)(void *),void *cancel_context);
uint8_t p15_wifi_stage_forget(const uint8_t session[8],uint32_t request);
void p12_wifi_response_consumed(const uint8_t session[8],uint32_t request);
void p12_wifi_request_context(const uint8_t session[8],uint32_t request);
void p12_wifi_snapshot(WifiBridgeSnapshot &);
uint8_t p12_wifi_wait_connected(uint8_t seconds,bool (*cancel)(void *),void *context);
const char *p12_wifi_last_error();
// Called before the legacy native RPC routing. Only reserved thread $FE is
// consumed; stale private replies are freed, never delivered to another task.
bool p12_wifi_rpc_receive_isr(void *context,void *buffer,void *wake);
void p12_wifi_note_connected();
void p12_wifi_note_disconnected();
// Native menu Forget APs uses the ordinary controller RPC. Keep the private
// bridge's nonsecret metadata and queued actions consistent with that action.
void p15_wifi_note_forget_started();
void p15_wifi_note_forget_finished(bool confirmed);
}
#endif
