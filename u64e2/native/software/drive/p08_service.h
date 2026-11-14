#ifndef P08_SERVICE_H
#define P08_SERVICE_H
#if U64 && P08_SERVICE
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "p08_mailbox.h"
#include "p08_http.h"
class ConfigItem;
class C1541;
namespace p14 {struct Status;}
#pragma pack(push, 8)
namespace p08 {
enum State {SERVICE_IDLE,STARTING,ACTIVE,STOPPING,RESTORED,ERROR};
enum Restore {NOT_NEEDED,PENDING,RESTORE_OK,NEEDS_ATTENTION};
struct Status {
 State state;Restore restore;uint8_t session[8];char helper_sha256[65],last_error[80];
 uint32_t requests,responses,pa2_samples,http_requests,http_success,http_errors;
 uint32_t request_bytes,response_bytes,rx_chunks,tx_chunks,tx_refills,last_tx_offset,tx_consumed_bytes;
 uint32_t response_cache_length,request_cache_length,peak_response_bytes;
 uint16_t http_last_status,last_stop_ms;
 bool rom_verified,metadata_verified,settings_verified,probe_armed;
 bool native_session,menu_paused,portal_pending,program_pending;
 bool secure_setup_pending;
 bool auto_drives,drives_prepared,b_metadata_verified;
 uint32_t portal_launches,program_launches,menu_pauses;
 uint32_t secure_setup_imports;
 uint32_t endpoint_resets,helper_guard_mask,helper_previous_sequence,helper_previous_request,helper_previous_drive_request,helper_work_request;
 char portal_error[48],preferences_error[48];
 Snapshot mailbox;
};
class Service {
#ifdef P08_SERVICE_HOST_TEST
 friend struct ServiceHostTest;
#endif
 SemaphoreHandle_t mutex;TaskHandle_t task;Status status;BackendContext backend;
 uint8_t backup[32768],request_data[MAX_RX],response_data[MAX_TX];
 char original_rom[256],original_config_rom[256];
 uint8_t original_power,original_reset,original_hw,original_rammap,original_hw_type,original_config_rom_id;
 int original_type,original_iec_address,original_config_power,original_config_address,original_config_type;
 ConfigItem *b_power_item,*b_address_item;
 uint8_t b_original_power,b_original_reset,b_original_hw;
 int b_original_iec_address,b_original_config_power,b_original_config_address,b_original_config_reset,b_original_config_freeze;
 ConfigItem *parallel_item,*turbo_item,*serial_item,*burst_item,*speed_item,*badlines_item,*supercpu_item;
 int original_parallel,original_turbo,original_serial,original_burst,original_speed,original_badlines,original_supercpu;
 uint8_t original_connectors,original_turbo_regs,original_speed_prefer;
 bool backup_valid,b_backup_valid,global_valid,rom_done,prepared,bad_snapshot,response_started,endpoint_reset_pending;
 volatile bool menu_hold,external_reset,portal_reset_owner;
 bool portal_restart,portal_loading,backend_working,backend_inflight;
 // Retro-Modern: a C64 reset restarts a native session like a real WiC64
 // stays usable across resets (stop/restore, then a fresh session).
 bool reset_restart;
 uint8_t *program_data;uint32_t program_size;
 uint8_t program_mode,program_drive;char program_name[64];
 bool program_prepared,program_loading;
 uint8_t secure_setup_data[64];
 uint8_t pending_network_preference;
 uint32_t native_sequence,consumed_hook_request,tcp_read_ticket_current;
 uint32_t work_request,last_request,last_drive_request,sample_generation,last_d_sequence;
 uint32_t request_received,request_total,response_length,published_next,consumed_current;
 uint8_t work_command,work_protocol,response_status,response_flags;
 TickType_t start_tick,bad_snapshot_tick,last_network_refresh;
 static void run(void *argument);static bool backend_should_cancel(void *argument);bool try_lock();void unlock();
 void step();void start_step();void stop_step();void active_step();void receive_window(const Snapshot &);void refill_window(const Snapshot &);
 Result queue_start_locked(const uint8_t session[8],bool native,bool portal);
 Result queue_native_locked(bool portal);
 Result request_program_impl(const uint8_t *,uint32_t,const char *,uint8_t,uint8_t,bool);
 void portal_step();void program_step();void discard_program();void network_preference_step();void network_refresh_step();void load_preferences();
 void secure_setup_step();void discard_secure_setup();
 void discard_exchange_buffers();
 void fault(const char *);bool drive_snapshot(Snapshot &);bool global_capture_apply();bool global_restore();bool drive_b_pending(C1541 *);bool restore_b();Result check_globals();
public:
#if defined(P18_TLS) && P18_TLS
 // Reserve a quiescent worker during an explicitly confirmed ESP update.
 // No instance layout change; all admission and release use its mutex.
 static bool begin_esp_maintenance();
 static void end_esp_maintenance();
#endif
 Service();Result request_start(const uint8_t session[8]);Result request_stop(const uint8_t session[8]);bool get_status(Status &);
 Result request_native_start(bool open_portal=false);
 Result request_native_stop();Result request_portal();
 // Copies the complete PRG. A successful queue never borrows caller memory.
 Result request_native_program(const uint8_t *,uint32_t,const char *,uint8_t,uint8_t);
 // Local validated Control Center: start if idle, then queue owned PRG bytes.
 Result request_control_center(const uint8_t *,uint32_t);
 // Copies a complete private setup file; only the worker may import/persist it.
 Result request_secure_setup(const uint8_t *,uint32_t);
 Result request_network_preference(uint8_t mode);
 void get_network_summary(BackendSummary &out) const;
 void get_request_trace(RequestTrace &out) const;
 bool get_secure_status(p14::Status &) const;
 static void notify_menu(bool held);
 static void notify_c64_reset();
 static void portal_reset_scope(bool owned);
 static bool reset_is_pending();
 static bool menu_is_held();
 bool portal_prepare_resume();
};
extern Service *service;
// Lock-free admission snapshot for callers already holding Drive/C64 locks.
// A stays reserved from queued Start until a fully verified final restore.
bool native_drive_a_reserved() noexcept;
bool native_menu_held();
bool native_c64_reset_pending();
const char *state_name(State);const char *restore_name(Restore);
}
#pragma pack(pop)
#endif
#endif
