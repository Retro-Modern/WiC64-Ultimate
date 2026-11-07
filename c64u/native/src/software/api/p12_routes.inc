#if C64U_ESP_PERSIST
#include "p21_preferences.h"
#endif
// Native WiC64 controls. This interface never returns credentials or SSIDs.
#include "p12_commands.h"
#include "p18_version.h"
#include "p12_wifi.h"
#include "p15_ip.h"
#include "p12_storage.h"
#include "p14_platform.h"
#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
#include "p17f_cache.h"
#endif
namespace {
const char *p12_network_name(unsigned mode) {
    return mode==p08::NETWORK_LAN?"LAN":mode==p08::NETWORK_WLAN?"WLAN":"Auto";
}
// Ultimate JSON numbers are signed 32-bit. Keep unsigned diagnostic counters
// nonnegative and explicitly report the unlikely saturation in their object.
int p17e_json_counter(uint32_t value,bool &clamped) {
    if(value>0x7fffffffU){clamped=true;return 0x7fffffff;}
    return int(value);
}
JSON_Object *p12_json(ResponseWrapper *resp) {
    JSON_Object *out=JSON::Obj();out->add("contract","U64-WIC64-1")->add("schema",1)->add("version",P18_U64_BUILD_ID)
        ->add("compatibility_version",P18_COMPATIBILITY_VERSION)->add("compatibility_reference",P18_COMPATIBILITY_REFERENCE)
        ->add("firmware_version",P18_WIC64_VERSION)->add("port64_version",P18_PORT64_VERSION)
        ->add("release_stage",P18_RELEASE_STAGE)->add("release_candidate",P18_RELEASE_CANDIDATE)
        ->add("display_version",P18_PUBLIC_DISPLAY_VERSION);
    resp->json->add("wic64",out);return out;
}
void p12_mutation_result(ResponseWrapper *resp,p08::Result result) {
    p12_json(resp)->add("queued",result==p08::OK)->add("result",p08::result_name(result));
    int code=result==p08::OK?HTTP_OK:result==p08::BUSY?HTTP_LOCKED:
        result==p08::BAD_PARAMETER?HTTP_BAD_REQUEST:result==p08::NO_DRIVE?HTTP_SERVICE_UNAVAILABLE:HTTP_CONFLICT;
    resp->json_response(code);
}
}
API_DOC(GET,machine,wic64_status,
    TAG("WiC64") SUMMARY("Read native WiC64 status without secrets")
    PATH("/v1/machine:wic64_status","wic64Status","")
    RESPONSE("200","application/json","","U64-WIC64-1 native state; no SSID, password or token values.","")
    RESPONSE_ERROR("423","Service state busy","")
)
API_CALL(GET,machine,wic64_status,NULL,ARRAY({ }))
{
    if(!p08::service){p12_mutation_result(resp,p08::NO_DRIVE);return;}
    p08::Status s={};if(!p08::service->get_status(s)){p12_mutation_result(resp,p08::BUSY);return;}
    p08::BackendSummary network={};p08::service->get_network_summary(network);
    p08::WifiBridgeSnapshot wifi={};p08::p12_wifi_snapshot(wifi);
    p08::P12CommandStatus commands={};p08::p12_command_status(commands);
    p12::Status storage={};p12::get_status(storage);
    unsigned reserved_slots=0;
    for(unsigned i=0;i<p12::PRIVATE_SLOTS;i++)if(storage.slots[i]>=0)reserved_slots++;
    p14::Status secure={};bool secure_supported=p08::service->get_secure_status(secure);
    JSON_Object *out=p12_json(resp);
    out->add("lifecycle",JSON::Obj()->add("state",p08::state_name(s.state))
        ->add("enabled",s.state==p08::ACTIVE||s.state==p08::STARTING)
        ->add("native_session",s.native_session)->add("menu_paused",s.menu_paused)
        ->add("auto_drives",s.auto_drives)->add("drives_prepared",s.drives_prepared)
        ->add("portal_pending",s.portal_pending)->add("portal_launches",int(s.portal_launches))
        ->add("program_pending",s.program_pending)->add("program_launches",int(s.program_launches))
        ->add("secure_setup_imports",int(s.secure_setup_imports))
        ->add("menu_pauses",int(s.menu_pauses))->add("last_error",s.last_error)->add("portal_error",s.portal_error));
    p08::RequestTrace trace={};p08::service->get_request_trace(trace);
    JSON_Object *request_trace=JSON::Obj();out->add("request_trace",request_trace);
    request_trace->add("sequence",int(trace.sequence))->add("request_id",int(trace.request_id))
        ->add("command",int(trace.command))->add("protocol",int(trace.protocol))
        ->add("phase",p08::trace_phase_name(trace.phase))
        ->add("state",p08::trace_lifecycle_name(trace.lifecycle))
        ->add("elapsed_tick_ms",int(trace.elapsed_tick_ms))
        ->add("backend_elapsed_tick_ms",int(trace.backend_elapsed_tick_ms))
        ->add("grant_elapsed_tick_ms",int(trace.grant_elapsed_tick_ms))
        ->add("remote_budget_ms",int(trace.remote_budget_ms))
        ->add("tls_connect_calls",int(trace.tls_connect_calls))
        ->add("tls_call_active",trace.tls_call_active)
        ->add("tls_call_interrupted",trace.tls_call_interrupted)
        ->add("tls_inflight_tick_ms",int(trace.tls_inflight_tick_ms))
        ->add("tls_last_call_tick_ms",int(trace.tls_last_call_tick_ms))
        ->add("tls_max_call_tick_ms",int(trace.tls_max_call_tick_ms))
        ->add("tls_send_calls",int(trace.tls_send_calls))->add("tls_recv_calls",int(trace.tls_recv_calls))
        ->add("tls_sent_bytes",int(trace.tls_sent_bytes))->add("tls_received_bytes",int(trace.tls_received_bytes))
        ->add("tls_io_tick_ms",int(trace.tls_io_tick_ms))->add("tls_io_max_tick_ms",int(trace.tls_io_max_tick_ms))
        ->add("progress",int(trace.progress))->add("progress_total",int(trace.progress_total))
        ->add("status",int(trace.status))->add("error",int(trace.error))
        ->add("http_status",int(trace.http_status))->add("response_length",int(trace.response_length))
        ->add("engine_error",int(trace.engine_error));
    JSON_Object *phases=JSON::Obj();request_trace->add("phase_tick_ms",phases);
    for(unsigned i=0;i<p08::TRACE_PHASE_COUNT;i++)
        phases->add(p08::trace_phase_name(i),int(trace.phase_elapsed_tick_ms[i]));
    // Public algorithm names, public key sizes and elapsed ticks only.
    // This record never exposes keys, hashes, signatures or certificate data.
    bool crypto_clamped=false;
    JSON_Object *crypto=JSON::Obj();request_trace->add("crypto",crypto);
    crypto->add("total_tick_ms",p17e_json_counter(trace.crypto_total_tick_ms,crypto_clamped))
        ->add("call_active",trace.crypto_call_active)
        ->add("call_interrupted",trace.crypto_call_interrupted)
        ->add("active_kind",p08::trace_crypto_kind_name(trace.crypto_active_kind))
        ->add("active_bits",int(trace.crypto_active_bits))
        ->add("inflight_tick_ms",p17e_json_counter(trace.crypto_inflight_tick_ms,crypto_clamped))
        ->add("last_kind",p08::trace_crypto_kind_name(trace.crypto_last_kind))
        ->add("last_bits",int(trace.crypto_last_bits))
        ->add("last_call_tick_ms",p17e_json_counter(trace.crypto_last_call_tick_ms,crypto_clamped))
        ->add("max_kind",p08::trace_crypto_kind_name(trace.crypto_max_kind))
        ->add("max_bits",int(trace.crypto_max_bits))
        ->add("max_call_tick_ms",p17e_json_counter(trace.crypto_max_call_tick_ms,crypto_clamped));
    JSON_Object *crypto_kinds=JSON::Obj();crypto->add("kinds",crypto_kinds);
    for(unsigned kind=1;kind<=5;kind++){
        const p08::CryptoTraceBin &bin=trace.crypto[kind-1];
        crypto_kinds->add(p08::trace_crypto_kind_name(kind),JSON::Obj()
            ->add("calls",p17e_json_counter(bin.calls,crypto_clamped))->add("total_tick_ms",p17e_json_counter(bin.total_tick_ms,crypto_clamped))
            ->add("max_tick_ms",p17e_json_counter(bin.max_tick_ms,crypto_clamped))->add("last_bits",int(bin.last_bits))
            ->add("max_bits",int(bin.max_bits)));
    }
    crypto->add("values_clamped_to_int32",crypto_clamped);
#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
    p17f::CacheStatus math_code={};p17f::get_math_cache_status(math_code);
    out->add("math_code",JSON::Obj()->add("state",p17f::math_cache_state_name(math_code.state))
        ->add("bytes",int(math_code.bytes)));
#endif
    out->add("preferences_error",s.preferences_error);
    out->add("secure_transport",JSON::Obj()->add("supported",secure_supported)
#if defined(C64U_ESP_TLS) && C64U_ESP_TLS
        ->add("provider","ESP TLS (BIO)")
        ->add("readiness_check","PER_REQUEST")
        ->add("native_journal_required",false)
        ->add("seed_status_scope","NATIVE_WOLFSSL_ONLY")
#endif
        ->add("provisioned",secure_supported&&secure.provisioned)
        ->add("entropy_ready",secure_supported&&secure.entropy_ready)
        ->add("storage_blocked",secure_supported&&secure.storage_blocked)
        ->add("time_ready",secure_supported&&secure.time_ready)
        ->add("setup_pending",s.secure_setup_pending)
        ->add("ready",secure_supported&&secure.provisioned&&secure.entropy_ready&&secure.time_ready&&!secure.storage_blocked&&!s.secure_setup_pending)
        ->add("error_code",secure_supported?p14::result_name(secure.last_error):"UNAVAILABLE"));
    p14::Result last_setup=p14::OK;bool setup_attempted=p14::get_last_setup_result(last_setup);
    out->add("last_setup_attempt_result",setup_attempted?p14::result_name(last_setup):"NOT_ATTEMPTED");
    out->add("restore",JSON::Obj()->add("status",p08::restore_name(s.restore))
        ->add("rom_verified",s.rom_verified)->add("metadata_verified",s.metadata_verified)
        ->add("b_metadata_verified",s.b_metadata_verified)->add("settings_verified",s.settings_verified));
    JSON_Object *net=JSON::Obj();out->add("network",net);
    net->add("preference",p12_network_name(network.preference))
        ->add("selected",network.mac_valid?p12_network_name(network.selected):"None")
        ->add("connected",network.connected)->add("mac_valid",network.mac_valid);
    char mac[18]={};
    if(network.mac_valid)snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",
        network.mac[0],network.mac[1],network.mac[2],network.mac[3],network.mac[4],network.mac[5]);
    net->add("mac",mac);
    char ip[16];
    snprintf(ip,sizeof(ip),"%u.%u.%u.%u",unsigned(network.ipv4[0]),unsigned(network.ipv4[1]),
        unsigned(network.ipv4[2]),unsigned(network.ipv4[3]));
    net->add("ip",ip);
    out->add("credentials",JSON::Obj()->add("profile_count",int(network.profile_count))
        ->add("portal_secret_present",network.portal_secret_present)
        ->add("port64_bearer_present",network.port64_bearer_present)->add("custom_bearer_present",network.custom_bearer_present)
        ->add("dirty",network.credentials_dirty)->add("saved",network.credentials_saved));
#if C64U_ESP_PERSIST
    p21prefs::Status preferences={};p21prefs::get_status(preferences);
    out->add("preferences",JSON::Obj()->add("provider","ESP NVS")
        ->add("state",p21prefs::state_name(preferences.state))->add("loaded",preferences.loaded)
        ->add("writable",preferences.writable)->add("dirty",preferences.dirty)->add("saved",preferences.saved)
        ->add("module_generation",int(preferences.module_generation))->add("last_error",preferences.error));
#endif
    out->add("storage",JSON::Obj()->add("state",p12::state_name(storage.state))
        ->add("initialized",storage.initialized)->add("writable",storage.writable)
        ->add("dirty",storage.dirty)->add("persisted",storage.persisted)->add("recovered",storage.recovered)
        ->add("generation",int(storage.generation))->add("capacity",int(storage.capacity))
        ->add("config_slots",int(storage.config_slots))->add("reserved_slots",int(reserved_slots))
        ->add("required_slots",int(p12::PRIVATE_SLOTS))
        ->add("last_error",p12::result_name(storage.last_error)));
    out->add("wifi",JSON::Obj()->add("available",wifi.available)->add("state",int(wifi.state))
        ->add("configured_known",wifi.configured_known)->add("configured",wifi.configured)->add("job_pending",wifi.job_pending)
        ->add("rssi_available",wifi.rssi_known)->add("rssi_source",wifi.rssi_source==1?"SCAN_MATCHED_SSID":"UNAVAILABLE")
        ->add("rssi_age_ms",int(wifi.rssi_age_ms))->add("forget_state",int(wifi.forget_state)));
    if(wifi.rssi_known)out->add("wifi_rssi_dbm",int(wifi.rssi));
    p08::P15IpStatus ip_job={};p08::p15_ip_status(ip_job);
    out->add("ip_configuration",JSON::Obj()->add("job_state",int(ip_job.state))
        ->add("request_id",int(ip_job.request))->add("persisted",ip_job.persisted)->add("applied",ip_job.applied));
    out->add("firmware_update",JSON::Obj()->add("simulated",commands.simulated_updates!=0)
        ->add("count",int(commands.simulated_updates))->add("flash_written",false));
    resp->json_response(HTTP_OK);
}
API_DOC(POST,machine,wic64_start,
    TAG("WiC64") SUMMARY("Enable native WiC64 with an internal session")
    PATH("/v1/machine:wic64_start","wic64Start","")
    RESPONSE("200","application/json","","Queued; poll status for ACTIVE.","")
)
API_CALL(POST,machine,wic64_start,NULL,ARRAY({ }))
{p12_mutation_result(resp,p08::service?p08::service->request_native_start():p08::NO_DRIVE);}
API_DOC(POST,machine,wic64_stop,
    TAG("WiC64") SUMMARY("Disable WiC64 and restore managed drive settings")
    PATH("/v1/machine:wic64_stop","wic64Stop","")
    RESPONSE("200","application/json","","Queued; poll restore flags before using Drive A.","")
)
API_CALL(POST,machine,wic64_stop,NULL,ARRAY({ }))
{p12_mutation_result(resp,p08::service?p08::service->request_native_stop():p08::NO_DRIVE);}
API_DOC(POST,machine,wic64_portal,
    TAG("WiC64") SUMMARY("Launch the original WiC64 portal starter")
    DESCRIPTION("Queues an intentional C64 restart and the original embedded portal starter. Existing C64 work is replaced.")
    PATH("/v1/machine:wic64_portal","wic64Portal","")
    RESPONSE("200","application/json","","Queued; poll portal status.","")
)
API_CALL(POST,machine,wic64_portal,NULL,ARRAY({ }))
{p12_mutation_result(resp,p08::service?p08::service->request_portal():p08::NO_DRIVE);}
API_DOC(POST,machine,wic64_network,
    TAG("WiC64") SUMMARY("Select the WiC64 network adapter")
    PATH("/v1/machine:wic64_network","wic64Network","")
    PARAM("mode","string","auto, lan, or wlan","","auto")
    RESPONSE("200","application/json","","Queued; changing adapters selects that adapter's own credentials.","")
)
API_CALL(POST,machine,wic64_network,NULL,ARRAY({ {"mode",P_REQUIRED} }))
{
    const char *mode=args["mode"];
    unsigned n=mode&&!strcmp(mode,"auto")?0:mode&&!strcmp(mode,"lan")?1:mode&&!strcmp(mode,"wlan")?2:255;
    p12_mutation_result(resp,n>2?p08::BAD_PARAMETER:p08::service?p08::service->request_network_preference(n):p08::NO_DRIVE);
}

#if defined(P18_LOG) && P18_LOG
#include "p18_log_routes.inc"
#endif
