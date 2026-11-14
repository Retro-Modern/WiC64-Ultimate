#if U64 && P08_SERVICE
#include "p08_service.h"
#include "p08_dispatch.h"
#include "p08_http.h"
#include "p08_embedded_helper.h"
#include "p12_embedded_portal.h"
#include "p12_commands.h"
#include "p12_tcp.h"
#include "p12_storage.h"
#if defined(P18_TLS) && P18_TLS && defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
#include "p18m_esp_resource.h"
#endif
#if P14_TLS
#include "p14_platform.h"
#include "p14_tls.h"
#endif
#include <stdlib.h>
#include "c1541.h"
#include "u64_machine.h"
#include "c64_subsys.h"
#include "u64_config.h"
#include "u64.h"
#include "config.h"
#include "itu.h"
#include "init_function.h"
#include <string.h>

namespace p08 {
Service *service=0;
// RV32IM has no atomic RMW extension. An aligned word plus load/store atomics
// publishes admission without taking the Service mutex under Drive/C64 locks.
alignas(4) static uint32_t native_drive_a_reservation=0;
bool native_drive_a_reserved() noexcept
{ return __atomic_load_n(&native_drive_a_reservation,__ATOMIC_ACQUIRE)!=0; }
#if defined(P18_TLS) && P18_TLS
// Protected by the sole native Service's existing mutex. Do not retain that
// mutex across UART/flash waits: admission and worker scheduling consult this.
static bool esp_maintenance=false;
#endif
static void copy_text(char *out,unsigned capacity,const char *text)
{ if(!capacity)return;unsigned n=0;while(text && text[n] && n+1<capacity){out[n]=text[n];n++;}out[n]=0; }
static void clear_private(void *memory,unsigned length)
{ volatile uint8_t *p=static_cast<volatile uint8_t *>(memory);while(length--)*p++=0; }
const char *state_name(State s) {static const char *v[]={"IDLE","STARTING","ACTIVE","STOPPING","RESTORED","ERROR"};return v[unsigned(s)<=ERROR?unsigned(s):unsigned(ERROR)];}
const char *restore_name(Restore s) {static const char *v[]={"NOT_NEEDED","PENDING","RESTORED","NEEDS_ATTENTION"};return v[unsigned(s)<=NEEDS_ATTENTION?unsigned(s):unsigned(NEEDS_ATTENTION)];}
Service::Service():mutex(xSemaphoreCreateMutex()),task(0),b_power_item(0),b_address_item(0),parallel_item(0),turbo_item(0),serial_item(0),burst_item(0),speed_item(0),badlines_item(0),supercpu_item(0),
 backup_valid(false),b_backup_valid(false),global_valid(false),rom_done(false),prepared(false),bad_snapshot(false),response_started(false),endpoint_reset_pending(false),
 menu_hold(false),external_reset(false),portal_reset_owner(false),portal_restart(false),reset_restart(false),portal_loading(false),backend_working(false),backend_inflight(false),program_data(0),program_size(0),program_mode(0),program_drive(0),program_prepared(false),program_loading(false),pending_network_preference(0xff),native_sequence(0),consumed_hook_request(0),tcp_read_ticket_current(0),
 work_request(0),last_request(0),last_drive_request(0),sample_generation(0),last_d_sequence(0),request_received(0),request_total(0),response_length(0),published_next(0),consumed_current(0),
 work_command(0),work_protocol(0),response_status(0),response_flags(0)
{
#if defined(P08_SERVICE_HOST_TEST)
 // Each host fixture constructs the sole Service of a fresh simulated boot.
 // Production initialization is the static zero above, never a later release.
 __atomic_store_n(&native_drive_a_reservation,0,__ATOMIC_RELEASE);
#endif
 memset(&status,0,sizeof(status));status.state=SERVICE_IDLE;status.restore=NOT_NEEDED;reset_backend(backend);
#if defined(P18_LOG) && P18_LOG
 // Public boot discrimination only; not secret material or a random source.
 // Production service construction is native, never a host hardware access.
 uint32_t log_boot=uint32_t(xTaskGetTickCount());
#if !defined(P08_SERVICE_HOST_TEST)
 log_boot^=*reinterpret_cast<volatile uint32_t*>(RTC_TIMER_BASE);
 log_boot^=uint32_t(ioRead8(ITU_MS_TIMER_HI))<<24;
 log_boot^=uint32_t(ioRead8(ITU_MS_TIMER_LO))<<16;
#endif
 p18log::initialize(log_boot);
#endif
 discard_exchange_buffers();
 copy_text(status.helper_sha256,sizeof(status.helper_sha256),P08_HELPER_SHA256);
 memset(secure_setup_data,0,sizeof(secure_setup_data));load_preferences();
#if P14_TLS
 // Latch recovery BEFORE any adapter/header save can clear the storage flag.
 // Startup reserves/reads only; it must not advance or emit RNG state.
 p12::Status storage={};bool have_storage=p12::get_status(storage);
 p14::initialize(backend,have_storage&&storage.recovered,have_storage&&storage.writable&&backend.persist_credentials);
 const unsigned service_stack_words=8192;
#else
 const unsigned service_stack_words=4096;
#endif
 refresh_network_info(backend);last_network_refresh=xTaskGetTickCount();
 if(!mutex || xTaskCreate(run,"WiC64 P08",service_stack_words,this,PRIO_POLL,&task)!=pdPASS){status.state=ERROR;copy_text(status.last_error,sizeof(status.last_error),"TASK_START_FAILED");}
}
void Service::load_preferences()
{
    // Init110 runs after native config stores register. Reserve/read only;
    // constructor does not save, and holds no service/C64/Drive mutex.
    p12::Result initialized=p12::initialize();
    backend.persist_credentials=p12::persist_callback;backend.persist_context=0;
    if(initialized!=p12::OK&&initialized!=p12::EMPTY){
        copy_text(status.preferences_error,sizeof(status.preferences_error),p12::result_name(initialized));
    }
    // Even a nonwritable inactive bank can leave an older valid bank readable.
    // Storage::load independently rejects unsafe geometry/ownership, so always
    // let it recover that bounded bank before treating the store as empty.
    uint8_t *blob=static_cast<uint8_t*>(malloc(p12::MAX_BLOB));
    if(!blob){copy_text(status.preferences_error,sizeof(status.preferences_error),"CREDENTIAL_LOAD_MEMORY");return;}
    uint16_t length=0;p12::Result loaded=p12::load(blob,p12::MAX_BLOB,length);
    if(loaded==p12::OK){
        if(!deserialize_credentials(backend,blob,length)){
            // Storage framing may be valid but a future credential schema is
            // unknown. Never overwrite that blob with an empty/current one.
            backend.persist_credentials=0;
            copy_text(status.preferences_error,sizeof(status.preferences_error),"CREDENTIAL_SCHEMA_UNSUPPORTED");
        }
    }else if(loaded!=p12::EMPTY)copy_text(status.preferences_error,sizeof(status.preferences_error),p12::result_name(loaded));
    memset(blob,0,p12::MAX_BLOB);free(blob);
}
bool Service::try_lock(){return mutex && xSemaphoreTake(mutex,0)==pdTRUE;}
void Service::unlock(){xSemaphoreGive(mutex);}
#if defined(P18_TLS) && P18_TLS
bool Service::begin_esp_maintenance()
{
    Service *self=service;
    if(!self||!self->try_lock())return false;
    bool idle=(self->status.state==SERVICE_IDLE||
        (self->status.state==RESTORED&&self->status.restore==RESTORE_OK));
    bool safe=!esp_maintenance&&self->task&&idle&&!self->backend_working&&!self->backend_inflight&&
        !self->backup_valid&&!self->b_backup_valid&&!self->global_valid&&!self->program_data&&
        !self->portal_restart&&!self->portal_loading&&!self->program_loading&&self->pending_network_preference>2&&
        !self->status.portal_pending&&!self->status.program_pending&&!self->status.secure_setup_pending;
    if(safe)esp_maintenance=true;
    self->unlock();return safe;
}
void Service::end_esp_maintenance()
{
    Service *self=service;if(!self||!self->mutex)return;
    xSemaphoreTake(self->mutex,portMAX_DELAY);esp_maintenance=false;self->unlock();
}
#endif
void Service::discard_exchange_buffers()
{
    // An unlocked backend owns these arrays until it returns. Cancellation
    // queues a state change; only that worker can erase its live buffers.
    if(backend_inflight)return;
    clear_private(request_data,sizeof(request_data));clear_private(response_data,sizeof(response_data));
    status.request_cache_length=status.response_cache_length=0;
}
bool Service::get_status(Status &out){if(!try_lock())return false;out=status;out.menu_paused=menu_hold;unlock();return true;}
void Service::get_network_summary(BackendSummary &out)const
{
 backend_summary(backend,out);
}
void Service::get_request_trace(RequestTrace &out)const
{
 trace_snapshot(backend.trace,out);
}
bool Service::get_secure_status(p14::Status &out)const
{
#if P14_TLS
    p14::get_status(backend,out);return true;
#else
    (void)out;return false;
#endif
}
Result Service::queue_start_locked(const uint8_t session[8],bool native,bool portal)
{
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance)return BUSY;
#endif
    if(backend_working||backend_inflight||status.secure_setup_pending)return BUSY;
    if(!task || (status.state!=SERVICE_IDLE && status.state!=RESTORED) || backup_valid || b_backup_valid || global_valid || program_data ||
       !nonzero(session,8) || !memcmp(session,status.session,8))return BAD_STATE;
#if defined(P18_TLS) && P18_TLS && defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
    // Headless/API starts never prompt or flash. Release the optional raw
    // resource before native work can use the reclaimed TLS/service heap.
    p18m_esp_resource_discard();
#endif
    uint32_t launches=status.portal_launches,programs=status.program_launches,pauses=status.menu_pauses,setups=status.secure_setup_imports;char preferences_error[48];
    memcpy(preferences_error,status.preferences_error,sizeof(preferences_error));
    // Reserve before exposing STARTING: the worker may not have claimed A yet.
    __atomic_store_n(&native_drive_a_reservation,1,__ATOMIC_RELEASE);
    memset(&status,0,sizeof(status));memcpy(status.preferences_error,preferences_error,sizeof(preferences_error));status.state=STARTING;status.restore=PENDING;
    status.native_session=native;status.auto_drives=native;status.portal_pending=portal;status.menu_paused=menu_hold;
    status.portal_launches=launches;status.program_launches=programs;status.menu_pauses=pauses;status.secure_setup_imports=setups;
    trace_service_state(backend.trace,work_request,TRACE_ABANDONED);
    memcpy(status.session,session,8);copy_text(status.helper_sha256,sizeof(status.helper_sha256),P08_HELPER_SHA256);
    work_request=last_request=last_drive_request=sample_generation=last_d_sequence=0;
    discard_exchange_buffers();
    request_received=request_total=response_length=published_next=consumed_current=consumed_hook_request=0;tcp_read_ticket_current=0;
    prepared=response_started=endpoint_reset_pending=false;rom_done=false;portal_restart=false;external_reset=false;
    reset_backend_session(backend);p12_reset_commands(session);
    backend.should_cancel=backend_should_cancel;backend.cancel_context=this;
    start_tick=xTaskGetTickCount();last_network_refresh=start_tick-configTICK_RATE_HZ;bad_snapshot=false;return OK;
}
Result Service::queue_native_locked(bool portal)
{
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance)return BUSY;
#endif
    if(native_sequence==0xffffffffu)return LIMIT_REACHED;
    uint8_t nonce[8]={'W','N',0,0,0,0,0,0};put32(nonce+2,++native_sequence);
    uint32_t ticks=xTaskGetTickCount();nonce[6]=uint8_t(ticks);nonce[7]=uint8_t(ticks>>8);
    return queue_start_locked(nonce,true,portal);
}
Result Service::request_start(const uint8_t session[8])
{
    if(!nonzero(session,8))return BAD_PARAMETER;
    if(!try_lock())return BUSY;
    Result result=queue_start_locked(session,false,false);unlock();return result;
}
Result Service::request_native_start(bool portal)
{
    if(!try_lock())return BUSY;
    Result result=queue_native_locked(portal);unlock();return result;
}
Result Service::request_stop(const uint8_t session[8])
{
    if(!try_lock())return BUSY;
    Result result=BAD_STATE;
    if(nonzero(session,8) && !memcmp(session,status.session,8) &&
       (status.state==STARTING || status.state==ACTIVE || status.state==ERROR ||
        (status.state==RESTORED&&status.restore==RESTORE_OK&&portal_restart))) {
        backend.cancel_requested=true;discard_secure_setup();status.state=STOPPING;status.restore=PENDING;
        discard_exchange_buffers();
        status.portal_pending=status.program_pending=false;status.drives_prepared=false;portal_restart=false;reset_restart=false;prepared=response_started=endpoint_reset_pending=false;result=OK;
    }
    unlock();return result;
}
Result Service::request_native_stop()
{
    if(!try_lock())return BUSY;
    Result result=BAD_STATE;
    // A queued portal restart can wait in RESTORED while the menu, backend or
    // sequence limit prevents admission. Stop must also cancel that gap, then
    // let the normal verified restore worker release its reservation.
    if(status.state==STARTING||status.state==ACTIVE||status.state==ERROR||
       (status.state==RESTORED&&status.restore==RESTORE_OK&&portal_restart)){
        backend.cancel_requested=true;discard_secure_setup();status.state=STOPPING;status.restore=PENDING;
        discard_exchange_buffers();
        status.portal_pending=status.program_pending=false;status.drives_prepared=false;portal_restart=false;reset_restart=false;prepared=response_started=false;result=OK;
    }
    unlock();return result;
}
Result Service::request_portal()
{
    if(!try_lock())return BUSY;
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance){unlock();return BUSY;}
#endif
    if(status.secure_setup_pending||backend_working){unlock();return BUSY;}
    Result result=BAD_STATE;
    if(status.state==SERVICE_IDLE||status.state==RESTORED)result=queue_native_locked(true);
    else if(status.state==ACTIVE||status.state==STARTING){
        // A portal launch resets C64. Restore the old claim and then install
        // a fresh session/helper; no old request or cached grant survives it.
        backend.cancel_requested=true;status.state=STOPPING;status.restore=PENDING;
        discard_exchange_buffers();
        status.portal_pending=true;status.program_pending=false;status.drives_prepared=false;portal_restart=true;reset_restart=false;prepared=response_started=false;result=OK;
    }
    unlock();return result;
}
Result Service::request_network_preference(uint8_t mode)
{
    if(mode>2)return BAD_PARAMETER;
    if(!try_lock())return BUSY;
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance){unlock();return BUSY;}
#endif
    // A menu toggle must not overwrite an accepted switch or change the
    // adapter of an in-flight request. The worker applies one queued choice.
    if(backend_working||backend_inflight||pending_network_preference<=2){unlock();return BUSY;}
    pending_network_preference=mode;unlock();return OK;
}
Result Service::request_secure_setup(const uint8_t *data,uint32_t length)
{
#if P14_TLS
    if(!data||length!=p14::SETUP_BYTES)return BAD_PARAMETER;
    if(!try_lock())return BUSY;
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance){unlock();return BUSY;}
#endif
    if(status.state==STOPPING||status.state==ERROR){unlock();return BAD_STATE;}
    if(status.secure_setup_pending||backend_working||program_data||status.portal_pending||portal_loading){unlock();return BUSY;}
    memcpy(secure_setup_data,data,p14::SETUP_BYTES);status.secure_setup_pending=true;
    // If an old HTTPS operation is in flight, the same worker must first
    // unwind it and destroy its TLS objects before replacing its RNG source.
    backend.cancel_requested=true;unlock();return OK;
#else
    (void)data;(void)length;return BAD_STATE;
#endif
}
void Service::discard_secure_setup()
{
    clear_private(secure_setup_data,sizeof(secure_setup_data));status.secure_setup_pending=false;
}
void Service::secure_setup_step()
{
#if P14_TLS
    if(!status.secure_setup_pending||backend_inflight)return;
    uint8_t setup[p14::SETUP_BYTES];memcpy(setup,secure_setup_data,sizeof(setup));
    clear_private(secure_setup_data,sizeof(secure_setup_data));
    backend_working=true;unlock();
    // $40 can retain a TLS lease while no backend call is in flight. Close
    // that idle socket before replacing/invalidating the process RNG source.
    // No credentials, setup journal, adapter preference or drive state reset.
    p12_tcp_reset();
    p14::Result result=p14::import_setup(backend,setup,sizeof(setup));
    clear_private(setup,sizeof(setup));
    if(result==p14::OK&&!p14::tls_forget_entropy()){
        p14::block_entropy(p14::CRYPTO_ERROR);result=p14::CRYPTO_ERROR;
    }
    xSemaphoreTake(mutex,portMAX_DELAY);backend_working=false;
    status.secure_setup_pending=false;
    if(result==p14::OK&&status.secure_setup_imports!=0xffffffffu)status.secure_setup_imports++;
    // Stop/portal/program cancellation may have arrived while flash was
    // committing. Never clear that newer cancellation or release its helper.
    if(status.state!=STOPPING&&status.state!=ERROR&&!status.portal_pending&&!status.program_pending)
        backend.cancel_requested=false;
#endif
}
Result Service::request_native_program(const uint8_t *data,uint32_t size,const char *name,uint8_t mode,uint8_t drive)
{
    return request_program_impl(data,size,name,mode,drive,false);
}
Result Service::request_control_center(const uint8_t *data,uint32_t size)
{
    return request_program_impl(data,size,"WiC64 Control Center",3,8,true);
}
Result Service::request_program_impl(const uint8_t *data,uint32_t size,const char *name,uint8_t mode,uint8_t drive,bool auto_start)
{
    // The direct DMA modes have an optional two-byte jump address followed by
    // the normal PRG load address. Reject overflow before copying/queueing.
    unsigned header=mode==5?4:2;
    if(!data||(mode!=1&&mode!=3&&mode!=5)||size<=header||size>65538u||
       size-header>65536u-u16(data+header-2))return BAD_PARAMETER;
    if(!try_lock())return BUSY;
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance){unlock();return BUSY;}
#endif
    bool start=auto_start&&(status.state==SERVICE_IDLE||status.state==RESTORED);
    if(!start&&(!status.native_session||(status.state!=ACTIVE&&status.state!=STARTING)||external_reset)){unlock();return BAD_STATE;}
    if(program_data||status.portal_pending||portal_loading||status.secure_setup_pending||backend_working){unlock();return BUSY;}
    uint8_t *copy=static_cast<uint8_t *>(malloc(size));
    if(!copy){unlock();return LIMIT_REACHED;}
    memcpy(copy,data,size);
    // Allocate and own every source byte before reserving A or starting the
    // service. Failed validation/allocation/admission leaves drives untouched.
    if(start){
        Result result=queue_native_locked(false);
        if(result!=OK){memset(copy,0,size);free(copy);unlock();return result;}
    }
    program_data=copy;program_size=size;program_mode=mode;program_drive=drive;
    copy_text(program_name,sizeof(program_name),name);program_prepared=false;
    status.program_pending=true;backend.cancel_requested=true;
    // The worker may currently be inside execute_backend outside this mutex.
    // Its buffers/context are left intact until that same worker returns.
    unlock();return OK;
}
void Service::discard_program()
{
    if(program_loading)return; // native DMA still owns these source bytes
    if(program_data){memset(program_data,0,program_size);free(program_data);}
    program_data=0;program_size=0;program_prepared=false;status.program_pending=false;
}
void Service::program_step()
{
    if(!program_data||backend_inflight||menu_hold)return;
    if(!program_prepared){
        U64Machine *machine=static_cast<U64Machine *>(C64::getMachine());
        if(!machine||!c64_subsys){fault("PROGRAM_C64_NOT_AVAILABLE");return;}
        if(!c64_subsys->p08_try_lock())return;
        bool eligible=machine->p08_start_eligible();c64_subsys->unlock();
        if(!eligible){fault("PROGRAM_EXTERNAL_CARTRIDGE");return;}
        Result globals=check_globals();if(globals==BUSY)return;
        if(globals!=OK){fault("FOREIGN_GLOBAL_CHANGE_NOT_OVERWRITTEN");return;}
        if(native_sequence==0xffffffffu){fault("PROGRAM_SESSION_LIMIT");return;}
        if(!c1541_A||!c1541_A->p08_try_lock())return;
        C1541 *a=c1541_A;
        if(!a->p08_owned){a->unlock();fault("PROGRAM_HELPER_NOT_OWNED");return;}
        a->registers[C1541_RESET]=7;barrier();a->registers[C1541_POWER]=0;
        uint8_t nonce[8]={'W','N',0,0,0,0,0,0};put32(nonce+2,++native_sequence);
        uint32_t ticks=xTaskGetTickCount();nonce[6]=uint8_t(ticks);nonce[7]=uint8_t(ticks>>8);
        trace_service_state(backend.trace,work_request,TRACE_ABANDONED);
        memcpy(status.session,nonce,8);
        for(unsigned i=0;i<8;i++){
            a->memory_map[0x8000+P08_HELPER_SESSION_OFFSET+i]=nonce[i];
            a->memory_map[0xc000+P08_HELPER_SESSION_OFFSET+i]=nonce[i];
        }
        for(unsigned i=0;i<128;i++)a->memory_map[D_ADDRESS+i]=0;
        barrier();a->unlock();
        work_request=last_request=last_drive_request=sample_generation=last_d_sequence=0;
        discard_exchange_buffers();
        request_received=request_total=response_length=published_next=consumed_current=consumed_hook_request=0;tcp_read_ticket_current=0;
        prepared=response_started=bad_snapshot=endpoint_reset_pending=false;status.probe_armed=false;
        status.response_cache_length=status.request_cache_length=0;memset(&status.mailbox,0,sizeof(status.mailbox));
        program_prepared=true;
        // The single worker has now drained the old request. Session reset
        // closes sockets/cancels deferred WiFi outside C64/Drive/service locks.
        backend_working=true;unlock();reset_backend_session(backend);p12_reset_commands(nonce);
        backend.should_cancel=backend_should_cancel;backend.cancel_context=this;
        xSemaphoreTake(mutex,portMAX_DELAY);backend_working=false;
        if(status.state!=ACTIVE||!status.program_pending)return;
        if(external_reset){fault("C64_RESET_NOTIFIED");return;}
        last_network_refresh=xTaskGetTickCount()-configTICK_RATE_HZ;
    }
    uint8_t nonce[8];memcpy(nonce,status.session,8);program_loading=true;
    unlock();int result=c64_subsys->p13a_launch_program(program_data,program_size,program_name,program_mode,program_drive);
    xSemaphoreTake(mutex,portMAX_DELAY);program_loading=false;
    if(status.state!=ACTIVE||!status.program_pending||memcmp(nonce,status.session,8)){discard_program();return;}
    if(external_reset){fault("C64_RESET_NOTIFIED");return;}
    if(result==-2)return; // no mutation; keep the same fresh helper/job for retry
    if(result==0){status.program_launches++;discard_program();}
    else fault("PROGRAM_LOAD_FAILED");
}
void Service::network_preference_step()
{
    if(pending_network_preference>2)return;
    const uint8_t mode=pending_network_preference;pending_network_preference=0xff;
    backend_working=true;unlock();bool ok=set_network_preference(backend,mode);xSemaphoreTake(mutex,portMAX_DELAY);backend_working=false;
    last_network_refresh=xTaskGetTickCount()-configTICK_RATE_HZ;
    if(!ok)copy_text(status.last_error,sizeof(status.last_error),"NETWORK_PREFERENCE_BUSY");
}
bool Service::menu_is_held(){return service&&service->menu_hold;}
bool Service::reset_is_pending(){return service&&service->external_reset;}
bool native_c64_reset_pending(){return Service::reset_is_pending();}
void Service::portal_reset_scope(bool owned){if(service)service->portal_reset_owner=owned;}
void Service::notify_c64_reset()
{
    if(service&&!service->portal_reset_owner){service->external_reset=true;service->backend.cancel_requested=true;}
}
bool native_menu_held(){return Service::menu_is_held();}
void Service::network_refresh_step()
{
    const TickType_t now=xTaskGetTickCount();
    if(uint32_t(now-last_network_refresh)<uint32_t((configTICK_RATE_HZ+3)/4))return;
    last_network_refresh=now;backend_working=true;
    unlock();refresh_network_info(backend);xSemaphoreTake(mutex,portMAX_DELAY);backend_working=false;
}
void Service::notify_menu(bool held)
{
    // Called before the freezer mutates C64, and after its complete restore.
    // A single atomic flag avoids service/C64 lock inversion in the UI task.
    if(service)service->menu_hold=held;
}

/* Called by the backend outside service/C64/Drive locks. The session and
   work_request are stable for this worker until it returns. Busy/torn samples
   are inconclusive; a committed superseding request aborts the old socket. */
bool Service::backend_should_cancel(void *argument)
{
 Service *self=static_cast<Service *>(argument);
 if(!self||!c1541_A||self->external_reset)return true;
 if(!c1541_A->p08_try_lock())return false;
 Snapshot current={};bool valid=read_snapshot(c1541_A->memory_map,current);c1541_A->unlock();
 if(!valid)return false;
 if(!valid_drive(current.d,self->status.session))return true;
 return u32(current.d+20)!=self->work_request||current.d[5]==DISCARD||current.d[5]==FAULT||current.d[5]==STOPPED;
}
void Service::run(void *argument)
{
    Service *self=static_cast<Service *>(argument);
    for(;;){self->step();vTaskDelay(1);}
}
void Service::step()
{
    if(!try_lock())return;
#if defined(P18_TLS) && P18_TLS
    if(esp_maintenance){unlock();return;}
#endif
    if(external_reset&&(status.state==ACTIVE||status.state==STARTING))fault("C64_RESET_NOTIFIED");
    if(menu_hold&&!status.menu_paused)status.menu_pauses++;
    status.menu_paused=menu_hold;
    secure_setup_step();network_preference_step();network_refresh_step();
    if(status.state==STARTING){
        if(menu_hold)start_tick=xTaskGetTickCount();else start_step();
    }else if(status.state==STOPPING)stop_step();
    else if(status.state==ACTIVE){
        if(menu_hold){bad_snapshot=false;}
        else if(status.program_pending)program_step();
        else if(status.portal_pending)portal_step();
        else active_step();
    }else if(status.state==ERROR && reset_restart && !menu_hold){
        // Same verified restore path as a requested stop; the session stays
        // reserved and is renewed below once RESTORED.
        backend.cancel_requested=true;status.state=STOPPING;status.restore=PENDING;
    }else if(status.state==ERROR && backup_valid && c1541_A && c1541_A->p08_try_lock()){
        c1541_A->registers[C1541_RESET]=7;barrier();c1541_A->registers[C1541_POWER]=0;c1541_A->unlock();
    }
    if(status.state==RESTORED&&portal_restart&&!menu_hold)queue_native_locked(true);
    else if(status.state==RESTORED&&reset_restart&&!menu_hold&&!backend_working&&!backend_inflight){
        // An external cartridge (or anything else start_step rejects) ends
        // the automatic restart; the service then stays stopped as before.
        reset_restart=false;
        if(queue_native_locked(false)!=OK)__atomic_store_n(&native_drive_a_reservation,0,__ATOMIC_RELEASE);
    }
    unlock();
}
void Service::portal_step()
{
    U64Machine *machine=static_cast<U64Machine *>(C64::getMachine());
    if(!machine||!c64_subsys||menu_hold)return;
    if(!c64_subsys->p08_try_lock())return;
    bool safe=machine->p08_environment_safe();c64_subsys->unlock();if(!safe)return;
    if(!c1541_A||!c1541_A->p08_try_lock())return;
    if(!c1541_A->p08_owned){c1541_A->unlock();fault("PORTAL_HELPER_NOT_OWNED");return;}
    c1541_A->registers[C1541_RESET]=7;barrier();c1541_A->registers[C1541_POWER]=0;c1541_A->unlock();
    uint8_t nonce[8];memcpy(nonce,status.session,8);portal_loading=true;
    unlock();int result=c64_subsys->p12_launch_portal(p12_portal_prg,P12_PORTAL_SIZE);xSemaphoreTake(mutex,portMAX_DELAY);
    portal_loading=false;
    if(status.state!=ACTIVE||memcmp(nonce,status.session,8))return;
    if(external_reset){fault("C64_RESET_NOTIFIED");return;}
    if(result==-2)return; // no C64 mutation; A stays power-off for retry
    status.portal_pending=false;
    if(result==0){status.portal_launches++;status.portal_error[0]=0;}
    else{copy_text(status.portal_error,sizeof(status.portal_error),"PORTAL_LOAD_FAILED");fault("PORTAL_LOAD_FAILED");}
}
bool Service::portal_prepare_resume()
{
    // C64's DMA loader holds its subsystem mutex. Never await Drive boot/ACK
    // under that C64 stop: the configured menu freeze also holds Drive A.
    if(!try_lock())return false;
    bool owned_load=(status.portal_pending&&portal_loading)||(status.program_pending&&program_loading);
    bool ok=status.state==ACTIVE&&owned_load&&!menu_hold&&c1541_A;
    if(ok){
        ok=c1541_A->p08_try_lock();
        if(ok){
            ok=c1541_A->p08_owned;
            if(ok){
                c1541_A->registers[C1541_RESET]=7;
                for(unsigned i=0;i<128;i++)c1541_A->memory_map[D_ADDRESS+i]=0;
                trace_service_state(backend.trace,work_request,TRACE_ABANDONED);
                work_request=last_request=last_drive_request=sample_generation=last_d_sequence=0;
                discard_exchange_buffers();
                request_received=request_total=response_length=published_next=consumed_current=consumed_hook_request=0;tcp_read_ticket_current=0;
                prepared=response_started=bad_snapshot=false;memset(&status.mailbox,0,sizeof(status.mailbox));
                p12_reset_commands(status.session);barrier();
                c1541_A->registers[C1541_POWER]=1;barrier();
                c1541_A->registers[C1541_RESET]=6;barrier();
            }
            c1541_A->unlock();
        }
    }
    unlock();return ok;
}
void Service::fault(const char *reason)
{
    trace_service_state(backend.trace,work_request,TRACE_ABANDONED);
    tcp_read_ticket_current=0; // Unconfirmed TCP bytes remain replayable until reset/CLOSE.
    discard_exchange_buffers();
    discard_secure_setup();
    copy_text(status.last_error,sizeof(status.last_error),reason);status.state=ERROR;
    reset_restart=status.native_session&&!strcmp(reason,"C64_RESET_NOTIFIED");
    status.restore=(backup_valid || b_backup_valid || global_valid)?NEEDS_ATTENTION:NOT_NEEDED;prepared=response_started=endpoint_reset_pending=false;status.portal_pending=status.program_pending=false;status.drives_prepared=false;portal_restart=false;discard_program();
    if(backup_valid && c1541_A && c1541_A->p08_try_lock()) {
        c1541_A->registers[C1541_RESET]=7;barrier();c1541_A->registers[C1541_POWER]=0;c1541_A->unlock();
    }
}
bool Service::global_capture_apply()
{
    if(!u64_configurator || !u64_configurator->p08_try_lock())return false;
    ConfigStore *cfg=u64_configurator->cfg;
    parallel_item=cfg?cfg->find_item("SpeedDOS Parallel Cable"):0;
    turbo_item=cfg?cfg->find_item("Turbo Control"):0;
    serial_item=cfg?cfg->find_item("Serial Bus Mode"):0;burst_item=cfg?cfg->find_item("Burst Mode Patch"):0;
    speed_item=cfg?cfg->find_item("CPU Speed"):0;badlines_item=cfg?cfg->find_item("Badline Timing"):0;
    supercpu_item=cfg?cfg->find_item("SuperCPU Detect (D0BC)"):0;
    if(!parallel_item || !turbo_item || !serial_item || !burst_item || !speed_item || !badlines_item || !supercpu_item) {
        u64_configurator->unlock();fault("GLOBAL_SETTINGS_MISSING");return false;
    }
    original_parallel=parallel_item->getValue();original_turbo=turbo_item->getValue();
    original_serial=serial_item->getValue();original_burst=burst_item->getValue();original_speed=speed_item->getValue();
    original_badlines=badlines_item->getValue();original_supercpu=supercpu_item->getValue();
    if(original_parallel<0 || original_parallel>1 || original_turbo<0 || original_turbo>3 || original_serial<0 || original_serial>1 ||
       original_burst<0 || original_burst>2 || original_speed<0 || original_speed>15 || original_badlines<0 || original_badlines>1 || original_supercpu<0 || original_supercpu>1) {
        u64_configurator->unlock();fault("GLOBAL_SETTINGS_RANGE");return false;
    }
    /* These MMIO registers have no established readback contract. Derive the
       original writes from the pinned U64Config::effectuate_settings and
       setCpuSpeed formulas instead of reading possibly write-only registers. */
    static const uint8_t connectors[]={0x70,0x60,0x30,0x50},turbo[]={0,0,1,5};
    original_connectors=connectors[original_serial] | (original_burst<<1) | original_parallel;
    original_turbo_regs=original_turbo?(turbo[original_turbo]+(original_supercpu?2:0)):0;
    original_speed_prefer=original_turbo?(original_speed|(original_badlines<<7)):0x80;
    /* Journal is complete before the first mutation. Quiet runtime values do
       not trigger whole-store changes, ESP calls, or persistence requests. */
    global_valid=true;parallel_item->setValueQuietly(1);turbo_item->setValueQuietly(0);
    U64_INT_CONNECTORS=original_connectors|1;C64_TURBOREGS_EN=0;C64_SPEED_PREFER=0x80;C64_SPEED_UPDATE=1;
    u64_configurator->unlock();return true;
}
bool Service::global_restore()
{
    if(!global_valid){status.settings_verified=true;return true;}
    if(!u64_configurator || !u64_configurator->p08_try_lock())return false;
    if(parallel_item->getValue()!=1 || turbo_item->getValue()!=0 ||
       serial_item->getValue()!=original_serial || burst_item->getValue()!=original_burst || speed_item->getValue()!=original_speed ||
       badlines_item->getValue()!=original_badlines || supercpu_item->getValue()!=original_supercpu) {
        status.settings_verified=false;
        copy_text(status.last_error,sizeof(status.last_error),"FOREIGN_GLOBAL_CHANGE_NOT_OVERWRITTEN");
        u64_configurator->unlock();return true;
    }
    parallel_item->setValueQuietly(original_parallel);turbo_item->setValueQuietly(original_turbo);
    U64_INT_CONNECTORS=original_connectors;C64_TURBOREGS_EN=original_turbo_regs;
    C64_SPEED_PREFER=original_speed_prefer;C64_SPEED_UPDATE=1;
    status.settings_verified=parallel_item->getValue()==original_parallel && turbo_item->getValue()==original_turbo &&
        serial_item->getValue()==original_serial && burst_item->getValue()==original_burst && speed_item->getValue()==original_speed &&
        badlines_item->getValue()==original_badlines && supercpu_item->getValue()==original_supercpu;
    if(status.settings_verified)global_valid=false;
    u64_configurator->unlock();return true;
}
bool Service::drive_b_pending(C1541 *b)
{
    // These WD reads have no FIFO-pop/ack side effects. GCR STATUS alone is
    // insufficient for native1571/1581 MFM writes and completion callbacks.
    if(b->current_drive_type!=e_dt_1541 &&
       ((b->registers[C1541_WD177X+4]&1) || (b->registers[C1541_WD177X+6]&0x80) || (b->registers[C1541_WD177X+7]&3)))return true;
    const bool software_pending=b->write_skip || b->are_mfm_dirty_bits_set();
    // An empty powered-off drive has no mounted image to flush. Preserve its
    // stale generic GCR flags; after startup its own task can acknowledge them.
    if(!(b->registers[C1541_POWER]&1) && b->disk_state==e_no_disk && !software_pending)return false;
    // Native drive_power() acknowledges the global flag with W1C0x80. A
    // powered-off mounted disk can consequently retain dirty tracks even
    // when the summary bit is clear. Do not discard those pending writes.
    for(unsigned i=0;i<128;i++)if(b->registers[C1541_DIRTYFLAGS+i]&1)return true;
    return software_pending || (b->registers[C1541_STATUS]&(DRVSTAT_WRITING|DRVSTAT_WRITEBUSY)) ||
        (b->registers[C1541_DIRTYFLAGS]&0x80);
}
void Service::start_step()
{
    if(uint32_t(xTaskGetTickCount()-start_tick)>uint32_t(configTICK_RATE_HZ*(status.auto_drives?10:2))){fault("START_TIMEOUT");return;}
    U64Machine *machine=static_cast<U64Machine *>(C64::getMachine());
    if(!machine || !c64_subsys){fault("C64_NOT_AVAILABLE");return;}
    if(!c1541_A){fault("DRIVE_A_MISSING");return;}
    if(!backup_valid) {
        if(!c64_subsys->p08_try_lock())return;
        bool eligible=machine->p08_start_eligible();c64_subsys->unlock();
        if(!eligible){fault("C64_UNAVAILABLE_OR_EXTERNAL_CARTRIDGE");return;}
        /* Modes 2/3 disconnect the CIA from the Ultimate IEC bus. Reject
           before claiming or mutating either drive. */
        if(!u64_configurator || !u64_configurator->p08_try_lock())return;
        ConfigItem *serial=u64_configurator->cfg?u64_configurator->cfg->find_item("Serial Bus Mode"):0;
        bool serial_ok=serial && serial->getValue()>=0 && serial->getValue()<=1;
        u64_configurator->unlock();if(!serial_ok){fault("SERIAL_BUS_MODE_UNSUPPORTED");return;}
        if(!c1541_A->p08_try_lock())return;
        C1541 *a=c1541_A;
        // Native startup owns the hardware mode as well as the helper image.
        // A disk is never ejected or migrated implicitly. Validate A before
        // locking/preparing B so rejection has no drive/global side effects.
        bool ready=!a->p08_owned && a->disk_state==e_no_disk &&
            (status.auto_drives ? a->current_drive_type>=e_dt_1541 && a->current_drive_type<=e_dt_1581 :
             a->current_drive_type==e_dt_1541 && (!(a->registers[C1541_POWER]&1)||!(a->registers[C1541_RESET]&1)));
        if(!ready){a->unlock();fault(status.auto_drives?"DRIVE_A_MUST_BE_EMPTY":"DRIVE_A_EMPTY_1541_REQUIRED");return;}
        const uint8_t config_rom_id=0xe1+unsigned(a->current_drive_type);
        const char *rom=a->current_drive_rom.c_str(),*config_rom=a->cfg->get_string(config_rom_id);
        if(strlen(rom)>=sizeof(original_rom) || strlen(config_rom)>=sizeof(original_config_rom) || P08_HELPER_SESSION_OFFSET+8>16384) {
            a->unlock();fault("ROM_METADATA_INVALID");return;
        }
        C1541 *b=0;
        if(status.auto_drives){
            b=c1541_B;
            if(!b){a->unlock();fault("DRIVE_B_MISSING");return;}
            if(!b->p08_try_lock()){a->unlock();return;}
            b_power_item=b->cfg?b->cfg->find_item("Drive"):0;
            b_address_item=b->cfg?b->cfg->find_item("Drive Bus ID"):0;
            if(b->p08_owned || !b_power_item || !b_address_item ||
               b->current_drive_type<e_dt_1541 || b->current_drive_type>e_dt_1581 ||
               b_power_item->getValue()<0 || b_power_item->getValue()>1 ||
               b_address_item->getValue()<8 || b_address_item->getValue()>11){
                b->unlock();a->unlock();fault("DRIVE_B_NOT_AVAILABLE");return;
            }
            // Its task must be allowed to finish pending writes. Retry with
            // no C64/Drive lock retained; never erase dirty flags or remount.
            if(drive_b_pending(b)){
                bool off=!(b->registers[C1541_POWER]&1);b->unlock();a->unlock();
                if(off)fault("DRIVE_B_PENDING_WRITES_POWER_ON");
                return;
            }
            b_original_power=b->registers[C1541_POWER];b_original_reset=b->registers[C1541_RESET];
            b_original_hw=b->registers[C1541_HW_ADDR];b_original_iec_address=b->iec_address;
            b_original_config_power=b_power_item->getValue();b_original_config_address=b_address_item->getValue();
            b_original_config_reset=b->cfg->get_value(0xd8);b_original_config_freeze=b->cfg->get_value(0xdb);
        }
        copy_text(original_rom,sizeof(original_rom),rom);copy_text(original_config_rom,sizeof(original_config_rom),config_rom);
        original_power=a->registers[C1541_POWER];original_reset=a->registers[C1541_RESET];original_hw=a->registers[C1541_HW_ADDR];original_rammap=a->registers[C1541_RAMMAP];
        original_hw_type=a->registers[C1541_DRIVETYPE];original_iec_address=a->iec_address;original_config_rom_id=config_rom_id;
        original_type=int(a->current_drive_type);original_config_power=a->cfg->get_value(0xd1);original_config_address=a->cfg->get_value(0xd2);original_config_type=a->cfg->get_value(0xd9);
        for(unsigned i=0;i<32768;i++)backup[i]=a->memory_map[0x8000+i];
        // The emulated CPU runs independently of its host mutex. Check again
        // after the relatively long A backup and before either drive changes.
        if(b && drive_b_pending(b)){
            bool off=!(b->registers[C1541_POWER]&1);b->unlock();a->unlock();
            if(off)fault("DRIVE_B_PENDING_WRITES_POWER_ON");
            return;
        }
        // Both journals precede the first mutation. A stays electrically quiet
        // while B boots its existing DOS/media as device8.
        backup_valid=true;b_backup_valid=(b!=0);a->p08_owned=true;
        a->registers[C1541_RESET]=7;barrier();a->registers[C1541_POWER]=0;
        if(b){
            b->registers[C1541_RESET]=7;barrier();b->registers[C1541_POWER]=0;
            b_power_item->setValueQuietly(1);b_address_item->setValueQuietly(8);
            b->set_hw_address(8);barrier();b->registers[C1541_POWER]=1;
            wait_ms(1);b->registers[C1541_RESET]=b_original_reset&6;
            bool applied=b->registers[C1541_POWER]==1 && b->registers[C1541_HW_ADDR]==0 && b->iec_address==8;
            b->unlock();
            if(!applied){a->unlock();fault("DRIVE_B_SETUP_VERIFY_FAILED");return;}
        }
        a->unlock();
    }
    if(!global_valid && !global_capture_apply())return;
    if(status.state!=STARTING)return;
    if(!c1541_A->p08_try_lock())return;
    C1541 *a=c1541_A;
    /* Power remains off until the complete image and session are installed. */
    if(!(a->registers[C1541_POWER]&1)) {
        for(unsigned i=0;i<16384;i++) {
            uint8_t value=(i>=P08_HELPER_SESSION_OFFSET && i<P08_HELPER_SESSION_OFFSET+8)?status.session[i-P08_HELPER_SESSION_OFFSET]:p08_helper_rom[i];
            a->memory_map[0x8000+i]=value;a->memory_map[0xc000+i]=value;
        }
        for(unsigned i=0;i<128;i++)a->memory_map[D_ADDRESS+i]=0;
        barrier();
        a->current_drive_rom="WiC64 service";a->current_drive_type=e_dt_1541;
        a->registers[C1541_DRIVETYPE]=0;
        a->registers[C1541_RESET]=7;a->registers[C1541_RAMMAP]=0;
        status.drives_prepared=status.auto_drives;
        if(status.portal_pending||status.program_pending){
            // Keep electrical IEC outputs released while the old C64 program
            // and the boot cartridge reset/initialize the CIA. Callback starts
            // the helper immediately before DMA's final C64 resume.
            a->registers[C1541_POWER]=0;status.state=ACTIVE;
        }else{a->registers[C1541_POWER]=1;wait_ms(1);a->registers[C1541_RESET]=6;}
        a->unlock();return;
    }
    Snapshot boot={};bool valid=snapshot(a->memory_map,status.session,boot);
    if(valid && boot.d[5]!=FAULT && boot.d[5]!=STOPPED && !u32(boot.h)) {
        status.mailbox=boot;last_d_sequence=u32(boot.d+8);status.state=ACTIVE;
    }
    a->unlock();
}
bool Service::drive_snapshot(Snapshot &out)
{
    if(!c1541_A || !c1541_A->p08_try_lock())return false;
    C1541 *a=c1541_A;
    bool valid=a->p08_owned && a->current_drive_type==e_dt_1541 && a->disk_state==e_no_disk &&
        (a->registers[C1541_POWER]&1) && !(a->registers[C1541_RESET]&1) && snapshot(a->memory_map,status.session,out);
    a->unlock();return valid;
}
Result Service::check_globals()
{
    if(!u64_configurator || !u64_configurator->p08_try_lock())return BUSY;
    bool owned=parallel_item && turbo_item && parallel_item->getValue()==1 && turbo_item->getValue()==0 &&
        serial_item->getValue()==original_serial && burst_item->getValue()==original_burst && speed_item->getValue()==original_speed &&
        badlines_item->getValue()==original_badlines && supercpu_item->getValue()==original_supercpu;
    u64_configurator->unlock();return owned?OK:BAD_STATE;
}
/* RX acknowledgements publish no data outputs. Payload remains Drive-owned
   until its entire stable page is copied and the matching H commit is final. */
void Service::receive_window(const Snapshot &seen)
{
 uint32_t request=u32(seen.d+20),total=u32(seen.d+28),offset=u32(seen.d+36);uint16_t length=u16(seen.d+40);
 if(!request||request<=last_request||total>MAX_RX||!protocol(seen.d[25])){fault("RX_REQUEST_INVALID");return;}
 if(work_request!=request){
  if(offset){fault("RX_INITIAL_OFFSET_INVALID");return;}
  trace_service_state(backend.trace,work_request,TRACE_ABANDONED);
  discard_exchange_buffers();tcp_read_ticket_current=0;endpoint_reset_pending=false;
  work_request=request;request_received=0;request_total=total;work_command=seen.d[24];work_protocol=seen.d[25];prepared=response_started=false;
 }
 if(request_total!=total||work_command!=seen.d[24]||work_protocol!=seen.d[25]){fault("RX_METADATA_CHANGED");return;}
 if(u32(seen.d+42)!=u32(seen.h))return; // prior H not yet consumed
 if(offset!=request_received||!length||length>256||offset>total||length>total-offset){fault("RX_WINDOW_INVALID");return;}
 if(!c1541_A->p08_try_lock())return;
 Snapshot now={};uint8_t command[64];
 bool same=snapshot(c1541_A->memory_map,status.session,now)&&!memcmp(&seen,&now,sizeof(now));
 if(same)for(unsigned i=0;i<length;i++)request_data[offset+i]=c1541_A->memory_map[RX_ADDRESS+i];
 Snapshot after={};same=same&&snapshot(c1541_A->memory_map,status.session,after)&&!memcmp(&now,&after,sizeof(now));
 bool valid=same&&prepare_rx(now,status.session,request,command);
 bool sent=valid&&publish(c1541_A->memory_map,now,status.session,command,0,0);c1541_A->unlock();
 if(same&&!valid){fault("RX_GRANT_INVALID");return;}
 if(sent){request_received+=length;status.request_bytes+=length;status.rx_chunks++;status.request_cache_length=request_received;}
}
/* Continuations use the initial receive grant, not another PA2 observation.
   C64 ownership excludes concurrent REST halts; exact D/H/offset ownership
   prevents overwriting an unconsumed page. */
void Service::refill_window(const Snapshot &seen)
{
 uint32_t request=u32(seen.d+20),offset=u32(seen.d+36);
 if(u32(seen.d+42)!=u32(seen.h))return;
 if(!response_started||request!=work_request||offset!=published_next){fault("TX_WINDOW_INVALID");return;}
 if(!c64_subsys->p08_try_lock())return;
 U64Machine *machine=static_cast<U64Machine *>(C64::getMachine());
 if(external_reset){c64_subsys->unlock();fault("C64_RESET_NOTIFIED");return;}
 if(menu_hold){c64_subsys->unlock();return;}
 if(!machine||!machine->p08_environment_safe()){c64_subsys->unlock();fault("C64_RESET_OR_PAUSE");return;}
 if(!c1541_A->p08_try_lock()){c64_subsys->unlock();return;}
 Snapshot now={};uint8_t command[64];
 bool same=snapshot(c1541_A->memory_map,status.session,now)&&!memcmp(&seen,&now,sizeof(now));
 bool valid=same&&prepare_tx(now,status.session,request,offset,response_length,response_status,response_flags,command);
 uint16_t length=valid?u16(command+28):0;
 bool sent=valid&&publish(c1541_A->memory_map,now,status.session,command,response_data+offset,length);
 c1541_A->unlock();c64_subsys->unlock();
 if(same&&!valid){fault("TX_GRANT_INVALID");return;}
 if(sent){
#if defined(P18_LOG) && P18_LOG
  p18log::response_packet(work_command,work_protocol,work_request,trace_now_ms(),response_status,response_flags,response_data+offset,response_length,offset,length);
#endif
  status.tx_consumed_bytes+=offset-consumed_current;consumed_current=offset;
  published_next+=length;status.last_tx_offset=offset;status.tx_chunks++;status.tx_refills++;
 }
}
void Service::active_step()
{
 U64Machine *machine=static_cast<U64Machine *>(C64::getMachine());
 if(!machine||!c64_subsys){fault("C64_NOT_AVAILABLE");return;}
 if(!c64_subsys->p08_try_lock())return;
 bool safe=machine->p08_environment_safe();c64_subsys->unlock();
 Result global_state=check_globals();if(global_state==BUSY)return;if(global_state!=OK){fault("FOREIGN_GLOBAL_CHANGE_NOT_OVERWRITTEN");return;}
 Snapshot current={};if(!c1541_A||!c1541_A->p08_try_lock())return;C1541 *a=c1541_A;
 bool running=a->p08_owned&&(a->registers[C1541_POWER]&1)&&!(a->registers[C1541_RESET]&1);
 if(!running){a->unlock();fault("HELPER_RESET_OR_BAD_MAILBOX");return;}
 if(!read_snapshot(a->memory_map,current)){
  a->unlock();if(!bad_snapshot){bad_snapshot=true;bad_snapshot_tick=xTaskGetTickCount();}
  else if(uint32_t(xTaskGetTickCount()-bad_snapshot_tick)>uint32_t(configTICK_RATE_HZ/2)){fault("MAILBOX_COMMIT_STALLED");}
  return;
 }
 a->unlock();bad_snapshot=false;
 if(!valid_drive(current.d,status.session)){fault("HELPER_SESSION_OR_HEADER_INVALID");return;}
 uint32_t sequence=u32(current.d+8),request=u32(current.d+20);
 if(!safe){if(menu_hold)return;if(!status.probe_armed&&status.requests==0&&!request)return;fault("C64_RESET_OR_PAUSE");return;}
 uint32_t guard_mask=helper_guard_reasons(current,last_d_sequence,last_request,last_drive_request);
 if(guard_mask){
  // Capture the actual validated offending snapshot BEFORE fault powers the
  // helper off. Previously the public status retained only the last good D/H.
  status.mailbox=current;status.helper_guard_mask=guard_mask;
  status.helper_previous_sequence=last_d_sequence;status.helper_previous_request=last_request;
  status.helper_previous_drive_request=last_drive_request;status.helper_work_request=work_request;
  fault("HELPER_GENERATION_INVALID");return;
 }
 /* The retained final offset proves completion even when D's diagnostic
    completed counter has saturated. The counter also notices a completion
    whose brief IDLE publication was followed by another request. At counter
    saturation a missed IDLE supplies no completion proof: telemetry may
    undercount and a staged connect must be abandoned by the new context,
    never executed from an assumed acknowledgement. */
 bool completed_current=current.d[5]==IDLE&&request==work_request&&
     u32(current.d+32)==response_length&&u32(current.d+36)==response_length&&published_next==response_length;
 if(response_started&&(completed_current||u16(current.d+52)>u16(status.mailbox.d+52))&&response_length>=consumed_current&&published_next==response_length){
  trace_service_state(backend.trace,work_request,TRACE_COMPLETE);
  status.tx_consumed_bytes+=response_length-consumed_current;consumed_current=response_length;
  discard_exchange_buffers();response_started=false;
  if(consumed_hook_request!=work_request){
   consumed_hook_request=work_request;uint8_t nonce[8];memcpy(nonce,status.session,8);uint32_t finished=work_request;
   // A TCP_READ owns a generation ticket. Only its fully delivered response
   // may consume held bytes; local commands/aborted replies never do so.
   uint32_t read_ticket=tcp_read_ticket_current;tcp_read_ticket_current=0;
   unlock();if(read_ticket)p12_tcp_finalize_read(read_ticket,true);
   p12_response_consumed(nonce,finished);xSemaphoreTake(mutex,portMAX_DELAY);
   if(status.state!=ACTIVE||status.program_pending||memcmp(nonce,status.session,8))return;
  }
 }
 last_d_sequence=sequence;last_drive_request=request;status.mailbox=current;
 if(current.d[5]==DISCARD){trace_service_state(backend.trace,work_request,TRACE_ABANDONED);discard_exchange_buffers();tcp_read_ticket_current=0;prepared=response_started=endpoint_reset_pending=false;return;}
 if(current.d[5]==RX_WINDOW){receive_window(current);return;}
 if(current.d[5]==TX_WINDOW){refill_window(current);return;}
 if(current.d[5]!=REQUEST_READY)return;
 // A newer request may overtake a stale H grant; the helper must first
 // acknowledge that old commit without emitting it. This is normal busy.
 if(u32(current.d+42)!=u32(current.h))return;
 if(prepared&&request!=work_request){trace_service_state(backend.trace,work_request,TRACE_ABANDONED);discard_exchange_buffers();tcp_read_ticket_current=0;prepared=response_started=endpoint_reset_pending=false;}
 if(!prepared){
  if(request==last_request)return;
  uint32_t total=u32(current.d+28);
  if(!request||request<=last_request||total>MAX_RX||!protocol(current.d[25])||u32(current.d+36)||u16(current.d+40)){
   fault("REQUEST_INVALID");return;
  }
  if(total){if(request!=work_request||request_received!=total||request_total!=total||work_command!=current.d[24]||work_protocol!=current.d[25]){fault("RX_INCOMPLETE");return;}}
  else {trace_service_state(backend.trace,work_request,TRACE_ABANDONED);work_request=request;request_received=request_total=0;work_command=current.d[24];work_protocol=current.d[25];clear_private(request_data,sizeof(request_data));status.request_cache_length=0;}
  clear_private(response_data,sizeof(response_data));status.response_cache_length=0;
  last_request=request;status.requests++;response_started=false;response_flags=0;tcp_read_ticket_current=0;
  trace_begin(backend.trace,work_command,work_protocol,work_request);
#if defined(P18_LOG) && P18_LOG
  uint8_t log_error=0;uint16_t log_http=0;
  p18log::request_packet(work_command,work_protocol,work_request,trace_now_ms(),request_data,total);
  if(!trace_command(work_command))p18log::local_begin(work_command,work_protocol,work_request,trace_now_ms());
#endif
  if(work_command==0x29&&!total&&(work_protocol=='R'||work_protocol=='W')){
   // Emulate the WiC64 endpoint reset, never the machine/ESP/FPGA reset.
   // Original drive/global journals and persistent credentials are retained.
   uint8_t nonce[8];memcpy(nonce,status.session,8);
   backend_working=true;unlock();reset_backend_session(backend);p12_reset_commands(nonce);
   vTaskDelay(pdMS_TO_TICKS(500));
   xSemaphoreTake(mutex,portMAX_DELAY);backend_working=false;
   if(status.state!=ACTIVE||status.program_pending||memcmp(nonce,status.session,8))return;
   if(external_reset){fault("C64_RESET_NOTIFIED");return;}
   backend.should_cancel=backend_should_cancel;backend.cancel_context=this;
   response_status=0;response_length=0;endpoint_reset_pending=true;
  }else response_status=(work_protocol=='R'||work_protocol=='W')?
      dispatch_local(work_command,request_data,total,response_data,response_length):NEEDS_BACKEND;
  if(response_status==NEEDS_BACKEND){
   uint8_t work_session[8];memcpy(work_session,status.session,8);
   p12_request_context(work_session,work_request);
   backend_inflight=true;unlock();BackendResult answer=execute_backend(backend,work_command,work_protocol,request_data,total,response_data,MAX_TX);
   uint32_t read_ticket=work_command==0x22&&!answer.status&&answer.length?p12_tcp_read_ticket():0;
   xSemaphoreTake(mutex,portMAX_DELAY);backend_inflight=false;
   clear_private(request_data,sizeof(request_data));status.request_cache_length=0;
   if(answer.http_performed){status.http_requests++;status.http_last_status=answer.http_status;if(!answer.status)status.http_success++;else status.http_errors++;}
   if(status.state!=ACTIVE||status.program_pending||memcmp(status.session,work_session,8)){trace_service_state(backend.trace,work_request,TRACE_ABANDONED);discard_exchange_buffers();return;}
   if(external_reset){fault("C64_RESET_NOTIFIED");return;}
   response_status=answer.status;response_length=answer.length;response_flags=answer.flags;tcp_read_ticket_current=read_ticket;
#if defined(P18_LOG) && P18_LOG
   log_error=answer.error;log_http=answer.http_status;
#endif
  }
  clear_private(request_data,sizeof(request_data));status.request_cache_length=0;
  if(response_length>MAX_TX||(work_protocol!='E'&&response_length>65535)){
   clear_private(response_data,sizeof(response_data));tcp_read_ticket_current=0;
   response_status=2;response_length=0;response_flags=0;copy_text(backend.last_status,sizeof(backend.last_status),"Response exceeds protocol limit");
  }
  status.response_bytes+=response_length;status.response_cache_length=response_length;
  trace_finish(backend.trace,response_status,0,0,response_length);
#if defined(P18_LOG) && P18_LOG
  if(!trace_command(work_command))p18log::local_finish(work_command,work_protocol,work_request,trace_now_ms(),response_status,log_error,log_http,response_length);
#endif
  trace_service_state(backend.trace,work_request,TRACE_RESPONSE_READY);
  if(response_length>status.peak_response_bytes)status.peak_response_bytes=response_length;
  consumed_current=0;prepared=true;
 }
 global_state=check_globals();if(global_state==BUSY)return;if(global_state!=OK){fault("FOREIGN_GLOBAL_CHANGE_NOT_OVERWRITTEN");return;}
 Snapshot before={};if(!drive_snapshot(before))return;
 if(before.d[5]!=REQUEST_READY||u32(before.d+20)!=work_request){trace_service_state(backend.trace,work_request,TRACE_ABANDONED);discard_exchange_buffers();tcp_read_ticket_current=0;prepared=response_started=endpoint_reset_pending=false;return;}
 if(!c64_subsys->p08_try_lock())return;
 if(!c1541_A->p08_try_lock()){c64_subsys->unlock();return;}
 if(endpoint_reset_pending){
  bool reset_notified=external_reset;
  if(reset_notified||menu_hold||!machine->p08_environment_safe()){
   c1541_A->unlock();c64_subsys->unlock();
   if(reset_notified)fault("C64_RESET_NOTIFIED");
   else if(!menu_hold)fault("C64_RESET_OR_PAUSE");
   return;
  }
  Snapshot now={};uint8_t command[64];
  bool same=snapshot(c1541_A->memory_map,status.session,now)&&!memcmp(&now,&before,sizeof(now));
  bool valid=same&&prepare_endpoint_reset(now,status.session,work_request,command);
  bool sent=valid&&publish(c1541_A->memory_map,now,status.session,command,0,0);
  c1541_A->unlock();c64_subsys->unlock();
  if(same&&!valid){fault("ENDPOINT_RESET_GRANT_INVALID");return;}
  if(sent){prepared=response_started=endpoint_reset_pending=false;status.endpoint_resets++;status.responses++;status.response_cache_length=0;}
  return;
 }
 Measurement measured={};uint16_t chunk=response_length>256?256:uint16_t(response_length);
 Result result=machine->p08_measure_publish(c1541_A->memory_map,before,status.session,work_request,response_data,chunk,response_length,response_status,response_flags,sample_generation+1,measured);
 c1541_A->unlock();c64_subsys->unlock();if(measured.sampled)status.pa2_samples++;status.last_stop_ms=measured.stop_ms;
 if(measured.published){
#if defined(P18_LOG) && P18_LOG
  p18log::response_packet(work_command,work_protocol,work_request,trace_now_ms(),response_status,response_flags,response_data,response_length,0,chunk);
#endif
  trace_service_state(backend.trace,work_request,TRACE_INITIAL_GRANT);status.responses++;sample_generation++;prepared=false;response_started=true;published_next=chunk;status.last_tx_offset=0;status.tx_chunks++;status.probe_armed=true;}
 else if(result==DIRECTION_NOT_READY)trace_service_state(backend.trace,work_request,TRACE_WAIT_DIRECTION);
 if(result!=OK&&result!=DIRECTION_NOT_READY&&result!=BUSY&&!menu_hold)fault(result_name(result));
}
bool Service::restore_b()
{
    if(!b_backup_valid){status.b_metadata_verified=true;return true;}
    if(!c1541_B){copy_text(status.last_error,sizeof(status.last_error),"RESTORE_DRIVE_B_MISSING");return true;}
    C1541 *b=c1541_B;if(!b->p08_try_lock())return false;
    // B remains a normal drive during WiC64. Mounted disks, type changes and
    // their data belong to the user; only our temporary address/power settings
    // are restored. Explicit foreign changes are not silently overwritten.
    bool owned=!b->p08_owned && b_power_item && b_address_item &&
        b_power_item->getValue()==1 && b_address_item->getValue()==8 &&
        b->registers[C1541_POWER]==1 && b->registers[C1541_HW_ADDR]==0 && b->iec_address==8 &&
        b->cfg->get_value(0xd8)==b_original_config_reset && b->cfg->get_value(0xdb)==b_original_config_freeze;
    if(!owned){
        status.b_metadata_verified=false;
        copy_text(status.last_error,sizeof(status.last_error),"FOREIGN_DRIVE_B_CHANGE_NOT_OVERWRITTEN");b->unlock();return true;
    }
    if(drive_b_pending(b)){
        b->unlock();return false;
    }
    b->registers[C1541_RESET]=7;barrier();b->registers[C1541_POWER]=0;
    b_power_item->setValueQuietly(b_original_config_power);b_address_item->setValueQuietly(b_original_config_address);
    b->registers[C1541_HW_ADDR]=b_original_hw;b->iec_address=b_original_iec_address;
    barrier();b->registers[C1541_POWER]=b_original_power;wait_ms(1);b->registers[C1541_RESET]=b_original_reset;
    status.b_metadata_verified=b_power_item->getValue()==b_original_config_power && b_address_item->getValue()==b_original_config_address &&
        b->registers[C1541_POWER]==b_original_power && b->registers[C1541_RESET]==b_original_reset &&
        b->registers[C1541_HW_ADDR]==b_original_hw && b->iec_address==b_original_iec_address;
    if(status.b_metadata_verified)b_backup_valid=false;
    else copy_text(status.last_error,sizeof(status.last_error),"RESTORE_DRIVE_B_VERIFY_FAILED");
    b->unlock();return true;
}
void Service::stop_step()
{
    trace_service_state(backend.trace,work_request,TRACE_ABANDONED);
    discard_exchange_buffers();
    tcp_read_ticket_current=0;
    discard_program();
    prepared=response_started=endpoint_reset_pending=false;status.drives_prepared=false;status.response_cache_length=status.request_cache_length=0;
    if(!rom_done) {
        if(backup_valid) {
            if(!c1541_A || !c1541_A->p08_try_lock())return;
            C1541 *a=c1541_A;a->registers[C1541_RESET]=7;barrier();a->registers[C1541_POWER]=0;
            for(unsigned i=0;i<32768;i++)a->memory_map[0x8000+i]=backup[i];
            barrier();
            status.rom_verified=true;
            for(unsigned i=0;i<32768;i++)if(a->memory_map[0x8000+i]!=backup[i]){status.rom_verified=false;break;}
            a->current_drive_rom=original_rom;a->current_drive_type=t_drive_type(original_type);
            a->registers[C1541_HW_ADDR]=original_hw;a->registers[C1541_RAMMAP]=original_rammap;
            a->registers[C1541_DRIVETYPE]=original_hw_type;a->iec_address=original_iec_address;
            /* Keep CPU/VIA reset and power off until global settings have
               also been restored. The normal DOS must not boot on the
               diagnostic parallel/turbo configuration. */
            status.metadata_verified=strcmp(a->current_drive_rom.c_str(),original_rom)==0 && int(a->current_drive_type)==original_type &&
                a->registers[C1541_HW_ADDR]==original_hw && a->registers[C1541_RAMMAP]==original_rammap &&
                a->registers[C1541_DRIVETYPE]==original_hw_type && a->iec_address==original_iec_address &&
                (a->registers[C1541_RESET]&1) && !(a->registers[C1541_POWER]&1) &&
                a->cfg->get_value(0xd1)==original_config_power && a->cfg->get_value(0xd2)==original_config_address && a->cfg->get_value(0xd9)==original_config_type &&
                strcmp(a->cfg->get_string(original_config_rom_id),original_config_rom)==0;
            a->unlock();
        } else status.rom_verified=status.metadata_verified=true;
        rom_done=true;
    }
    if(!restore_b())return;
    if(!global_restore())return;
    bool restored=status.rom_verified && status.metadata_verified && status.b_metadata_verified && status.settings_verified;
    if(restored) {
        if(backup_valid) {
            if(!c1541_A || !c1541_A->p08_try_lock())return;
            C1541 *a=c1541_A;
            barrier();a->registers[C1541_POWER]=original_power;wait_ms(1);a->registers[C1541_RESET]=original_reset;
            status.metadata_verified=a->registers[C1541_POWER]==original_power && a->registers[C1541_RESET]==original_reset;
            if(!status.metadata_verified){a->registers[C1541_RESET]=original_reset|1;a->registers[C1541_POWER]=0;a->unlock();fault("RESTORE_POWER_VERIFY_FAILED");return;}
            a->p08_owned=false;a->unlock();
        }
        uint8_t no_session[8]={};p12_reset_commands(no_session);
        backup_valid=false;status.restore=RESTORE_OK;status.state=RESTORED;
        // A portal restart owns the gap between its restored and next session.
        if(!portal_restart&&!reset_restart)__atomic_store_n(&native_drive_a_reservation,0,__ATOMIC_RELEASE);
    } else fault(status.last_error[0]?status.last_error:"RESTORE_VERIFY_FAILED");
}
}
static void init_p08(void *,void *){p08::service=new p08::Service();}
InitFunction init_p08_service("WiC64 P08 RAM service",init_p08,0,0,110);
#endif
