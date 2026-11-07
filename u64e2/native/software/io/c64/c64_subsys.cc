// U64E2 modifications: Retro-Modern and U64E2 contributors, 2026-11-07.
/*
 * c64_subsys.cc
 *
 *  Created on: Jul 16, 2015
 *      Author: Gideon
 */

#include "c64.h"
#include "x00_wrapper.h"
#include "pattern.h"
#include "c64_crt.h"
#include "c64_subsys.h"
#include <ctype.h>
#include <stdlib.h>
#include "init_function.h"
#include "userinterface.h"
#include "u64.h"
#include "c1541.h"
#include "endianness.h"
#include "monitor_init.h"
#if U64 && P08_SERVICE
#include "p08_service.h"
#include "p18_mount_target.h"
#include "p12_storage.h"
#include "p14_platform.h"
#include "p17c_ui.h"
#include "p18_control_center.h"
#if defined(P18_TLS) && P18_TLS
#include "p18m_esp_firmware.h"
#endif
#if defined(P18_LOG) && P18_LOG
#include "p18_log_view.h"
#endif
#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
#include "p17f_cache.h"
#endif
#define MENU_P12_START  0x64a0
#define MENU_P12_STOP   0x64a1
#define MENU_P12_STATUS 0x64a2
#define MENU_P12_PORTAL 0x64a3
#define MENU_P12_CONNECTION 0x64a4
#define MENU_P12_DIAGNOSTICS 0x64a5
#define MENU_P12_TLS_DETAILS 0x64a6
#define MENU_P18_LOG 0x64a7
#define MENU_P18_CONTROL_CENTER 0x64a8

#if defined(P18_TLS) && P18_TLS
// P18M_LAUNCH_BEGIN
static SubsysResultCode_e p18m_wic64_launch(SubsysCommand *cmd)
{
    if(!cmd||(cmd->functionID!=MENU_P12_START&&cmd->functionID!=MENU_P12_PORTAL&&
              cmd->functionID!=MENU_P18_CONTROL_CENTER))return SSRET_INVALID_PARAMETER;
    // Direct actions reach this callback without the C64 subsystem mutex.
    // Probes, consent, maintenance release and ESP recovery finish before the
    // ordinary command acquires that mutex to queue the requested C64 action.
    SubsysResultCode_e ready=p18m_esp::prepare_launch(cmd->user_interface);
    if(ready!=SSRET_OK)return ready;
    SubsysCommand *routed=new SubsysCommand(cmd->user_interface,SUBSYSID_C64,
        cmd->functionID,cmd->mode,cmd->path.c_str(),cmd->filename.c_str());
    return routed->execute().status;
}
// P18M_LAUNCH_END
#endif

class WiC64ConnectionAction : public Action
{
public:
    WiC64ConnectionAction():Action("Connection: Auto / LAN / WLAN",SUBSYSID_C64,MENU_P12_CONNECTION){}
    const char *getDisplayName(UserInterface *)
    {
        p08::BackendSummary network={};
        if(!p08::service)return "Connection: Unavailable";
        p08::service->get_network_summary(network);
        return p17c::network_action_label(network);
    }
};
#endif
#if U64 == 2
#include "wifi.h"
#if U64 && P08_SERVICE
#include "p12_wifi.h"
#endif
#endif

#define C64_BOOTCRT_DOSYNC    0x014F
#define C64_BOOTCRT_RUNCODE   0x0172
#define C64_BOOTCRT_DRIVENUM  0x0173
#define C64_BOOTCRT_NAMELEN   0x0174
#define C64_BOOTCRT_NAME      0x0175
#define C64_BOOTCRT_HANDSHAKE 0x02
#define C64_BOOTCRT_JUMPADDR  0x00AA

/* other external references */
extern uint8_t _bootcrt_65_start;
extern uint8_t _bootcrt_65_end;

static bool contains_path_separator(const char *name)
{
    while (*name) {
        if ((*name == '/') || (*name == '\\')) {
            return true;
        }
        name++;
    }
    return false;
}

// Returns either the name itself, or a trimmed copy in the caller's buffer.
// Plain names are passed on untouched: CbmFileName cuts them to 16 PETSCII
// characters itself, and needs the extension that trimming here would remove.
static const char *format_bootcrt_display_name(const char *name, char *trimmed)
{
    const int kDisplayChars = 16;
    const int kTrimmedTailChars = 13;
    int length = strlen(name);

    if ((length <= kDisplayChars) || !contains_path_separator(name)) {
        return name;
    }

    memcpy(trimmed, "...", 3);
    memcpy(trimmed + 3, name + length - kTrimmedTailChars, kTrimmedTailChars);
    trimmed[kDisplayChars] = 0;
    return trimmed;
}

// The boot cart prints the name out of the x00 header, as the host name does not identify the
// file, rendered as a host name spells a CBM name because CbmFileName reads it back (SI-144b).
static const char *x00_load_name(File *f, const char *host_name, char *rendered, int size)
{
    char cbm_name[17];
    if (!x00_skip_header(f, host_name, NULL, cbm_name) || !x00_shown_name(cbm_name)) {
        return host_name;
    }
    petscii_to_fat(cbm_name, rendered, size);
    return rendered;
}

cart_def boot_cart; // static => initialized with all zeros.

static SubsysResultCode_e dma_result(int result)
{
    return result==-2?SSRET_NO_LOCK:result<0?SSRET_INVALID_PARAMETER:SSRET_OK;
}

static void initBootCart(void *object, void *param)
{
    int size = (int)&_bootcrt_65_end - (int)&_bootcrt_65_start;
    boot_cart.custom_addr = new uint8_t[8192];
    boot_cart.length = size;
    boot_cart.type = CART_TYPE_8K;

    memcpy(boot_cart.custom_addr, &_bootcrt_65_start, size);
    printf("%d bytes copied into boot_cart.\n", size);
}
InitFunction bootCart_initializer("Boot Cart", initBootCart, NULL, NULL);

C64_Subsys::C64_Subsys(C64 *machine)  : SubSystem(SUBSYSID_C64)
{
	taskHandle = 0;
	c64 = machine;
	fm = FileManager :: getFileManager();
	taskHandle = 0;

	taskCategory = TasksCollection :: getCategory("C64 Machine", SORT_ORDER_C64);
}

C64_Subsys::~C64_Subsys() {
    if (taskHandle) {
    	vTaskDelete(taskHandle);
    }

}

void C64_Subsys :: create_task_items(void)
{
    myActions.reset    = new Action("Reset C64", SUBSYSID_C64, MENU_C64_RESET);
    myActions.reboot   = new Action("Reboot C64", SUBSYSID_C64, MENU_C64_REBOOT);
    myActions.clearmem = new Action("Reboot (Clr Mem)", SUBSYSID_C64, MENU_C64_CLEARMEM);
    myActions.powercyc = new Action("Power Cycle", SUBSYSID_C64, MENU_C64_POWERCYCLE);
    myActions.off      = new Action("Power OFF", SUBSYSID_C64, MENU_C64_POWEROFF);
    myActions.pause    = new Action("Pause",  SUBSYSID_C64, MENU_C64_PAUSE);
    myActions.resume   = new Action("Resume", SUBSYSID_C64, MENU_C64_RESUME);
    myActions.savereu  = new Action("Save REU Memory", SUBSYSID_C64, MENU_C64_SAVEREU);
    myActions.savemem  = new Action("Save C64 Memory", SUBSYSID_C64, MENU_U64_SAVERAM);
    myActions.save_crt = new Action("Save Cartridge", SUBSYSID_C64, MENU_C64_SAVE_CARTRIDGE);
    myActions.savemp3a = new Action("Save MP3 Drv A", SUBSYSID_C64, MENU_C64_SAVE_MP3_DRV_A);
    myActions.savemp3b = new Action("Save MP3 Drv B", SUBSYSID_C64, MENU_C64_SAVE_MP3_DRV_B);
    myActions.savemp3c = new Action("Save MP3 Drv C", SUBSYSID_C64, MENU_C64_SAVE_MP3_DRV_C);
    myActions.savemp3d = new Action("Save MP3 Drv D", SUBSYSID_C64, MENU_C64_SAVE_MP3_DRV_D);
    myActions.measure  = new Action("Measure Cart Bus", SUBSYSID_C64, MENU_MEASURE_TIMING);
#if !U64
    myActions.monitor  = register_c64_machine_monitor_task ? register_c64_machine_monitor_task(MENU_C64_MONITOR) : NULL;
#endif

    taskCategory->append(myActions.reset);
    taskCategory->append(myActions.reboot);
#if U64
    taskCategory->append(myActions.clearmem);
    taskCategory->append(myActions.off);
#endif
#if U64 == 2
    taskCategory->append(myActions.powercyc);
#endif
#if DEVELOPER > 0
    taskCategory->append(myActions.pause);
    taskCategory->append(myActions.resume);
    taskCategory->append(myActions.measure);
#endif
    taskCategory->append(myActions.savemem);
    taskCategory->append(myActions.savereu);
    taskCategory->append(myActions.save_crt);
    taskCategory->append(myActions.savemp3a);
    taskCategory->append(myActions.savemp3b);
    taskCategory->append(myActions.savemp3c);
    taskCategory->append(myActions.savemp3d);
#if U64 && P08_SERVICE
    TaskCategory *wic=TasksCollection::getCategory("WiC64",SORT_ORDER_C64+1);
#if defined(P18_TLS) && P18_TLS
    myActions.wic_start=new Action("Start WiC64",p18m_wic64_launch,MENU_P12_START);
#else
    myActions.wic_start=new Action("Start WiC64",SUBSYSID_C64,MENU_P12_START);
#endif
    myActions.wic_stop=new Action("Stop WiC64",SUBSYSID_C64,MENU_P12_STOP);
    myActions.wic_status=new Action("WiC64 Status",SUBSYSID_C64,MENU_P12_STATUS);
#if defined(P18_TLS) && P18_TLS
    myActions.wic_portal=new Action("WiC64 Portal",p18m_wic64_launch,MENU_P12_PORTAL);
    myActions.wic_control_center=new Action("WiC64 Control Center",p18m_wic64_launch,MENU_P18_CONTROL_CENTER);
#else
    myActions.wic_portal=new Action("WiC64 Portal",SUBSYSID_C64,MENU_P12_PORTAL);
    myActions.wic_control_center=new Action("WiC64 Control Center",SUBSYSID_C64,MENU_P18_CONTROL_CENTER);
#endif
    myActions.wic_connection=new WiC64ConnectionAction();
    myActions.wic_diagnostics=new Action("Diagnostic",SUBSYSID_C64,MENU_P12_DIAGNOSTICS);
    myActions.wic_tls_details=new Action("TLS Details",SUBSYSID_C64,MENU_P12_TLS_DETAILS);
    wic->append(myActions.wic_portal);wic->append(myActions.wic_control_center);wic->append(myActions.wic_start);wic->append(myActions.wic_stop);wic->append(myActions.wic_status);
    wic->append(myActions.wic_connection);wic->append(myActions.wic_diagnostics);wic->append(myActions.wic_tls_details);
#if defined(P18_LOG) && P18_LOG
    // Direct callback: a live remote viewer must not hold the C64 subsystem
    // mutex and prevent portal/program actions while the machine is running.
    static Action *log_action=new Action("Log",p18logview::open,MENU_P18_LOG);
    if(log_action){log_action->setPersistent();wic->append(log_action);}
#endif
#endif
}

void C64_Subsys :: update_task_items(bool writablePath)
{
#if U64 && P08_SERVICE
    p08::Status ws={};bool available=p08::service&&p08::service->get_status(ws);
    bool idle=available&&(ws.state==p08::SERVICE_IDLE||ws.state==p08::RESTORED);
    bool stopping=available&&(ws.state==p08::ACTIVE||ws.state==p08::STARTING||ws.state==p08::ERROR);
    if(idle)myActions.wic_start->enable();else myActions.wic_start->disable();
    if(stopping)myActions.wic_stop->enable();else myActions.wic_stop->disable();
    if(idle||(available&&ws.state==p08::ACTIVE))myActions.wic_portal->enable();else myActions.wic_portal->disable();
    if(idle||(available&&ws.native_session&&(ws.state==p08::ACTIVE||ws.state==p08::STARTING)))myActions.wic_control_center->enable();else myActions.wic_control_center->disable();
    if(available)myActions.wic_connection->enable();else myActions.wic_connection->disable();
#endif

    if (C64 :: isMP3RamDrive(0) > 0) myActions.savemp3a->show(); else myActions.savemp3a->hide();
    if (C64 :: isMP3RamDrive(1) > 0) myActions.savemp3b->show(); else myActions.savemp3b->hide();
    if (C64 :: isMP3RamDrive(2) > 0) myActions.savemp3c->show(); else myActions.savemp3c->hide();
    if (C64 :: isMP3RamDrive(3) > 0) myActions.savemp3d->show(); else myActions.savemp3d->hide();

    if (C64_CRT :: is_valid()) {
        myActions.save_crt->show();
    } else {
        myActions.save_crt->hide();
    }

    if (writablePath) {
        myActions.savemem  ->enable();
        myActions.savereu  ->enable();
        myActions.save_crt ->enable();
        myActions.savemp3a ->enable();
        myActions.savemp3b ->enable();
        myActions.savemp3c ->enable();
        myActions.savemp3d ->enable();
    } else {
        myActions.savemem  ->disable();
        myActions.savereu  ->disable();
        myActions.save_crt ->disable();
        myActions.savemp3a ->disable();
        myActions.savemp3b ->disable();
        myActions.savemp3c ->disable();
        myActions.savemp3d ->disable();
    }
}


void C64_Subsys :: restoreCart(void)
{
	for (int i=0; (i<500) && (C64_CARTRIDGE_ACTIVE); i++) {
		vTaskDelay(2);
	}
	if (C64_CARTRIDGE_ACTIVE) {
	    printf("Error.. cart did not get disabled.\n");
	    c64->init_cartridge(); // hard reset
	} else {
	    printf("Cart got disabled, now restoring.\n");
	    c64->set_cartridge(NULL);
        C64_CARTRIDGE_KILL = 2; // Force update
        C64_CARTRIDGE_KILL = 2; // Force update
	}
}


SubsysResultCode_e C64_Subsys::executeCommand(SubsysCommand *cmd)
{
    File *f = 0;
    FRESULT res;
    CachedTreeNode *po;
    uint32_t transferred;
    int ram_size;
    char buffer[64] = "memory";
    uint8_t *pb;
    SubsysResultCode_e result = SSRET_OK;

    switch (cmd->functionID) {
#if U64 && P08_SERVICE
        case MENU_P18_CONTROL_CENTER: {
            if(!p08::service)return SSRET_SUBSYS_NOT_PRESENT;
            p18cc::Image image;
            p18cc::Result loaded=p18cc::load(fm,cmd->path.c_str(),image);
            if(loaded!=p18cc::OK){
                if(cmd->user_interface)cmd->user_interface->popup(p18cc::message(loaded),BUTTON_OK);
                return loaded==p18cc::NO_MEMORY?SSRET_OUT_OF_MEMORY:
                       loaded==p18cc::MISSING||loaded==p18cc::OPEN_ERROR?SSRET_CANNOT_OPEN_FILE:
                       loaded==p18cc::READ_ERROR?SSRET_FILE_READ_FAILED:SSRET_ERROR_IN_FILE_FORMAT;
            }
            if(cmd->user_interface&&cmd->user_interface->popup("Start Control Center\nand restart C64?",BUTTON_YES|BUTTON_NO)!=BUTTON_YES)return SSRET_ABORTED_BY_USER;
            p08::Result queued=p08::service->request_control_center(image.bytes,p18cc::ASSET_BYTES);
            if(queued!=p08::OK){
                if(cmd->user_interface)cmd->user_interface->popup(p08::result_name(queued),BUTTON_OK);
                return SSRET_NO_LOCK;
            }
            if(cmd->user_interface)cmd->user_interface->menu_response_to_action=MENU_HIDE;
            return SSRET_OK;
        }
        case MENU_P12_START:case MENU_P12_STOP:case MENU_P12_STATUS:case MENU_P12_PORTAL:
        case MENU_P12_CONNECTION:case MENU_P12_DIAGNOSTICS:case MENU_P12_TLS_DETAILS: {
            if(!p08::service)return SSRET_SUBSYS_NOT_PRESENT;
            if(cmd->functionID==MENU_P12_STATUS||cmd->functionID==MENU_P12_DIAGNOSTICS||cmd->functionID==MENU_P12_TLS_DETAILS){
                p08::Status ws={};p08::BackendSummary network={};
                if(!p08::service->get_status(ws))return SSRET_NO_LOCK;
                p08::service->get_network_summary(network);char text[p17c::PANEL_BYTES];
                p12::Status flash={};bool have_flash=p12::get_status(flash);
                const char *flash_state=!have_flash?"Unavailable":network.credentials_saved&&flash.persisted&&!flash.dirty?"Saved":flash.writable?"Ready / unsaved":"RAM only";
                const char *flash_error=ws.preferences_error[0]?ws.preferences_error:have_flash&&flash.last_error!=p12::OK&&flash.last_error!=p12::EMPTY?p12::result_name(flash.last_error):"";
                const char *drives=ws.drives_prepared?"A: WiC64 / B: device 8":ws.state==p08::RESTORED?"Previous settings restored":ws.state==p08::ERROR?"Setup / restore needs attention":ws.auto_drives?"Automatic setup pending":"Normal settings";
                p14::Status secure={};bool have_secure=p08::service->get_secure_status(secure);
                const char *https=ws.secure_setup_pending?"Importing setup":!have_secure?"Unavailable":secure.storage_blocked?"Storage blocked":
#if defined(P18_TLS) && P18_TLS
                    !secure.time_ready?"Waiting for time":!secure.provisioned?"Auto setup on first HTTPS":
#else
                    !secure.provisioned?"Setup required":!secure.time_ready?"Waiting for time":
#endif
                    !secure.entropy_ready?"Not ready":"Ready";
                p08::WifiBridgeSnapshot wifi_status={};
                // Reading status must not start a WLAN scan while a network
                // request is in flight. $11 explicitly refreshes this cache.
                p08::p12_wifi_snapshot(wifi_status);
                p17c::StatusView view={};view.network=network;view.state=p08::state_name(ws.state);
                view.program_pending=ws.program_pending;view.menu_paused=ws.menu_paused;
                view.drives=drives;view.https=https;view.https_error=have_secure?p14::result_name(secure.last_error):"UNAVAILABLE";
                view.flash=flash_state;view.flash_error=flash_error;view.last_error=ws.last_error;view.requests=ws.requests;
                p14::Result setup_result=p14::OK;if(p14::get_last_setup_result(setup_result))view.setup_result=p14::result_name(setup_result);
#if defined(P18_TLS) && P18_TLS
                p14::Result bootstrap_result=p14::OK;
                bool bootstrap_attempted=p14::get_last_bootstrap_result(bootstrap_result);
                if(bootstrap_attempted){
                    if(!view.setup_result)view.setup_result=p14::result_name(bootstrap_result);
                    if(have_secure&&secure.time_ready&&!secure.provisioned&&!secure.storage_blocked&&bootstrap_result!=p14::OK){
                        view.https="Auto setup failed";view.https_error=p14::result_name(bootstrap_result);
                    }
                }else if(have_secure&&!secure.provisioned&&!secure.storage_blocked&&secure.last_error==p14::UNSEEDED){
                    // An empty clean device is expected until its first HTTPS
                    // attempt. Real storage/clock/bootstrap failures stay visible.
                    view.https_error="";
                }
#endif
                view.rssi_known=wifi_status.rssi_known;view.rssi=wifi_status.rssi;view.rssi_age_ms=wifi_status.rssi_age_ms;
#if defined(P17F_CACHED_MATH) && P17F_CACHED_MATH
                if(cmd->functionID==MENU_P12_TLS_DETAILS){
                    p17f::CacheStatus math_cache={};p17f::get_math_cache_status(math_cache);
                    view.math_cache=p17f::math_cache_state_name(math_cache.state);
                }
#endif
                if(cmd->functionID==MENU_P12_DIAGNOSTICS||cmd->functionID==MENU_P12_TLS_DETAILS){
                    p08::RequestTrace trace={};p08::service->get_request_trace(trace);
                    if(cmd->functionID==MENU_P12_TLS_DETAILS)p17c::format_tls_details(text,sizeof(text),view,trace);
                    else p17c::format_diagnostics(text,sizeof(text),view,trace);
                }else p17c::format_status(text,sizeof(text),view);
                if(cmd->user_interface)cmd->user_interface->popup(text,BUTTON_OK);
                return SSRET_OK;
            }
            p08::Result queued=p08::BAD_STATE;
            if(cmd->functionID==MENU_P12_START)queued=p08::service->request_native_start();
            else if(cmd->functionID==MENU_P12_STOP)queued=p08::service->request_native_stop();
            else if(cmd->functionID==MENU_P12_PORTAL){
                if(cmd->user_interface&&cmd->user_interface->popup("Open portal and restart C64?",BUTTON_YES|BUTTON_NO)!=BUTTON_YES)return SSRET_ABORTED_BY_USER;
                queued=p08::service->request_portal();
            }
            else {
                p08::BackendSummary network={};p08::service->get_network_summary(network);
                queued=p08::service->request_network_preference(p17c::network_toggle_target(network));
            }
            if(queued!=p08::OK){if(cmd->user_interface)cmd->user_interface->popup(cmd->functionID==MENU_P12_CONNECTION&&queued==p08::BUSY?"Network busy.\nTry again shortly.":p08::result_name(queued),BUTTON_OK);return SSRET_NO_LOCK;}
            if(cmd->user_interface){
                if(cmd->functionID==MENU_P12_START||cmd->functionID==MENU_P12_PORTAL)cmd->user_interface->menu_response_to_action=MENU_HIDE;
                else cmd->user_interface->popup(cmd->functionID==MENU_P12_STOP?"WiC64 stop queued":"Connection change queued.\nWiC64 Status shows the active link.",BUTTON_OK);
            }
            return SSRET_OK;
        }
#endif
        case C64_PUSH_BUTTON:
            c64->setButtonPushed();
            break;
        case C64_UNFREEZE:
            if (c64->client) { // we can't execute this yet
                c64->client->release_host(); // disconnect from user interface
                c64->client = 0;
            }
            c64->unfreeze();
            break;
        case MENU_C64_RESET:
            if (c64->client) { // we can't execute this yet
                c64->client->release_host(); // disconnect from user interface
                c64->client = 0;
            }
            c64->unfreeze();
            c64->reset();
            break;

        case MENU_C64_PAUSE:
            // A frozen machine is stopped already, and unfreeze() needs the stop mode freeze() set.
            if (!c64->isFrozen) {
                c64->stop(false);
            }
            break;

        case MENU_C64_RESUME:
            // Only unfreeze() may release a machine the menu holds: its screen and cart are still in.
            if (!c64->isFrozen) {
                c64->resume();
            }
            break;

        case MENU_C64_CLEARMEM:
#if U64
            if (c64->client) { // we can't execute this yet
                c64->client->release_host(); // disconnect from user interface
                c64->client = 0;
            }
            c64->clear_ram();
            c64->start_cartridge(NULL);
            break;
#endif

        case MENU_C64_POWERCYCLE:
#if U64 == 2
            wifi_machine_reboot();
#else
            result = SSRET_NOT_IMPLEMENTED;
#endif
            break;
        case MENU_C64_POWEROFF:
#if U64 == 2
            wifi_machine_off();
#elif U64 == 1
            U64_POWER_REG = 0x2B;
            U64_POWER_REG = 0xB2;
            U64_POWER_REG = 0x2B;
            U64_POWER_REG = 0xB2;
#else
            result = SSRET_NOT_IMPLEMENTED;
#endif
            break;

        case MENU_C64_REBOOT:
            if (c64->client) { // we can't execute this yet
                c64->client->release_host(); // disconnect from user interface
                c64->client = 0;
            }
            c64->start_cartridge(NULL);
            break;

        case C64_START_CART:
            if (c64->client) { // we can't execute this yet
                c64->client->release_host(); // disconnect from user interface
                c64->client = 0;
            }
            c64->start_cartridge((cart_def *)cmd->mode);
            break;

        case MENU_C64_SAVEREU:
            ram_size = 128 * 1024;
            ram_size <<= c64->cfg->get_value(CFG_C64_REU_SIZE);

            if ((cmd->user_interface->string_box("Save REU memory as..", buffer, 22) > 0) && (*buffer)) {
                fix_filename(buffer);
                set_extension(buffer, ".reu", 32);

                res = create_file_ask_if_exists(fm, cmd->user_interface, cmd->path.c_str(), buffer, &f);
                if (res == FR_OK) {
                    printf("Opened file successfully.\n");

                    uint32_t reu_sizes[] =
                            { 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000, 0x1000000 };

                    uint32_t current_reu_size = reu_sizes[c64->cfg->get_value(CFG_C64_REU_SIZE)];
                    uint32_t sectors = (current_reu_size >> 9);
                    uint32_t secs_per_step = (sectors + 31) >> 5;
                    uint32_t bytes_per_step = secs_per_step << 9;
                    uint32_t bytes_written;
                    uint32_t remain = current_reu_size;
                    uint8_t *src;
                    transferred = 0;

                    cmd->user_interface->show_progress("Saving REU file..", 32);
                    src = (uint8_t *)REU_MEMORY_BASE;

                    while (remain != 0) {
                        f->write(src, bytes_per_step, &bytes_written);
                        transferred += bytes_written;
                        cmd->user_interface->update_progress(NULL, 1);
                        remain -= bytes_per_step;
                        src += bytes_per_step;
                    }
                    cmd->user_interface->hide_progress();

                    printf("written: %d...", transferred);
                    sprintf(buffer, "Bytes saved: %d ($%8x)", transferred, transferred);
                    cmd->user_interface->popup(buffer, BUTTON_OK);

                    fm->fclose(f);
                } else {
                    printf("Couldn't open file..\n");
                    cmd->user_interface->popup(FileSystem::get_error_string(res), BUTTON_OK);
                }
            }
            break;

        case MENU_U64_SAVERAM:
            ram_size = 64 * 1024;
            if ((cmd->user_interface->string_box("Save RAM as..", buffer, 22) > 0) && (*buffer)) {
                fix_filename(buffer);
                set_extension(buffer, ".bin", 32);

                res = create_file_ask_if_exists(fm, cmd->user_interface, cmd->path.c_str(), buffer, &f);
                if (res == FR_OK) {
                    printf("Opened file successfully.\n");

                    pb = new uint8_t[ram_size];
                    c64->get_all_memory(pb);

                    uint32_t bytes_written;
                    f->write(pb, ram_size, &bytes_written);

                    printf("written: %d...", bytes_written);
                    sprintf(buffer, "bytes saved: %d ($%8x)", bytes_written, bytes_written);
                    cmd->user_interface->popup(buffer, BUTTON_OK);

                    fm->fclose(f);
                    delete[] pb;
                } else {
                    printf("Couldn't open file..\n");
                    cmd->user_interface->popup(FileSystem::get_error_string(res), BUTTON_OK);
                }
            }
            break;

        case MENU_C64_SAVE_CARTRIDGE:
            buffer[0] = 0;
            if ((cmd->user_interface->string_box("Save Cartridge as..", buffer, 28) > 0) && (*buffer)) {
                fix_filename(buffer);
                set_extension(buffer, ".crt", 32);

                res = create_file_ask_if_exists(fm, cmd->user_interface, cmd->path.c_str(), buffer, &f);
                if (res == FR_OK) {
                    // Overlay and REST get here with the C64 running; stopped, the file is one image.
                    bool stopped = c64->begin_stopped_session();
                    SubsysResultCode_e retval = C64_CRT::save_crt(f);
                    c64->end_stopped_session(stopped);
                    fm->fclose(f);
                    if (retval != SSRET_OK) {
                        cmd->user_interface->popup(SubsysCommand::error_string(retval), BUTTON_OK);
                    }
                }
            }
            break;

        case MENU_C64_SAVEFLASH: // doesn't belong here, but i need it fast
            res = create_file_ask_if_exists(fm, cmd->user_interface, cmd->path.c_str(), "flash_dump.bin", &f);

            if (res == FR_OK) {
                int pages = c64->flash->get_number_of_pages();
                int page_size = c64->flash->get_page_size();
                uint8_t *page_buf = new uint8_t[page_size];
                for (int i = 0; i < pages; i++) {
                    c64->flash->read_page(i, page_buf);
                    f->write(page_buf, page_size, &transferred);
                }
                delete[] page_buf;
                fm->fclose(f);
            } else {
                printf("Couldn't open file..\n");
            }
            break;

        case MENU_MEASURE_TIMING:
            measure_timing(cmd->path.c_str());
            break;

        case MENU_MEASURE_TIMING_API:
            c64->measure_timing((uint8_t *)cmd->buffer);
            break;

        case C64_DMA_LOAD:
            res = fm->fopen(cmd->path.c_str(), cmd->filename.c_str(), FA_READ, &f);
            if (res == FR_OK) {
                char shown[52];
                const char *name = x00_load_name(f, cmd->filename.c_str(), shown, sizeof(shown));
                result=dma_result(dma_load(f, NULL, 0, name, cmd->mode, c64->cfg->get_value(CFG_C64_DMA_ID)));
                fm->fclose(f);
            } else {
                result = SSRET_CANNOT_OPEN_FILE;
            }
            break;

#ifndef RECOVERYAPP
#if U64 && P08_SERVICE
        case C64_DMA_LOAD_MNT:
        case p18mount::DMA_LOAD_MNT_B:
        {
            C1541 *drive=cmd->functionID==p18mount::DMA_LOAD_MNT_B?c1541_B:c1541_A;
            result=p18mount::check(drive);
            if(result!=SSRET_OK)break;
            res = fm->fopen(cmd->path.c_str(), cmd->filename.c_str(), FA_READ, &f);
            if (res == FR_OK) {
                char shown[52];
                const char *name = x00_load_name(f, cmd->filename.c_str(), shown, sizeof(shown));
                result=p18mount::check(drive);
                if(result==SSRET_OK)
                    result=dma_result(dma_load(f,NULL,0,name,uint8_t(cmd->mode),drive->get_current_iec_address()));
                fm->fclose(f);
            } else {
                result = SSRET_CANNOT_OPEN_FILE;
            }
            break;
        }
#else
        case C64_DMA_LOAD_MNT:
            res = fm->fopen(cmd->path.c_str(), cmd->filename.c_str(), FA_READ, &f);
            if (res == FR_OK) {
                char shown[52];
                const char *name = x00_load_name(f, cmd->filename.c_str(), shown, sizeof(shown));
                result=dma_result(dma_load(f, NULL, 0, name, cmd->mode, c1541_A->get_current_iec_address()));
                fm->fclose(f);
            } else {
                result = SSRET_CANNOT_OPEN_FILE;
            }
            break;
#endif
#endif
        case C64_DMA_LOAD_RAW:
            res = fm->fopen(cmd->path.c_str(), cmd->filename.c_str(), FA_READ, &f);
            if (res == FR_OK) {
                // A raw load has no name to print; the header is still skipped, because
                // the C64 file is what follows it.
                x00_skip_header(f, cmd->filename.c_str(), NULL);
                dma_load_raw(f);
                fm->fclose(f);
            } else {
                result = SSRET_CANNOT_OPEN_FILE;
            }
            break;
        case C64_DRIVE_LOAD:
#if U64 && P08_SERVICE
            if(cmd->mode&p18mount::RUN_TARGET_MASK){
                C1541 *drive=p18mount::run_target(cmd->mode);
                if(!drive){result=SSRET_INVALID_PARAMETER;break;}
                result=p18mount::check(drive);
                if(result!=SSRET_OK)break;
                const uint8_t address=drive->get_current_iec_address();
                if((cmd->path.c_str()[0]&0x1f)!=address){result=SSRET_NO_LOCK;break;}
                result=dma_result(dma_load(0,NULL,0,cmd->filename.c_str(),uint8_t(cmd->mode),address));
            } else
#endif
            result=dma_result(dma_load(0, NULL, 0, cmd->filename.c_str(), cmd->mode, cmd->path.c_str()[0] & 0x1F));
            if (cmd->user_interface) {
                cmd->user_interface->menu_response_to_action = result==SSRET_OK?MENU_HIDE:MENU_NOP;
            }
            break;
        case C64_DMA_BUFFER:
            result=dma_result(dma_load(0, (const uint8_t *)cmd->buffer, cmd->bufferSize, cmd->filename.c_str(), cmd->mode,
                    c64->cfg->get_value(CFG_C64_DMA_ID)));
            break;
        case C64_DMA_RAW_WRITE:
            dma_load_raw_buffer((uint16_t)cmd->mode, (uint8_t *)cmd->buffer, cmd->bufferSize, 0);
            break;
        case C64_DMA_RAW_READ:
            dma_load_raw_buffer((uint16_t)cmd->mode, (uint8_t *)cmd->buffer, cmd->bufferSize, 1);
            break;
        case C64_STOP_COMMAND:
            c64->stop(false);
            break;
        case MENU_C64_HARD_BOOT:
            c64->flash->reboot(0);
            break;
        case C64_READ_FLASH:
            switch (cmd->mode) {
                case FLASH_CMD_PAGESIZE:
                    *(int*)cmd->buffer = c64->flash->get_page_size();
                    break;
                case FLASH_CMD_NOPAGES:
                    *(int*)cmd->buffer = c64->flash->get_number_of_pages();
                    break;
                default:
                    if (cmd->bufferSize >= c64->flash->get_page_size())
                        c64->flash->read_page(cmd->mode - FLASH_CMD_GETPAGE, cmd->buffer);
            }
            break;
        case C64_SET_KERNAL:
            c64->enable_kernal((uint8_t*)cmd->buffer);
            // c64->reset();
            break;
        case MENU_C64_SAVE_MP3_DRV_A:
            case MENU_C64_SAVE_MP3_DRV_B:
            case MENU_C64_SAVE_MP3_DRV_C:
            case MENU_C64_SAVE_MP3_DRV_D:
            {
            int devNo = cmd->functionID - MENU_C64_SAVE_MP3_DRV_A;
            int ftype = C64::isMP3RamDrive(devNo);
            uint8_t* reu = (uint8_t *)(REU_MEMORY_BASE);
            int expSize = 1;
            const char* extension = 0;

            if (ftype == 1541) {
                expSize = 174848;
                extension = ".D64";
            }
            if (ftype == 1571) {
                expSize = 2 * 174848;
                extension = ".D71";
            }
            if (ftype == 1581) {
                expSize = 819200;
                extension = ".D81";
            }
            if (ftype == DRVTYPE_MP3_DNP) {
                expSize = C64::getSizeOfMP3NativeRamdrive(devNo);
                extension = ".DNP";
            }

            uint8_t ramBase = reu[0x7dc7 + devNo];
            uint8_t* srcAddr = reu + (((uint32_t)ramBase) << 16);

            if ((cmd->user_interface->string_box("Save RAMDISK as..", buffer, 22) > 0) && (*buffer)) {
                fix_filename(buffer);
                set_extension(buffer, extension, 32);

                res = create_file_ask_if_exists(fm, cmd->user_interface, cmd->path.c_str(), buffer, &f);
                if (res == FR_OK) {
                    printf("Opened file successfully.\n");
                    uint32_t bytes_written;

                    if (ftype == 1571) {
                        f->write(srcAddr, expSize / 2, &bytes_written);
                        uint32_t tmp;
                        f->write(srcAddr + 700 * 256, expSize / 2, &tmp);
                        bytes_written += tmp;
                    } else {
                        f->write(srcAddr, expSize, &bytes_written);
                    }
                    printf("written: %d...", bytes_written);
                    sprintf(buffer, "bytes saved: %d ($%8x)", bytes_written, bytes_written);
                    cmd->user_interface->popup(buffer, BUTTON_OK);

                    fm->fclose(f);
                } else {
                    printf("Couldn't open file..\n");
                    cmd->user_interface->popup(FileSystem::get_error_string(res), BUTTON_OK);
                }
            }
        }
            break;

        default:
            break;
    }

    return result;
}

int C64_Subsys :: dma_load_raw(File *f)
{
	bool i_stopped_it = false;
	if (c64->client) {
    	c64->client->release_host(); // disconnect from user interface
    	c64->release_ownership();
	}
	if(!c64->isFrozen) {
		c64->stop(false);
        C64_MODE = MODE_NORMAL;
		i_stopped_it = true;
	}
	int bytes = load_file_dma(f, 0);

	if (i_stopped_it) {
		c64->resume();
	}
	return bytes;
}

int C64_Subsys :: dma_load_raw_buffer(uint16_t offset, uint8_t *buffer, int length, int rw)
{
    bool i_stopped_it = false;
    if (c64->client && !c64->isFrozen) {
        c64->client->release_host(); // disconnect from user interface
        c64->release_ownership();
    }
    if(!c64->is_stopped()) {
        c64->stop(false);
        i_stopped_it = true;
    }

    if (c64->isFrozen) {
        // The freezer menu may have its own mode/cart banked in, so route through
        // dma_transfer_frozen, which restores the frozen C64 mode for ROM/cart
        // ranges instead of blindly bypassing to raw RAM.
        c64->dma_transfer_frozen(offset, buffer, length, rw);
    } else {
        volatile uint8_t *dest = (volatile uint8_t *)(C64_MEMORY_BASE + offset);

        if (rw) {
            memcpy(buffer, (void *)dest, length);
        } else {
            memcpy((void *)dest, buffer, length);
        }
    }

    if (i_stopped_it) {
        c64->resume();
    }
	return length;
}

int C64_Subsys :: dma_load(File *f, const uint8_t *buffer, const int bufferSize,
		const char *name, uint8_t run_code, uint8_t drv, uint16_t reloc, bool p12_portal)
{
#if U64 && P08_SERVICE
    // Ordinary PRG Run/Load uses the same controlled reset/resume boundary as
    // the native portal. Queue complete owned bytes before mutating the C64;
    // the service worker can then cancel/drain any old network operation.
    const uint8_t base_run_code=p18mount::base_run_code(run_code);
    bool direct=(base_run_code==RUNCODE_DMALOAD_RUN||base_run_code==RUNCODE_DMALOAD||
                 (base_run_code==RUNCODE_DMALOAD_JUMP&&!f));
    if(!p12_portal&&!reloc&&direct&&(f||buffer)&&p08::service){
        p08::Status state={};if(!p08::service->get_status(state))return -2;
        if(state.native_session&&(state.state==p08::ACTIVE||state.state==p08::STARTING)){
            uint8_t *file_data=0;const uint8_t *data=buffer;uint32_t size=bufferSize>0?uint32_t(bufferSize):0;
            if(f){
                file_data=static_cast<uint8_t *>(malloc(65539));if(!file_data)return -1;
                uint32_t total=0;
                while(total<65539){
                    uint32_t transferred=0;FRESULT read=f->read(file_data+total,65539-total,&transferred);
                    if(read!=FR_OK||transferred>65539-total){memset(file_data,0,total);free(file_data);return -1;}
                    total+=transferred;if(!transferred)break;
                }
                data=file_data;size=total;
            }
            p08::Result queued=p08::service->request_native_program(data,size,name,base_run_code,drv);
            if(file_data){memset(file_data,0,size);free(file_data);}
            return queued==p08::OK?0:queued==p08::BUSY?-2:-1;
        }
    }
#endif
	// prepare DMA load
    if(c64->client) { // we are locked by a client, likely: user interface
    	c64->client->release_host(); // disconnect from user interface
    	c64->client = 0;
	}
    if(!c64->isFrozen) {
    	c64->stop(false);
    }

    C64_POKE(C64_BOOTCRT_RUNCODE, run_code);

    C64_POKE(C64_BOOTCRT_DOSYNC, (c64->cfg->get_value(CFG_C64_DO_SYNC) == 1) ? 1 : 0);

    char trimmed_name[17];
    const char *display_name = format_bootcrt_display_name(name, trimmed_name);

    CbmFileName cbm;
    cbm.init(display_name);
    const char *p = cbm.getName();
    for(int i=0; i<16; i++) {
        C64_POKE(C64_BOOTCRT_NAME+i, p[i]);
    }
    C64_POKE(C64_BOOTCRT_NAMELEN, strlen(p));

    C64_POKE(C64_BOOTCRT_HANDSHAKE, 0x80); // initial boot cart handshake

    boot_cart.custom_addr = (void *)&_bootcrt_65_start;
    c64->start_cartridge(&boot_cart);

	// perform DMA load
    wait_ms(100);

	// handshake with boot cart
    c64->stop(false);

    C64_POKE(C64_BOOTCRT_DRIVENUM, drv);    // drive number for printout

	C64_POKE(C64_BOOTCRT_HANDSHAKE, 0x40);  // signal cart ready for DMA load

	if ( !(run_code & RUNCODE_REAL_BIT) ) {
        int timeout = 0;
        while(C64_PEEK(2) != 0x01) {
        	c64->resume();
            timeout++;
            if(timeout == 60) {
                c64->init_cartridge();
                return -1;
            }
            wait_ms(25);
            printf("_");
            c64->stop(false);
        }
        if (f) {
        	load_file_dma(f, 0);
        } else {
            // If we need to jump, the first two bytes are the jump address
            if (run_code & RUNCODE_JUMP_BIT) {
            	C64_POKE(C64_BOOTCRT_JUMPADDR, buffer[0]);
            	C64_POKE(C64_BOOTCRT_JUMPADDR+1, buffer[1]);
                if (bufferSize > 2) {
                    load_buffer_dma(buffer+2, bufferSize-2, 0);
                }
            } else {
            	load_buffer_dma(buffer, bufferSize, 0);
            }
        }

        C64_POKE(C64_BOOTCRT_HANDSHAKE, 0); // signal DMA load done
        C64_POKE(C64_BOOTCRT_RUNCODE, run_code);
        C64_POKE(0x00BA, drv);    // fix drive number
	}

#if U64 && P08_SERVICE
    if(p12_portal && (!p08::service||!p08::service->portal_prepare_resume())){
        c64->init_cartridge();return -1;
    }
#else
    (void)p12_portal;
#endif
	printf("Resuming..\n");
    c64->resume();

    restoreCart();
    return 0;
}

#if U64 && P08_SERVICE
int C64_Subsys::p12_launch_portal(const uint8_t *buffer,unsigned size)
{
    if(!buffer||size<3)return -1;
    if(!p08_try_lock())return -2;
    if(c64->isFrozen||p08::native_menu_held()){unlock();return -2;}
    p08::Service::portal_reset_scope(true);
    int result=dma_load(0,buffer,int(size),"WiC64 Portal",RUNCODE_DMALOAD_RUN,8,0,true);
    p08::Service::portal_reset_scope(false); // before releasing C64 ownership
    unlock();return result;
}
int C64_Subsys::p13a_launch_program(const uint8_t *buffer,unsigned size,const char *name,uint8_t mode,uint8_t drive)
{
    if(!buffer||size<3)return -1;
    if(!p08_try_lock())return -2;
    if(c64->isFrozen||p08::native_menu_held()){unlock();return -2;}
    p08::Service::portal_reset_scope(true);
    int result=dma_load(0,buffer,int(size),name,mode,drive,0,true);
    p08::Service::portal_reset_scope(false); // before releasing C64 ownership
    unlock();return result;
}
#endif

int C64_Subsys :: load_file_dma(File *f, uint16_t reloc)
{
	uint32_t dma_load_buffer[128];
    uint32_t transferred = 0;
    uint16_t load_address = 0;
    uint8_t  *dma_load_buffer_b;
    dma_load_buffer_b = (uint8_t *)dma_load_buffer;

    if (f) {
        f->read(&load_address, 2, &transferred);
        if(transferred != 2) {
            printf("Can't read from file..\n");
            return -1;
        }
        load_address = le2cpu(load_address); // make sure we can interpret the word correctly (endianness)
        printf("Load address: %4x...", load_address);
    }
    if(reloc) {
    	load_address = reloc;
    	printf(" -> %4x ..", load_address);
    }
    int max_length = 65536 - int(load_address); // never exceed $FFFF
    int block = 510;
    printf("Now loading...");
	volatile uint8_t *dest = (volatile uint8_t *)(C64_MEMORY_BASE + load_address);

	/* Now actually load the file */
	int total_trans = 0;
	while (max_length > 0) {
		FRESULT fres = f->read(dma_load_buffer, block, &transferred);
		if (fres != FR_OK) {
			printf("Error reading from file. %s\n", FileSystem :: get_error_string(fres));
			return -1;
		}
		//printf("[%d]", transferred);
		total_trans += transferred;
		volatile uint8_t *d = dest;
		for (int i=0;i<transferred;i++) {
			*(d++) = dma_load_buffer_b[i];
		}
		if (transferred < block) {
			break;
		}
		dest += transferred;
		max_length -= transferred;
		block = (max_length > 512) ? 512 : max_length;
	}
	uint16_t end_address = load_address + total_trans;
	printf("DMA load complete: $%4x-$%4x\n", load_address, end_address);

	// The following pokes are documented in the C64 documentation and are not
	// Ultimate specific.
	C64_POKE(0x002D, end_address);
	C64_POKE(0x002E, end_address >> 8);
	C64_POKE(0x002F, end_address);
	C64_POKE(0x0030, end_address >> 8);
	C64_POKE(0x0031, end_address);
	C64_POKE(0x0032, end_address >> 8);
	C64_POKE(0x00AE, end_address);
	C64_POKE(0x00AF, end_address >> 8);

	C64_POKE(0x0090, 0x40); // Load status
	C64_POKE(0x0035, 0);    // FRESPC
	C64_POKE(0x0036, 0xA0);

	return total_trans;
}

int C64_Subsys :: load_buffer_dma(const uint8_t *buffer, const int bufferSize, uint16_t reloc)
{
    if (!buffer || bufferSize < 2) {
        return 0;
    }
    uint16_t load_address = 0;

    load_address = (uint16_t)buffer[0] | ((uint16_t)buffer[1]) << 8;
	printf("Load address: %4x...", load_address);

	if (reloc) {
    	load_address = reloc;
    	printf(" -> %4x ..", load_address);
    }
	volatile uint8_t *dest = (volatile uint8_t *)(C64_MEMORY_BASE + load_address);

	memcpy((void *)dest, buffer + 2, bufferSize - 2);

	uint16_t end_address = load_address + bufferSize - 2;
	printf("DMA load complete: $%4x-$%4x\n", load_address, end_address);

    // The following pokes are documented in the C64 documentation and are not
    // Ultimate specific.
	C64_POKE(0x002D, end_address);
	C64_POKE(0x002E, end_address >> 8);
	C64_POKE(0x002F, end_address);
	C64_POKE(0x0030, end_address >> 8);
	C64_POKE(0x0031, end_address);
	C64_POKE(0x0032, end_address >> 8);
	C64_POKE(0x00AE, end_address);
	C64_POKE(0x00AF, end_address >> 8);

	C64_POKE(0x0090, 0x40); // Load status
	C64_POKE(0x0035, 0);    // FRESPC
	C64_POKE(0x0036, 0xA0);

	return bufferSize - 2;
}

bool C64_Subsys :: write_vic_state(File *f)
{
    uint32_t transferred;
    uint8_t mode = C64_MODE;
    C64_MODE = 0;

    // find bank
    uint8_t bank = 3 - (c64->cia_backup[1] & 0x03);
    uint32_t addr = C64_MEMORY_BASE + (uint32_t(bank) << 14);
    if(bank == 0) {
        f->write((uint8_t *)C64_MEMORY_BASE, 0x0400, &transferred);
        f->write(c64->screen_backup, 0x0400, &transferred);
        f->write(c64->ram_backup, 0x0800, &transferred);
        f->write((uint8_t *)(C64_MEMORY_BASE + 0x1000), 0x3000, &transferred);
    } else {
        f->write((uint8_t *)addr, 16384, &transferred);
    }
    f->write(c64->color_backup, 0x0400, &transferred);
    f->write(c64->vic_backup, NUM_VICREGS, &transferred);

    C64_MODE = mode;
    return true;
}

void C64_Subsys :: measure_timing(const char *path)
{
    uint8_t *buffer = new uint8_t[64 * 1024];

    c64->measure_timing(buffer);

    // write file
    mstring fn(path);
    fn += "bus_measurement.bin";
    FILE *fo = fopen(fn.c_str(), "wb");
    if (fo) {
        int t = fwrite(buffer, 2048, 32, fo);
        printf("%d blocks written.\n", t);
        fclose(fo);
    } else {
        printf("Couldn't open file %s\n", fn.c_str());
    }

    delete[] buffer;
}
