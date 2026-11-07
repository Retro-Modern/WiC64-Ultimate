#include "p64_ordering.h"
/* One-shot optional ESP application offer before a GUI WiC64 launch.
 * GPL-3.0-or-later. No headless caller can confirm or flash this resource.
 */
#if U64 && P08_SERVICE && P18_TLS
#include "p18m_esp_firmware.h"
#include "p18m_esp_resource.h"
#include "p08_service.h"
#include "p18_tls_rpc.h"
#include "p18_tls_wire.h"
#if defined(C64U_ESP_PERSIST) && C64U_ESP_PERSIST
#include "p21_store_client.h"
#endif
#include "wifi_cmd.h"
#include "esp32.h"
#include "userinterface.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/hash.h>

namespace p18m_esp {
namespace {
alignas(4) static uint32_t identity_generation=1;
alignas(4) static uint32_t identity_version=0;
uint32_t generation()
{return p64_ordering::load(&identity_generation,__ATOMIC_ACQUIRE);}
#if C64U_ESP_TLS_INSTALL
const uint32_t image_hash_chunk=32768;
unsigned image_hash_steps(uint32_t length)
{return length/image_hash_chunk+(length%image_hash_chunk!=0);}
bool hash_application(UserInterface *ui,const uint8_t *bytes,uint32_t length,uint8_t digest[32])
{
    if(!ui||!bytes||!digest||length>C64U_ESP_FACTORY_APP_BYTES)return false;
    wc_Sha256 hash={};
    int result=wc_InitSha256(&hash);
    const bool initialized=result==0;
    for(uint32_t offset=0;!result&&offset<length;){
        const uint32_t remaining=length-offset;
        const uint32_t count=remaining<image_hash_chunk?remaining:image_hash_chunk;
        result=wc_Sha256Update(&hash,bytes+offset,count);
        if(!result){offset+=count;ui->update_progress(NULL,1);}
    }
    if(!result)result=wc_Sha256Final(&hash,digest);
    if(initialized)wc_Sha256Free(&hash);
    if(result){volatile uint8_t *wipe=digest;for(unsigned i=0;i<32;++i)wipe[i]=0;}
    return result==0;
}
bool compatible_live_app()
{
    const uint32_t before=generation();
    uint16_t major=0,minor=0;char name[64]={0};
    // This bounded IDENTIFY checks the live module, after GUI consent and while
    // the caller holds maintenance. Neither an absent reply nor a lifecycle
    // change permits stopping or replacing an unknown controller application.
    return read_identity(&major,&minor,name,sizeof(name),250) &&
           generation()==before && major==1 && minor==11 &&
           (!strcmp(name,"ESP32 WiFi Bridge V1.11") ||
            !strcmp(name,"ESP32 WiFi Bridge V1.11 C64U TLS"));
}
struct InstallProgress {
    UserInterface *ui;
    InstallProgress(UserInterface *user,uint32_t length):ui(user)
    {ui->show_progress("Checking ESP image",int((length+1023)/1024+image_hash_steps(length))+3);}
    ~InstallProgress(){ui->hide_progress();}
    void step(const char *message,int steps){ui->update_progress(message,steps);}
};
#endif
#if C64U_ESP_BUNDLE_OFFER_ENABLED || C64U_ESP_RETURN_APP
#if C64U_ESP_TLS_INSTALL
alignas(4) static uint32_t launch_offer_attempted=0;
bool claim_launch_offer()
{
    ENTER_SAFE_SECTION;
    const bool attempted=p64_ordering::load(&launch_offer_attempted,__ATOMIC_ACQUIRE)!=0;
    if(!attempted)p64_ordering::store(&launch_offer_attempted,1U,__ATOMIC_RELEASE);
    LEAVE_SAFE_SECTION;
    return !attempted;
}
#endif
struct OwnedResource {
    uint8_t *bytes;
    explicit OwnedResource(uint8_t *p):bytes(p){}
    ~OwnedResource(){free(bytes);}
    OwnedResource(const OwnedResource &)=delete;
    OwnedResource &operator=(const OwnedResource &)=delete;
};
struct MaintenanceLease {
    bool held;
    MaintenanceLease():held(p08::Service::begin_esp_maintenance()){}
    ~MaintenanceLease(){if(held)p08::Service::end_esp_maintenance();}
};
struct CheckProgress {
    UserInterface *ui;
    CheckProgress(UserInterface *user,int steps):ui(user)
    {ui->show_progress("Checking ESP firmware",steps);}
    ~CheckProgress(){hide();}
    void hide(){if(ui){ui->hide_progress();ui=0;}}
};
enum Compatibility {UNKNOWN,COMPATIBLE,OLD_STOCK,OLD_TLS,NEWER,OTHER_FIRMWARE};
bool upgrade_needed(Compatibility state){return state==OLD_STOCK||state==OLD_TLS;}
#if defined(C64U_ESP_PERSIST) && C64U_ESP_PERSIST
const int probe_steps=4;
#else
const int probe_steps=3;
#endif
Compatibility probe_trusted_ca(CheckProgress &progress,uint32_t before,uint32_t version)
{
    progress.ui->update_progress("Checking trusted CA support",0);
    uint8_t frame[P18_TLS_HEADER+8]={0};uint16_t reply=0;
    p18_envelope(frame,P18_TLS_CAPS,0,0,P18_TLS_CA_QUERY,0);
    const int result=p18_tls_rpc_exchange(frame,P18_TLS_HEADER,sizeof(frame),&reply,100);
    progress.ui->update_progress(NULL,1);
    if(generation()!=before||p64_ordering::load(&identity_version,__ATOMIC_ACQUIRE)!=version||
       result||!p18_magic(frame)||frame[8]!=P18_TLS_VERSION||
       p18_get64(frame+12)||p18_get32(frame+20)||p18_get32(frame+24))return UNKNOWN;
    // Only an explicit rejection from the already identified TLS app proves
    // that its application needs replacing. Missing or malformed replies do not.
    if(reply==P18_TLS_HEADER&&frame[9]==P18_TLS_BAD&&!p18_get16(frame+10))return OLD_TLS;
    const uint32_t required=P18_TLS_CAP_FEATURES|P18_TLS_CAP_OPERATION_WINDOWS|P18_TLS_CAP_TRUSTED_CA;
    return reply==sizeof(frame)&&frame[9]==P18_TLS_OK&&p18_get16(frame+10)==8&&
        p18_get32(frame+P18_TLS_HEADER)==required&&
        p18_get16(frame+P18_TLS_HEADER+4)==P18_TLS_CHUNK&&
        !p18_get16(frame+P18_TLS_HEADER+6)?COMPATIBLE:UNKNOWN;
}
Compatibility probe(CheckProgress &progress)
{
    const uint32_t before=generation();
    uint16_t major=0,minor=0;char name[64]={0};
    if(!read_identity(&major,&minor,name,sizeof(name),250)||!major||generation()!=before)return UNKNOWN;
    note_identified(major,minor,name);
#if C64U_ESP_TLS_INSTALL
    if(major>1||(major==1&&minor>11))return NEWER;
    if(major!=1||minor!=11)return OTHER_FIRMWARE;
    const bool stock_name=!strcmp(name,"ESP32 WiFi Bridge V1.11");
    const bool tls_name=!strcmp(name,"ESP32 WiFi Bridge V1.11 C64U TLS");
    if(!stock_name&&!tls_name)return OTHER_FIRMWARE;
#endif
    progress.ui->update_progress("Checking HTTPS support",1);
    uint8_t frame[P18_TLS_HEADER+8]={0};uint16_t reply=0;
    p18_envelope(frame,P18_TLS_CAPS,0,0,P18_TLS_OPERATION_QUERY,0);
    const int result=p18_tls_rpc_exchange(frame,P18_TLS_HEADER,sizeof(frame),&reply,100);
    progress.ui->update_progress(NULL,1);
    if(generation()!=before||p64_ordering::load(&identity_version,__ATOMIC_ACQUIRE)!=
       ((uint32_t(major)<<16)|minor))return UNKNOWN;
    if(result==0&&reply==sizeof(frame)&&p18_magic(frame)&&frame[8]==P18_TLS_VERSION&&
       frame[9]==P18_TLS_OK&&p18_get16(frame+10)==8&&!p18_get64(frame+12)&&
       !p18_get32(frame+20)&&!p18_get32(frame+24)&&
       p18_get16(frame+P18_TLS_HEADER+4)==P18_TLS_CHUNK&&
       !p18_get16(frame+P18_TLS_HEADER+6)){
        const uint32_t required=P18_TLS_CAP_FEATURES|P18_TLS_CAP_OPERATION_WINDOWS;
#if C64U_ESP_TLS_INSTALL
        if(tls_name&&p18_get32(frame+P18_TLS_HEADER)==required){
#if defined(C64U_ESP_PERSIST) && C64U_ESP_PERSIST
            progress.ui->update_progress("Checking ESP storage support",0);
            const int store=p21_store::probe(100);
            progress.ui->update_progress(NULL,1);
            if(generation()!=before||p64_ordering::load(&identity_version,__ATOMIC_ACQUIRE)!=
               ((uint32_t(major)<<16)|minor))return UNKNOWN;
            if(store==0)return probe_trusted_ca(progress,before,(uint32_t(major)<<16)|minor);
            // Only an explicit NOT_SUPPORTED from the reviewed old TLS app
            // identifies an upgrade candidate. Timeout/malformed is unknown.
            return store==-2?OLD_TLS:UNKNOWN;
#else
            return probe_trusted_ca(progress,before,(uint32_t(major)<<16)|minor);
#endif
        }
#else
        if((p18_get32(frame+P18_TLS_HEADER)&required)==required)
            return probe_trusted_ca(progress,before,(uint32_t(major)<<16)|minor);
#endif
    }
    // Lost, truncated, or malformed replies do not prove a firmware mismatch.
    // Only the stock dispatcher's explicit NOT_SUPPORTED reply can offer the
    // bundled application, and never over a numerically newer application.
#if C64U_ESP_TLS_INSTALL
    if(result!=-2)return UNKNOWN;
    return stock_name?OLD_STOCK:OTHER_FIRMWARE;
#else
    if(major>1||(major==1&&minor>21))return NEWER;
    if(result!=-2)return UNKNOWN;
    char stock[64];
    snprintf(stock,sizeof(stock),"ESP32 WiFi Bridge V%u.%u",unsigned(major),unsigned(minor));
    return !strcmp(name,stock)?OLD_STOCK:OTHER_FIRMWARE;
#endif
}
bool valid_resource(const uint8_t *bytes,uint32_t length,UserInterface *ui=0)
{
#if C64U_ESP_TLS_INSTALL
    uint8_t digest[32];
    return length==C64U_ESP_TLS_APP_BYTES && c64u_esp_app_image_ok(bytes,length) &&
        hash_application(ui,bytes,length,digest) && c64u_esp_app_approval(digest,length)==1;
#else
    (void)ui;
    static const uint8_t digest_expected[32]={
        0x8c,0x63,0xf6,0x51,0x75,0x19,0xcd,0xd1,0xe9,0x51,0x0f,0x6e,0x35,0xb3,0x30,0x3d,
        0x6f,0x55,0xcb,0x2e,0x50,0x27,0x7e,0x7d,0x63,0x1e,0x37,0x0b,0xb0,0xc9,0x77,0xab};
    if(!bytes||length!=1043088||bytes[0]!=0xe9||bytes[12]!=9||bytes[13]!=0)return false;
    uint8_t digest[32];
    return wc_Sha256Hash(bytes,length,digest)==0&&!memcmp(digest,digest_expected,sizeof(digest));
#endif
}
void explain_probe(UserInterface *ui,Compatibility state)
{
    if(state==NEWER)ui->popup("Newer ESP firmware detected.\nBundled ESP update skipped.",BUTTON_OK);
    else if(state==OTHER_FIRMWARE)ui->popup("ESP firmware not recognized.\nBundled ESP update skipped.",BUTTON_OK);
    else {
#if C64U_ESP_TLS_INSTALL
        ui->popup("ESP check unavailable.\nHTTPS could not be confirmed.\nNo ESP firmware was changed.",BUTTON_OK);
#else
        ui->popup("ESP check unavailable.\nWiC64 uses the existing firmware.",BUTTON_OK);
#endif
    }
}
#endif
}

void note_reset()
{
    // RV32IM has no atomic RMW. The short single-core critical section uses
    // only aligned word loads/stores and is never held over a UART operation.
    ENTER_SAFE_SECTION;
    uint32_t next=generation()+1;
    p64_ordering::store(&identity_generation,next?next:1,__ATOMIC_RELEASE);
    p64_ordering::store(&identity_version,0,__ATOMIC_RELEASE);
    LEAVE_SAFE_SECTION;
}
uint32_t module_generation()
{
    return generation();
}
void note_identified(uint16_t major,uint16_t minor,const char *name)
{
    p64_ordering::store(&identity_version,major&&name&&*name?(uint32_t(major)<<16)|minor:0,__ATOMIC_RELEASE);
}

// P18M_FLASH_BEGIN
int flash_application(UserInterface *ui,const uint8_t *bytes,uint32_t length)
{
#if !C64U_ESP_MANUAL_INSTALL_ENABLED
    // Direct callers must also be refused before stopping the existing module.
    (void)ui;(void)bytes;(void)length;
    return -1;
#else
#if C64U_ESP_TLS_INSTALL
    if(!ui||(length!=C64U_ESP_TLS_APP_BYTES&&length!=C64U_ESP_RETURN_APP_BYTES)||
       !c64u_esp_app_image_ok(bytes,length))return -1;
    // Paint before hashing or the live identity wait. This progress remains
    // visible through ROM-loader connection, writes and module recovery.
    InstallProgress progress(ui,length);
    uint8_t digest[32];
    if(!hash_application(ui,bytes,length,digest))return -1;
    const unsigned approval=c64u_esp_app_approval(digest,length);
    if(!approval || (C64U_ESP_RETURN_APP && approval!=2))return -1;
    progress.step("Checking ESP identity",1);
    if(!compatible_live_app())return C64U_ESP_INSTALL_IDENTITY_REJECTED;
    progress.step("Connecting ESP loader",1);
#endif
    struct RunRecovery {
        UserInterface *ui;
        ~RunRecovery(){
#if C64U_ESP_TLS_INSTALL
            ui->update_progress("Restarting ESP module",0);
#endif
            esp32.EnableRunMode();esp32.StartApp();
        }
    } recovery={ui};
    note_reset();
    esp32.StopApp();
    int status=esp32.Download();
    if(!status){
#if C64U_ESP_TLS_INSTALL
        progress.step("Installing ESP application",1);
#else
        ui->show_progress("Installing ESP application",(length+1023)/1024);
#endif
        status=esp32.Flash(bytes,0x10000,length,[](void *user){
            static_cast<UserInterface *>(user)->update_progress(NULL,1);
        },ui);
#if !C64U_ESP_TLS_INSTALL
        ui->hide_progress();
#endif
    }
    return status;
#endif
}
// P18M_FLASH_END

SubsysResultCode_e restore_stock_application(UserInterface *ui)
{
#if C64U_ESP_RETURN_APP
    if(!ui)return SSRET_INVALID_PARAMETER;
    // Acquire quiescence before taking the one owned embedded image. A busy
    // service leaves it available for the next explicit F5 attempt.
    MaintenanceLease lease;
    if(!lease.held){ui->popup("WiC64 is busy.\nTry the return action again.",BUTTON_OK);return SSRET_NO_LOCK;}
    OwnedResource image(p18m_esp_resource_take());
    const uint32_t length=p18m_esp_resource_length();
    if(!image.bytes){ui->popup("Return image unavailable.\nReload this return application.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
    bool valid=false,known=false;
    {
        InstallProgress progress(ui,length);
        uint8_t digest[32]={0};
        valid=length==C64U_ESP_RETURN_APP_BYTES &&
            c64u_esp_app_image_ok(image.bytes,length) &&
            hash_application(ui,image.bytes,length,digest) &&
            c64u_esp_app_approval(digest,length)==2;
        if(valid){progress.step("Checking ESP identity",1);known=compatible_live_app();}
    }
    if(!valid){ui->popup("Return image is invalid.\nESP firmware was not changed.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
    if(!known){ui->popup("Known ESP 1.11 not confirmed.\nNo ESP firmware was changed.\nReload this app to try again.",BUTTON_OK);return SSRET_NOT_IMPLEMENTED;}
    if(ui->popup("Install ESP return app 1.11?\nThis writes the WLAN module flash.\nWiC64 HTTPS and storage stop.",BUTTON_YES|BUTTON_NO)!=BUTTON_YES){
        ui->popup("ESP return cancelled.\nNo ESP firmware was changed.\nReload this app to offer again.",BUTTON_OK);
        return SSRET_ABORTED_BY_USER;
    }
    // flash_application repeats the exact digest and fresh live identity after
    // consent; only then may StopApp/ROM download occur. The lease spans both.
    const int status=flash_application(ui,image.bytes,length);
    if(status==C64U_ESP_INSTALL_IDENTITY_REJECTED){ui->popup("ESP identity changed.\nNo ESP firmware was changed.",BUTTON_OK);return SSRET_NOT_IMPLEMENTED;}
    if(status){ui->popup("ESP return failed.\nTransfer not completed.\nReload this app to try again.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
    ui->popup("ESP return transfer completed.\nPower off/on to use Stock.\nNo C64U firmware was installed.",BUTTON_OK);
    return SSRET_OK;
#else
    (void)ui;return SSRET_NOT_IMPLEMENTED;
#endif
}

SubsysResultCode_e prepare_launch(UserInterface *ui)
{
#if C64U_ESP_BUNDLE_OFFER_ENABLED
    if(!ui)return SSRET_OK;
#if C64U_ESP_TLS_INSTALL
    // The resource is consumed once. A later ordinary Start/Portal action must
    // not report the already-released image as a new resource failure.
    if(p64_ordering::load(&launch_offer_attempted,__ATOMIC_ACQUIRE))return SSRET_OK;
    OwnedResource image(0);
#else
    OwnedResource image(p18m_esp_resource_take());
    if(!image.bytes)return SSRET_OK;
#endif
    const uint32_t length=p18m_esp_resource_length();
    Compatibility state;
    {
        CheckProgress progress(ui,probe_steps);
        MaintenanceLease lease;
        if(!lease.held){progress.hide();ui->popup("WiC64 is busy.\nTry starting again.",BUTTON_OK);return SSRET_NO_LOCK;}
#if C64U_ESP_TLS_INSTALL
        // A busy service has consumed neither the one-shot check nor its image.
        if(!claim_launch_offer())return SSRET_OK;
#endif
        state=probe(progress);
#if C64U_ESP_TLS_INSTALL
        // Probe even when a manual/headless start already discarded the image:
        // an already-compatible ESP then needs no resource and no warning.
        image.bytes=p18m_esp_resource_take();
#endif
    }
    if(state==COMPATIBLE)return SSRET_OK;
    if(!upgrade_needed(state)){explain_probe(ui,state);return SSRET_OK;}
#if C64U_ESP_TLS_INSTALL
    if(!image.bytes){
        ui->popup("Bundled ESP image unavailable.\nUse the manual ESP installer.\nNo ESP firmware was changed.",BUTTON_OK);
        return SSRET_OK;
    }
#endif
    if(ui->popup(state==OLD_TLS?
        "ESP application update required.\nInstall bundled ESP application?\nThis writes the WLAN module flash.":
        "ESP TLS support is missing.\nInstall bundled ESP application?\nThis writes the WLAN module flash.",BUTTON_YES|BUTTON_NO)!=BUTTON_YES)
    {
#if C64U_ESP_TLS_INSTALL
        ui->popup(state==OLD_TLS?
            "ESP update skipped.\nThe existing ESP application\nremains installed.":
            "ESP update skipped.\nHTTPS remains unavailable.\nHTTP can still be used.",BUTTON_OK);
#else
        ui->popup("ESP HTTPS support not enabled.\nHTTP remains available.\nHTTPS/TLS may be slow or fail.",BUTTON_OK);
#endif
        return SSRET_OK;
    }
    int status=0;
    bool valid=true;
    {
        // Confirmation can take arbitrarily long. Reacquire quiescence and
        // reread both live identity and capabilities before any module stop.
        CheckProgress progress(ui,
#if C64U_ESP_TLS_INSTALL
            int(image_hash_steps(length))+probe_steps
#else
            3
#endif
        );
        MaintenanceLease lease;
        if(!lease.held){
            progress.hide();
#if C64U_ESP_TLS_INSTALL
            ui->popup("WiC64 became busy.\nESP firmware was not changed.\nReload this app to offer again.",BUTTON_OK);
#else
            ui->popup("WiC64 is busy.\nESP firmware was not changed.",BUTTON_OK);
#endif
            return SSRET_NO_LOCK;
        }
        state=probe(progress);
        if(upgrade_needed(state)){
            progress.ui->update_progress("Checking ESP image",0);
            valid=valid_resource(image.bytes,length,progress.ui);
#if !C64U_ESP_TLS_INSTALL
            progress.ui->update_progress(NULL,1);
#endif
            progress.hide();
            if(valid)status=flash_application(ui,image.bytes,length);
        }
    }
    if(state==COMPATIBLE)return SSRET_OK;
    if(!upgrade_needed(state)){explain_probe(ui,state);return SSRET_OK;}
    if(!valid){ui->popup("Bundled ESP image is invalid.\nESP firmware was not changed.",BUTTON_OK);return SSRET_OK;}
#if C64U_ESP_TLS_INSTALL
    if(status==C64U_ESP_INSTALL_IDENTITY_REJECTED){
        ui->popup("ESP 1.11 identity not confirmed.\nESP firmware was not changed.",BUTTON_OK);
        return SSRET_NOT_IMPLEMENTED;
    }
#endif
    if(status){ui->popup("ESP installation failed.\nTransfer not completed.\nReload this app to try again.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
    // A ROM-loader acknowledgement does not prove that the new application
    // has initialized. A later launch uses its normal fresh module startup.
    ui->popup("ESP application installed.\nStart WiC64 again after\nthe WLAN module initializes.",BUTTON_OK);
    return SSRET_ABORTED_BY_USER;
#else
    (void)ui;return SSRET_OK;
#endif
}
}
#endif
