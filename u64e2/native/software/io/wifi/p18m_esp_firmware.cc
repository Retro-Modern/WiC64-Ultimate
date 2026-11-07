/* One-shot optional ESP application offer before a GUI WiC64 launch.
 * GPL-3.0-or-later. No headless caller can confirm or flash this resource.
 */
#if U64 && P08_SERVICE && P18_TLS
#include "p18m_esp_firmware.h"
#include "p18m_esp_resource.h"
#include "p18m_esp_image.h"
#include "p08_service.h"
#include "p18_tls_rpc.h"
#include "p18_tls_wire.h"
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
{return __atomic_load_n(&identity_generation,__ATOMIC_ACQUIRE);}
#if defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
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
enum Compatibility {UNKNOWN,COMPATIBLE,OLD_STOCK,OLD_P18,NEWER,OTHER_FIRMWARE};
Compatibility probe(CheckProgress &progress)
{
    const uint32_t before=generation();
    uint16_t major=0,minor=0;char name[64]={0};
    if(!read_identity(&major,&minor,name,sizeof(name),250)||!major||generation()!=before)return UNKNOWN;
    note_identified(major,minor,name);
    progress.ui->update_progress("Checking HTTPS support",1);
    uint8_t frame[P18_TLS_HEADER+8]={0};uint16_t reply=0;
    p18_envelope(frame,P18_TLS_CAPS,0,0,P18_TLS_OPERATION_QUERY,0);
    const int result=p18_tls_rpc_exchange(frame,P18_TLS_HEADER,sizeof(frame),&reply,100);
    progress.ui->update_progress(NULL,1);
    if(generation()!=before||__atomic_load_n(&identity_version,__ATOMIC_ACQUIRE)!=
       ((uint32_t(major)<<16)|minor))return UNKNOWN;
    if(result==0&&reply==sizeof(frame)&&p18_magic(frame)&&frame[8]==P18_TLS_VERSION&&
       frame[9]==P18_TLS_OK&&p18_get16(frame+10)==8&&!p18_get64(frame+12)&&
       !p18_get32(frame+20)&&!p18_get32(frame+24)&&
       p18_get16(frame+P18_TLS_HEADER+4)==P18_TLS_CHUNK&&
       !p18_get16(frame+P18_TLS_HEADER+6)){
        const uint32_t required=P18_TLS_CAP_FEATURES|P18_TLS_CAP_OPERATION_WINDOWS;
        if((p18_get32(frame+P18_TLS_HEADER)&required)==required){
            if(major>1||(major==1&&minor>21))return NEWER;
            if(major==1&&minor==21){
                if(!strcmp(name,"ESP32 WiFi Bridge V1.21 P18 TLS U64E2 B5RM1"))return COMPATIBLE;
                // Earlier P18 apps: Beta 4 bundle, Beta 5 bundle, Retro-Modern RM1.
                if(!strcmp(name,"ESP32 WiFi Bridge V1.21 P18 TLS")||
                   !strcmp(name,"ESP32 WiFi Bridge V1.21 P18 TLS U64E2 B5")||
                   !strcmp(name,"ESP32 WiFi Bridge V1.21 P18 TLS RM1"))return OLD_P18;
            }
            return OTHER_FIRMWARE;
        }
    }
    // Lost, truncated, or malformed replies do not prove a firmware mismatch.
    // Without valid capabilities, only an explicit stock NOT_SUPPORTED reply
    // can offer the bundle, never over a numerically newer application.
    if(major>1||(major==1&&minor>21))return NEWER;
    if(result!=-2)return UNKNOWN;
    char stock[64];
    snprintf(stock,sizeof(stock),"ESP32 WiFi Bridge V%u.%u",unsigned(major),unsigned(minor));
    return !strcmp(name,stock)?OLD_STOCK:OTHER_FIRMWARE;
}
bool valid_resource(const uint8_t *bytes,uint32_t length)
{
    static const uint8_t digest_expected[32]={P18M_ESP_IMAGE_SHA256};
    if(!bytes||length!=P18M_ESP_IMAGE_BYTES||length<24||bytes[0]!=0xe9||bytes[12]!=9||bytes[13]!=0)return false;
    uint8_t digest[32];
    return wc_Sha256Hash(bytes,length,digest)==0&&!memcmp(digest,digest_expected,sizeof(digest));
}
void explain_probe(UserInterface *ui,Compatibility state)
{
    if(state==NEWER)ui->popup("Newer ESP firmware detected.\nBundled ESP update skipped.",BUTTON_OK);
    else if(state==OTHER_FIRMWARE)ui->popup("ESP firmware not recognized.\nBundled ESP update skipped.",BUTTON_OK);
    else ui->popup("ESP check unavailable.\nWiC64 uses the existing firmware.",BUTTON_OK);
}
#endif
}

void note_reset()
{
    // RV32IM has no atomic RMW. The short single-core critical section uses
    // only aligned word loads/stores and is never held over a UART operation.
    ENTER_SAFE_SECTION;
    uint32_t next=generation()+1;
    __atomic_store_n(&identity_generation,next?next:1,__ATOMIC_RELEASE);
    __atomic_store_n(&identity_version,0,__ATOMIC_RELEASE);
    LEAVE_SAFE_SECTION;
}
void note_identified(uint16_t major,uint16_t minor,const char *name)
{
    __atomic_store_n(&identity_version,major&&name&&*name?(uint32_t(major)<<16)|minor:0,__ATOMIC_RELEASE);
}

// P18M_FLASH_BEGIN
namespace {
bool read_application_memory(void *context,uint8_t *dest,uint32_t offset,uint32_t length)
{memcpy(dest,static_cast<const uint8_t *>(context)+offset,length);return true;}
}
int flash_application(UserInterface *ui,const uint8_t *bytes,uint32_t length)
{
    if(!bytes)return -8;
    return flash_application_from(ui,read_application_memory,const_cast<uint8_t *>(bytes),length);
}
int flash_application_from(UserInterface *ui,FlashRead read,void *read_context,uint32_t length)
{
    if(!ui||!read||length<24||length>3*1024*1024)return -8;
    struct RunRecovery {
        ~RunRecovery(){esp32.EnableRunMode();esp32.StartApp();}
    } recovery;
    note_reset();
    esp32.StopApp();
    int status=esp32.Download();
    if(!status){
        ui->show_progress("Installing ESP application",(length+1023)/1024);
        status=esp32.FlashFrom(read,read_context,0x10000,length,[](void *user){
            static_cast<UserInterface *>(user)->update_progress(NULL,1);
        },ui);
        ui->hide_progress();
    }
    return status;
}
// P18M_FLASH_END

SubsysResultCode_e prepare_launch(UserInterface *ui)
{
#if defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
    if(!ui)return SSRET_OK;
    OwnedResource image(p18m_esp_resource_take());
    if(!image.bytes)return SSRET_OK;
    const uint32_t length=p18m_esp_resource_length();
    Compatibility state;
    {
        CheckProgress progress(ui,2);
        MaintenanceLease lease;
        if(!lease.held){progress.hide();ui->popup("WiC64 is busy.\nTry starting again.",BUTTON_OK);return SSRET_NO_LOCK;}
        state=probe(progress);
    }
    if(state==COMPATIBLE)return SSRET_OK;
    if(state!=OLD_STOCK&&state!=OLD_P18){explain_probe(ui,state);return SSRET_OK;}
    const char *question=state==OLD_P18?
        "Update ESP TLS application?\nThis writes the WLAN module flash.":
        "ESP TLS support is missing.\nInstall bundled ESP application?\nThis writes the WLAN module flash.";
    if(ui->popup(question,BUTTON_YES|BUTTON_NO)!=BUTTON_YES)
    {
        if(state==OLD_STOCK)
            ui->popup("ESP HTTPS support not enabled.\nHTTP remains available.\nHTTPS/TLS may be slow or fail.",BUTTON_OK);
        return SSRET_OK;
    }
    int status=0;
    bool valid=true;
    {
        // Confirmation can take arbitrarily long. Reacquire quiescence and
        // reread both live identity and capabilities before any module stop.
        CheckProgress progress(ui,3);
        MaintenanceLease lease;
        if(!lease.held){progress.hide();ui->popup("WiC64 is busy.\nESP firmware was not changed.",BUTTON_OK);return SSRET_NO_LOCK;}
        state=probe(progress);
        if(state==OLD_STOCK||state==OLD_P18){
            progress.ui->update_progress("Checking ESP image",0);
            valid=valid_resource(image.bytes,length);
            progress.ui->update_progress(NULL,1);
            progress.hide();
            if(valid)status=flash_application(ui,image.bytes,length);
        }
    }
    if(state==COMPATIBLE)return SSRET_OK;
    if(state!=OLD_STOCK&&state!=OLD_P18){explain_probe(ui,state);return SSRET_OK;}
    if(!valid){ui->popup("Bundled ESP image is invalid.\nESP firmware was not changed.",BUTTON_OK);return SSRET_OK;}
    if(status){ui->popup("ESP installation failed.\nModule restarted.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
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
