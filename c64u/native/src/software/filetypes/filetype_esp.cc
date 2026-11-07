/* P18 manual ESP application installer. GPL-3.0-or-later.
 * Based on Gideon Zweijtzer's FileTypeESP integration. This deliberately
 * accepts only the two reviewed application images, never arbitrary segments.
 */
#if U64 && P08_SERVICE && P18_TLS
#include "filetype_esp.h"
#include "filemanager.h"
#include "menu.h"
#include "userinterface.h"
#include "browsable_root.h"
#include "esp32.h"
#include "p08_service.h"
#include "p18m_esp_firmware.h"
#include "p18m_esp_resource.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wolfssl/wolfcrypt/hash.h>

#if C64U_ESP_MANUAL_INSTALL_ENABLED
FactoryRegistrator<BrowsableDirEntry *, FileType *> tester_esp(
    FileType::getFileTypeFactory(), FileTypeESP::test_type);
#endif

#define FLASH_ESP 0x8501

FileTypeESP::FileTypeESP(BrowsableDirEntry *entry):browsable(entry) {}
FileTypeESP::~FileTypeESP() {}

int FileTypeESP::fetch_context_items(IndexedList<Action *> &list)
{
#if !C64U_ESP_MANUAL_INSTALL_ENABLED
    (void)list;
    return 0;
#else
    list.append(new Action("Flash into ESP32",FileTypeESP::execute,FLASH_ESP));
    return 1;
#endif
}
FileType *FileTypeESP::test_type(BrowsableDirEntry *entry)
{
#if !C64U_ESP_MANUAL_INSTALL_ENABLED
    (void)entry;
    return 0;
#else
    FileInfo *info=entry?entry->getInfo():0;
    return info&&!strcasecmp(info->extension,"ESP")?new FileTypeESP(entry):0;
#endif
}

#if C64U_ESP_MANUAL_INSTALL_ENABLED
namespace {
const uint32_t APP_ADDRESS=0x10000,MAX_APP_BYTES=3*1024*1024;
#if !C64U_ESP_TLS_INSTALL
const uint8_t approved_sha256[2][32]={
    {0x8c,0x63,0xf6,0x51,0x75,0x19,0xcd,0xd1,0xe9,0x51,0x0f,0x6e,0x35,0xb3,0x30,0x3d,
     0x6f,0x55,0xcb,0x2e,0x50,0x27,0x7e,0x7d,0x63,0x1e,0x37,0x0b,0xb0,0xc9,0x77,0xab},
    {0x0d,0xc5,0x8d,0x29,0x8b,0x80,0xf7,0x55,0xe5,0x82,0xea,0xfb,0xca,0xbe,0x48,0xd2,
     0x06,0x19,0xa9,0xc1,0x70,0x1f,0x76,0x16,0xe7,0x0f,0xa0,0x0c,0x20,0x86,0xea,0x12}
};
#endif
struct Image {
    uint8_t *bytes;uint32_t length;unsigned approved;
    Image():bytes(0),length(0),approved(0) {}
    ~Image(){free(bytes);}
};
struct OpenFile {
    FileManager *manager;File *file;
    explicit OpenFile(FileManager *fm):manager(fm),file(0) {}
    ~OpenFile(){if(file)manager->fclose(file);}
};
uint32_t le32(const uint8_t *p)
{return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
bool read_exact(File *file,uint8_t *bytes,uint32_t length)
{
    while(length){
        uint32_t count=length>65536?65536:length,got=0;
        if(file->read(bytes,count,&got)!=FR_OK||!got||got>count)return false;
        bytes+=got;length-=got;
    }
    return true;
}
bool service_idle()
{
    if(!p08::service)return false;
    p08::Status status={};
    if(!p08::service->get_status(status))return false;
    return (status.state==p08::SERVICE_IDLE||
        (status.state==p08::RESTORED&&status.restore==p08::RESTORE_OK))&&
        !status.portal_pending&&!status.program_pending&&!status.secure_setup_pending;
}
SubsysResultCode_e load_image(SubsysCommand *cmd,Image &image,const char *&message)
{
    FileManager *manager=FileManager::getFileManager();
    if(!manager){message="File manager unavailable.";return SSRET_INTERNAL_ERROR;}
    OpenFile opened(manager);
    if(manager->fopen(cmd->path.c_str(),cmd->filename.c_str(),FA_READ,&opened.file)!=FR_OK||!opened.file){
        message="Could not open ESP image.";return SSRET_CANNOT_OPEN_FILE;
    }
    const uint32_t size=opened.file->get_size();uint8_t header[12];
    if(size<36||size>MAX_APP_BYTES+12){message="Invalid ESP image size.";return SSRET_ERROR_IN_FILE_FORMAT;}
    if(!read_exact(opened.file,header,sizeof(header))){message="Could not read ESP header.";return SSRET_FILE_READ_FAILED;}
    image.length=le32(header+4);
    if(memcmp(header,"SEGM",4)||le32(header+8)!=APP_ADDRESS||
       image.length<24||image.length>MAX_APP_BYTES||image.length!=size-12){
        message="Invalid ESP application segment.";return SSRET_ERROR_IN_FILE_FORMAT;
    }
    image.bytes=static_cast<uint8_t *>(malloc(image.length));
    if(!image.bytes){message="Not enough memory for ESP image.";return SSRET_OUT_OF_MEMORY;}
    if(!read_exact(opened.file,image.bytes,image.length)){
        message="Could not read complete ESP image.";return SSRET_FILE_READ_FAILED;
    }
    uint8_t extra=0;uint32_t got=0;
    if(opened.file->read(&extra,1,&got)!=FR_OK||got){
        message="ESP image has trailing data.";return SSRET_ERROR_IN_FILE_FORMAT;
    }
    if(image.bytes[0]!=0xe9||image.bytes[12]!=9||image.bytes[13]!=0){
        message="ESP image is not for ESP32-S3.";return SSRET_ERROR_IN_FILE_FORMAT;
    }
    uint8_t digest[32];
    if(wc_Sha256Hash(image.bytes,image.length,digest)!=0){
        message="ESP image verification failed.";return SSRET_INTERNAL_ERROR;
    }
#if C64U_ESP_TLS_INSTALL
    image.approved=c64u_esp_app_approval(digest,image.length);
#else
    for(unsigned i=0;i<2;++i)if(!memcmp(digest,approved_sha256[i],sizeof(digest))){image.approved=i+1;break;}
#endif
    if(!image.approved){message="ESP image is not an approved\nP18 file.";return SSRET_ERROR_IN_FILE_FORMAT;}
    return SSRET_OK;
}
struct MaintenanceLease {
    ~MaintenanceLease(){p08::Service::end_esp_maintenance();}
};
}
#endif

SubsysResultCode_e FileTypeESP::execute(SubsysCommand *cmd)
{
    if(!cmd||cmd->functionID!=FLASH_ESP)return SSRET_INVALID_PARAMETER;
#if !C64U_ESP_MANUAL_INSTALL_ENABLED
    if(cmd->user_interface)cmd->user_interface->popup("ESP installation is disabled.",BUTTON_OK);
    return SSRET_NOT_IMPLEMENTED;
#else
    if(!cmd->user_interface)return SSRET_NO_USER_INTERFACE;
    UserInterface *ui=cmd->user_interface;
    if(!service_idle()){
        ui->popup("Stop WiC64 before installing\nESP firmware.",BUTTON_OK);return SSRET_NO_LOCK;
    }
#if defined(P18M_ESP_BUNDLE) && P18M_ESP_BUNDLE
    p18m_esp_resource_discard();
#endif
    Image image;const char *message=0;
    SubsysResultCode_e result=load_image(cmd,image,message);
    if(result!=SSRET_OK){ui->popup(message,BUTTON_OK);return result;}
    if(!service_idle()){
        ui->popup("WiC64 is busy.\nESP firmware was not changed.",BUTTON_OK);return SSRET_NO_LOCK;
    }
    const char *question=image.approved==1?
        "Install P18 ESP TLS application?\nThis writes the WLAN module flash.":
#if C64U_ESP_TLS_INSTALL
        "Install ESP return app 1.11?\nThis writes the WLAN module flash.";
#else
        "Restore original ESP\napplication 1.21?\nThis writes the WLAN module flash.";
#endif
    if(ui->popup(question,BUTTON_YES|BUTTON_NO)!=BUTTON_YES)return SSRET_ABORTED_BY_USER;
    // Atomically reserve quiescence after the potentially long confirmation.
    // New API starts and worker network refreshes stay blocked until restart.
    // The validated, owned image is not reopened after consent.
    if(!p08::Service::begin_esp_maintenance()){
        ui->popup("WiC64 is busy.\nESP firmware was not changed.",BUTTON_OK);return SSRET_NO_LOCK;
    }
    int status;
    {
        MaintenanceLease maintenance;
        status=p18m_esp::flash_application(ui,image.bytes,image.length);
    }
#if C64U_ESP_TLS_INSTALL
    if(status==C64U_ESP_INSTALL_IDENTITY_REJECTED){
        ui->popup("ESP 1.11 identity not confirmed.\nESP firmware was not changed.",BUTTON_OK);
        return SSRET_NOT_IMPLEMENTED;
    }
#endif
    if(status){ui->popup("ESP installation failed.\nModule restarted.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
    ui->popup("ESP application installed.\nModule restarted.",BUTTON_OK);
    return SSRET_OK;
#endif
}
#endif
