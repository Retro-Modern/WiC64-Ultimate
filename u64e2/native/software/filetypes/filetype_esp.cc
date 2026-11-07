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
#include "p18m_esp_image.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>

FactoryRegistrator<BrowsableDirEntry *, FileType *> tester_esp(
    FileType::getFileTypeFactory(), FileTypeESP::test_type);

#define FLASH_ESP 0x8501

FileTypeESP::FileTypeESP(BrowsableDirEntry *entry):browsable(entry) {}
FileTypeESP::~FileTypeESP() {}

int FileTypeESP::fetch_context_items(IndexedList<Action *> &list)
{
    list.append(new Action("Flash into ESP32",FileTypeESP::execute,FLASH_ESP));
    return 1;
}
FileType *FileTypeESP::test_type(BrowsableDirEntry *entry)
{
    FileInfo *info=entry?entry->getInfo():0;
    return info&&!strcasecmp(info->extension,"ESP")?new FileTypeESP(entry):0;
}

namespace {
const uint32_t APP_ADDRESS=0x10000,MAX_APP_BYTES=3*1024*1024;
const uint8_t approved_sha256[2][32]={
    {P18M_ESP_IMAGE_SHA256},
    {0x0d,0xc5,0x8d,0x29,0x8b,0x80,0xf7,0x55,0xe5,0x82,0xea,0xfb,0xca,0xbe,0x48,0xd2,
     0x06,0x19,0xa9,0xc1,0x70,0x1f,0x76,0x16,0xe7,0x0f,0xa0,0x0c,0x20,0x86,0xea,0x12}
};
// SHA-256 runs at only ~25 KB/s on the U64 CPU (about 40 s per image), so
// the image is hashed once: read completely into RAM, verified, then flashed
// from RAM. Only if that allocation fails, the streaming path below hashes
// each block again while flashing.
struct Image {
    uint8_t *block_digests,*bytes;uint32_t length,block_count;unsigned approved;
    Image():block_digests(0),bytes(0),length(0),block_count(0),approved(0) {}
    ~Image(){free(block_digests);free(bytes);}
    Image(const Image &)=delete;
    Image &operator=(const Image &)=delete;
};
// Read the file in large pieces: 1 KB reads cost one USB command each and made
// the check take over a minute. Digests stay per FLASH_BLOCK_BYTES block.
const uint32_t READ_BYTES=64*1024;
static_assert(READ_BYTES%Esp32::FLASH_BLOCK_BYTES==0,"read size must hold whole blocks");
struct Buffer {
    uint8_t *bytes;
    Buffer():bytes(static_cast<uint8_t *>(malloc(READ_BYTES))) {}
    ~Buffer(){free(bytes);}
    Buffer(const Buffer &)=delete;
    Buffer &operator=(const Buffer &)=delete;
};
struct Progress {
    UserInterface *ui;
    Progress(UserInterface *user,const char *text,int steps):ui(user){if(ui)ui->show_progress(text,steps);}
    ~Progress(){if(ui)ui->hide_progress();}
    void step(){if(ui)ui->update_progress(NULL,1);}
};
struct HashState {
    wc_Sha256 state;bool ready;
    HashState():ready(wc_InitSha256(&state)==0) {}
    ~HashState(){if(ready)wc_Sha256Free(&state);}
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
    image.block_count=(image.length+Esp32::FLASH_BLOCK_BYTES-1)/Esp32::FLASH_BLOCK_BYTES;
    image.bytes=static_cast<uint8_t *>(malloc(image.length));
    if(!image.bytes)image.block_digests=static_cast<uint8_t *>(malloc(image.block_count*32));
    Buffer buffer;HashState sha;
    if((!image.bytes&&(!image.block_digests||!buffer.bytes))||!sha.ready){
        message="Not enough memory for ESP verification.";return SSRET_OUT_OF_MEMORY;
    }
    Progress progress(cmd->user_interface,"Checking ESP image",(image.length+READ_BYTES-1)/READ_BYTES);
    for(uint32_t done=0;done<image.length;){
        const uint32_t now=image.length-done>READ_BYTES?READ_BYTES:image.length-done;
        uint8_t *piece=image.bytes?image.bytes+done:buffer.bytes;
        if(!read_exact(opened.file,piece,now)){
            message="Could not read complete ESP image.";return SSRET_FILE_READ_FAILED;
        }
        if(!done&&(piece[0]!=0xe9||piece[12]!=9||piece[13]!=0)){
            message="ESP image is not for ESP32-S3.";return SSRET_ERROR_IN_FILE_FORMAT;
        }
        // The full-image whitelist authenticates this in-memory digest table.
        if(wc_Sha256Update(&sha.state,piece,now)!=0){
            message="ESP image verification failed.";return SSRET_INTERNAL_ERROR;
        }
        for(uint32_t offset=0;!image.bytes&&offset<now;offset+=Esp32::FLASH_BLOCK_BYTES){
            const uint32_t part=now-offset>Esp32::FLASH_BLOCK_BYTES?Esp32::FLASH_BLOCK_BYTES:now-offset;
            if(wc_Sha256Hash(piece+offset,part,
                   image.block_digests+((done+offset)/Esp32::FLASH_BLOCK_BYTES)*32)!=0){
                message="ESP image verification failed.";return SSRET_INTERNAL_ERROR;
            }
        }
        done+=now;
        progress.step();
    }
    uint8_t extra=0;uint32_t got=0;
    if(opened.file->read(&extra,1,&got)!=FR_OK||got){
        message="ESP image has trailing data.";return SSRET_ERROR_IN_FILE_FORMAT;
    }
    uint8_t digest[32];
    if(wc_Sha256Final(&sha.state,digest)!=0){
        message="ESP image verification failed.";return SSRET_INTERNAL_ERROR;
    }
    for(unsigned i=0;i<2;++i)if(!memcmp(digest,approved_sha256[i],sizeof(digest))){image.approved=i+1;break;}
    if(!image.approved){message="ESP image is not an approved\nP18 file.";return SSRET_ERROR_IN_FILE_FORMAT;}
    return SSRET_OK;
}
struct Stream {
    File *file;const Image &image;uint32_t next;const char *message;
    Buffer buffer;uint32_t buffer_start,buffer_length;
    Stream(File *f,const Image &validated):file(f),image(validated),next(0),message(0),
        buffer_start(0),buffer_length(0) {}
};
bool read_stream(void *context,uint8_t *dest,uint32_t offset,uint32_t length)
{
    Stream *stream=static_cast<Stream *>(context);
    const Image &image=stream->image;
    if(stream->message||!image.approved||!image.block_digests||offset!=stream->next||
       offset>=image.length||offset%Esp32::FLASH_BLOCK_BYTES||
       offset/Esp32::FLASH_BLOCK_BYTES>=image.block_count||
       length!=(image.length-offset>Esp32::FLASH_BLOCK_BYTES?
           Esp32::FLASH_BLOCK_BYTES:image.length-offset)){
        stream->message="ESP verification state invalid.";return false;
    }
    // Requests are sequential (offset==next), so a refill always starts at the
    // end of the previous piece. Each block is still checked after copying.
    if(offset>=stream->buffer_start+stream->buffer_length){
        const uint32_t want=image.length-offset>READ_BYTES?READ_BYTES:image.length-offset;
        if(!stream->buffer.bytes||!read_exact(stream->file,stream->buffer.bytes,want)){
            stream->message="Could not read ESP image.";return false;
        }
        stream->buffer_start=offset;stream->buffer_length=want;
    }
    memcpy(dest,stream->buffer.bytes+(offset-stream->buffer_start),length);
    uint8_t digest[32];
    if(wc_Sha256Hash(dest,length,digest)!=0){
        stream->message="ESP block verification failed.";return false;
    }
    if(memcmp(digest,image.block_digests+(offset/Esp32::FLASH_BLOCK_BYTES)*32,32)){
        stream->message="ESP image changed.\nInstallation stopped.";return false;
    }
    stream->next+=length;
    return true;
}
struct MaintenanceLease {
    ~MaintenanceLease(){p08::Service::end_esp_maintenance();}
};
}

SubsysResultCode_e FileTypeESP::execute(SubsysCommand *cmd)
{
    if(!cmd||cmd->functionID!=FLASH_ESP)return SSRET_INVALID_PARAMETER;
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
        "Restore original ESP\napplication 1.21?\nThis writes the WLAN module flash.";
    if(ui->popup(question,BUTTON_YES|BUTTON_NO)!=BUTTON_YES)return SSRET_ABORTED_BY_USER;
    if(image.bytes){
        // Verified bytes are already in RAM; the file is not read again.
        if(!p08::Service::begin_esp_maintenance()){
            ui->popup("WiC64 is busy.\nESP firmware was not changed.",BUTTON_OK);return SSRET_NO_LOCK;
        }
        int status;
        {
            MaintenanceLease maintenance;
            status=p18m_esp::flash_application(ui,image.bytes,image.length);
        }
        if(status){ui->popup("ESP installation failed.\nModule restarted.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
        ui->popup("ESP application installed.\nModule restarted.",BUTTON_OK);
        return SSRET_OK;
    }
    // Atomically reserve quiescence after the potentially long confirmation.
    // New API starts and worker network refreshes stay blocked until restart.
    // Reopened source bytes must match the authenticated table before sending.
    OpenFile opened(FileManager::getFileManager());
    if(!opened.manager){ui->popup("File manager unavailable.",BUTTON_OK);return SSRET_INTERNAL_ERROR;}
    if(opened.manager->fopen(cmd->path.c_str(),cmd->filename.c_str(),FA_READ,&opened.file)!=FR_OK||!opened.file){
        ui->popup("Could not open ESP image.\nESP firmware was not changed.",BUTTON_OK);return SSRET_CANNOT_OPEN_FILE;
    }
    uint8_t header[12];
    if(opened.file->get_size()!=image.length+12||!read_exact(opened.file,header,sizeof(header))||
       memcmp(header,"SEGM",4)||le32(header+4)!=image.length||le32(header+8)!=APP_ADDRESS){
        ui->popup("ESP image changed.\nESP firmware was not changed.",BUTTON_OK);return SSRET_ERROR_IN_FILE_FORMAT;
    }
    Stream stream(opened.file,image);
    if(!stream.buffer.bytes){ui->popup("Not enough memory for ESP installation.\nESP firmware was not changed.",BUTTON_OK);return SSRET_OUT_OF_MEMORY;}
    if(!p08::Service::begin_esp_maintenance()){
        ui->popup("WiC64 is busy.\nESP firmware was not changed.",BUTTON_OK);return SSRET_NO_LOCK;
    }
    int status;
    {
        MaintenanceLease maintenance;
        status=p18m_esp::flash_application_from(ui,read_stream,&stream,image.length);
    }
    if(status){
        ui->popup(stream.message?stream.message:"ESP installation failed.\nModule restarted.",BUTTON_OK);
        return SSRET_INTERNAL_ERROR;
    }
    ui->popup("ESP application installed.\nModule restarted.",BUTTON_OK);
    return SSRET_OK;
}
#endif
