/* Local, explicitly selected WiC64 HTTPS setup import. GPL-3.0-or-later. */
#if U64 && P08_SERVICE && P14_TLS
#include "filetype_wic64.h"
#include "filemanager.h"
#include "menu.h"
#include "subsys.h"
#include "userinterface.h"
#include "p08_service.h"
#include "p14_platform.h"
#include <strings.h>

FactoryRegistrator<BrowsableDirEntry *, FileType *> tester_wic64(
    FileType::getFileTypeFactory(), FileTypeWiC64::test_type);

int FileTypeWiC64::fetch_context_items(IndexedList<Action *> &list)
{
    list.append(new Action("Set up WiC64 HTTPS",FileTypeWiC64::execute_st,0,0));
    return 1;
}
FileType *FileTypeWiC64::test_type(BrowsableDirEntry *entry)
{
    FileInfo *info=entry->getInfo();
    return info&&!strcasecmp(info->extension,"W64")?new FileTypeWiC64(entry):0;
}
static void wipe_setup(uint8_t *bytes,unsigned length)
{ volatile uint8_t *p=bytes;while(length--)*p++=0; }
SubsysResultCode_e FileTypeWiC64::execute_st(SubsysCommand *cmd)
{
    if(!p08::service)return SSRET_SUBSYS_NOT_PRESENT;
    FileManager *manager=FileManager::getFileManager();File *file=0;
    if(manager->fopen(cmd->path.c_str(),cmd->filename.c_str(),FA_READ,&file)!=FR_OK||!file)
        return SSRET_CANNOT_OPEN_FILE;
    // One extra byte makes a truncated/oversized setup an error rather than a
    // silent partial import. A successful short read is not assumed to be EOF.
    uint8_t bytes[p14::SETUP_BYTES+1]={};uint32_t used=0;bool valid=true;
    while(used<sizeof(bytes)){
        uint32_t got=0;FRESULT read=file->read(bytes+used,sizeof(bytes)-used,&got);
        if(read!=FR_OK||got>sizeof(bytes)-used){valid=false;break;}
        used+=got;if(!got)break;
    }
    manager->fclose(file);
    p08::Result result=valid&&used==p14::SETUP_BYTES?
        p08::service->request_secure_setup(bytes,used):p08::BAD_PARAMETER;
    wipe_setup(bytes,sizeof(bytes));
    if(result!=p08::OK)return result==p08::BUSY?SSRET_NO_LOCK:SSRET_INVALID_PARAMETER;
    if(cmd->user_interface){
        cmd->user_interface->menu_response_to_action=MENU_NOP;
        cmd->user_interface->popup("HTTPS setup queued.\nCheck WiC64 Status.\nKeep the setup file private.",BUTTON_OK);
    }
    return SSRET_OK;
}
#endif
