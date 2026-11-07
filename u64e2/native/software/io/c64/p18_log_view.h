#ifndef P18_WIC64_LOG_VIEW_H
#define P18_WIC64_LOG_VIEW_H
#include "p18_log.h"
#include "p18_log_access.h"
#include "userinterface.h"
#include "subsys.h"

namespace p18logview {
/* The native menu only controls capture and shows connection instructions.
 * Event output belongs to the browser and dedicated PuTTY log stream. Keep
 * this static Action callback outside the C64 subsystem mutex and ABI.
 */
inline SubsysResultCode_e open(SubsysCommand *command)
{
    if(!command||!command->user_interface)return SSRET_NO_USER_INTERFACE;
    UserInterface *ui=command->user_interface;
    if(!ui->host||!ui->host->exists()||!ui->get_screen()||!ui->get_keyboard())return SSRET_NO_USER_INTERFACE;
    const char *notice="";
    while(ui->host->exists()){
        int result=p18logaccess::settings(ui,(unsigned)p18log::level(),p18log::previews_enabled(),notice);
        // A menu-button close or disconnected remote session must not change
        // capture settings or open another popup.
        if(!ui->host->exists()||result<=0||result==1)break;
        if(result==2){
            p18log::Level next=(p18log::Level)((unsigned(p18log::level())+1)%4);
            notice=p18log::configure(next)?"Capture level changed":"Log busy; try again";
        }else if(result==4){
            notice=p18log::configure_previews(!p18log::previews_enabled())?"Hex/ASCII setting changed":"Log busy; try again";
        }else if(result==8){
            notice=p18log::clear()?"Log cleared":"Log busy; try again";
        }else break;
    }
    return SSRET_OK;
}
}
#endif
