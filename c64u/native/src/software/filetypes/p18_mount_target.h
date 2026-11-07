#ifndef P18_NATIVE_MOUNT_TARGET_H
#define P18_NATIVE_MOUNT_TARGET_H
#if U64 && P08_SERVICE
#include "c1541.h"
#include "c64.h"
#include "p08_service.h"
#include "subsys.h"

namespace p18mount {
enum { DEFAULT_TARGET=0, EXPLICIT_B=1, DMA_LOAD_MNT_B=0x646b,
       RUN_TARGET_A=0x100, RUN_TARGET_B=0x200, RUN_TARGET_MASK=0x300 };
inline C1541 *target(bool explicit_b=false)
{
    return explicit_b||p08::native_drive_a_reserved()?c1541_B:c1541_A;
}
inline SubsysResultCode_e check(C1541 *drive)
{
    if(!drive)return SSRET_SUBSYS_NOT_PRESENT;
    return drive==c1541_A&&p08::native_drive_a_reserved()?SSRET_NO_LOCK:SSRET_OK;
}
inline int run_mode(C1541 *drive,int mode)
{
    return mode|(drive==c1541_B?RUN_TARGET_B:RUN_TARGET_A);
}
inline C1541 *run_target(int mode)
{
    return (mode&RUN_TARGET_MASK)==RUN_TARGET_B?c1541_B:
           (mode&RUN_TARGET_MASK)==RUN_TARGET_A?c1541_A:0;
}
inline uint8_t base_run_code(uint8_t mode)
{
    return uint8_t(mode&~RUNCODE_MOUNT_BIT);
}
inline SubsysResultCode_e mount_default(SubsysCommand *command)
{
    C1541 *drive=target();SubsysResultCode_e ready=check(drive);
    if(ready!=SSRET_OK)return ready;
    SubsysCommand *mount=new SubsysCommand(command->user_interface,drive->getID(),
        command->functionID,command->mode,command->path.c_str(),command->filename.c_str());
    return mount->execute().status;
}
}
#endif
#endif
