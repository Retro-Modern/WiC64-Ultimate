/*
 * filetype_prg.cc
 *
 * Written by 
 *    Gideon Zweijtzer <info@1541ultimate.net>
 *    Daniel Kahlin <daniel@kahlin.net>
 *
 *  This file is part of the 1541 Ultimate-II application.
 *  Copyright (C) 200?-2011 Gideon Zweijtzer <info@1541ultimate.net>
 *  Copyright (C) 2011 Daniel Kahlin <daniel@kahlin.net>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "filetype_prg.h"
#include "directory.h"
#include "filemanager.h"
#include "c1541.h"
#if U64 && P08_SERVICE
#include "p18_mount_target.h"
#endif
#include "c64.h"
#include <ctype.h>

/* Drives to mount on */
extern C1541 *c1541_A;

// tester instance
FactoryRegistrator<BrowsableDirEntry *, FileType *> tester_prg(FileType :: getFileTypeFactory(), FileTypePRG :: test_type);

/*********************************************************************/
/* PRG File Browser Handling                                         */
/*********************************************************************/
#define PRGFILE_RUN       0x2201
#define PRGFILE_LOAD      0x2202
#define PRGFILE_DMAONLY   0x2205
#define PRGFILE_MOUNT_RUN 0x2203
#define PRGFILE_MOUNT_REAL_RUN 0x2204
#if U64 && P08_SERVICE
#define PRGFILE_MOUNT_RUN_B 0x2206
#define PRGFILE_MOUNT_REAL_RUN_B 0x2207
#endif

FileTypePRG :: FileTypePRG(BrowsableDirEntry *n, bool hdr)
{
    node = n;
    has_header = hdr;
}

FileTypePRG :: ~FileTypePRG()
{
}

int FileTypePRG::fetch_context_items(IndexedList<Action *> &list)
{
    int mode = (has_header) ? 1 : 0;

    int count = 0;
    C64 *machine = C64::getMachine();
#if U64 && P08_SERVICE
    if (!machine || !machine->exists()) {
#else
    if (!machine->exists()) {
#endif
        return 0;
    }

    list.append(new Action("Run", FileTypePRG::execute_st, PRGFILE_RUN, mode));
    list.append(new Action("Load", FileTypePRG::execute_st, PRGFILE_LOAD, mode));
    list.append(new Action("DMA", FileTypePRG::execute_st, PRGFILE_DMAONLY, mode));
    count += 3;

#if U64 && P08_SERVICE
    if (!p18mount::target())
        return count;
#else
    if (!c1541_A)
        return count;
#endif

    BrowsableDirEntry *parentEntry = (BrowsableDirEntry *)(node->getParent());
    FileInfo *parentInfo = parentEntry->getInfo();

    int image = 0;
    if (strcasecmp("D64", parentInfo->extension) == 0) {
        image = 1541;
    } else if (strcasecmp("D71", parentInfo->extension) == 0) {
        image = 1571;
    } else if (strcasecmp("D81", parentInfo->extension) == 0) {
        image = 1581;
    }

    if (image) {
#if U64 && P08_SERVICE
        const bool on_b=p08::native_drive_a_reserved();
        list.append(new Action(on_b?"Mount & Run on B":"Mount & Run",FileTypePRG::execute_st,
            on_b?PRGFILE_MOUNT_RUN_B:PRGFILE_MOUNT_RUN,image));
        count++;
        list.append(new Action(on_b?"Real Run on B":"Real Run",FileTypePRG::execute_st,
            on_b?PRGFILE_MOUNT_REAL_RUN_B:PRGFILE_MOUNT_REAL_RUN,image));
        count++;
#else
        // This file is inside a disk image, and the mode carries the image type.
        list.append(new Action("Mount & Run", FileTypePRG::execute_st, PRGFILE_MOUNT_RUN, image));
        count++;
        list.append(new Action("Real Run", FileTypePRG::execute_st, PRGFILE_MOUNT_REAL_RUN, image));
        count++;
#endif
    }
    return count;
}

// static member
FileType *FileTypePRG :: test_type(BrowsableDirEntry *obj)
{
	FileInfo *inf = obj->getInfo();
    if(strcmp(inf->extension, "PRG")==0)
        return new FileTypePRG(obj, false);
    if(inf->extension[0] == 'P') {
        if(isdigit(inf->extension[1]) && isdigit(inf->extension[2])) {
            return new FileTypePRG(obj, true);
        }
    }
    return NULL;
}

bool FileTypePRG :: check_header(File *f, bool has_header)
{
    static char p00_header[0x1A]; 

    if(!has_header)
        return true;
    uint32_t bytes_read;
    FRESULT res = f->read(p00_header, 0x1A, &bytes_read);
    if(res != FR_OK || bytes_read != sizeof(p00_header))
        return false;
    if(strncmp(p00_header, "C64File", 7))
        return false;
    return true;        
}

SubsysResultCode_e FileTypePRG :: execute_st(SubsysCommand *cmd)
{
	printf("PRG Select: %4x\n", cmd->functionID);
	File *file = 0;
	SubsysCommand *drive_command;
	SubsysCommand *c64_command;
	
    int run_code = -1;
    int menu_action = MENU_HIDE;

	switch(cmd->functionID) {
	case PRGFILE_RUN:
        run_code = RUNCODE_DMALOAD_RUN;
        break;
    case PRGFILE_LOAD:
        run_code = RUNCODE_DMALOAD;
        break;
#if U64 && P08_SERVICE
    case PRGFILE_MOUNT_RUN_B:
#endif
    case PRGFILE_MOUNT_RUN:
        run_code = RUNCODE_MOUNT_DMALOAD_RUN;
        break;
#if U64 && P08_SERVICE
    case PRGFILE_MOUNT_REAL_RUN_B:
#endif
    case PRGFILE_MOUNT_REAL_RUN:
        run_code = RUNCODE_MOUNT_LOAD_RUN;
        break;
    case PRGFILE_DMAONLY:
    	run_code = 0;
        menu_action = MENU_NOP;
    	break;
    default:
        return SSRET_UNDEFINED_COMMAND;
    }

    const char *name = cmd->filename.c_str();
    printf("DMA Load.. %s\n", name);
    FileManager *fm = FileManager :: getFileManager();
    FRESULT fres = fm->fopen(cmd->path.c_str(), name, FA_READ, &file);
    if (file) {
        bool header_ok = check_header(file, (cmd->mode == 1));
        fm->fclose(file);
        file = NULL;
        if (!header_ok) {
            printf("Header of P00 file not correct.\n");
            return SSRET_ERROR_IN_FILE_FORMAT;
        }

        if (run_code & RUNCODE_MOUNT_BIT) {
            printf("Runcode mount bit set. trying to find mount point '%s' resulted: ", cmd->path.c_str());
            FileInfo info(32);
            fres = fm->fstat(cmd->path.c_str(), info);
            printf("%s\n", FileSystem::get_error_string(fres));

#if U64 && P08_SERVICE
            const bool explicit_b=cmd->functionID==PRGFILE_MOUNT_RUN_B||cmd->functionID==PRGFILE_MOUNT_REAL_RUN_B;
            C1541 *drive=p18mount::target(explicit_b);
            SubsysResultCode_e ready=p18mount::check(drive);
            if(ready!=SSRET_OK)return ready;
            drive_command = new SubsysCommand(cmd->user_interface,drive->getID(),MENU_1541_MOUNT_D64,cmd->mode,0,cmd->path.c_str());
            SubsysResultCode_e mounted=drive_command->execute().status;
            if(mounted!=SSRET_OK)return mounted;
            ready=p18mount::check(drive);
            if(ready!=SSRET_OK)return ready;
            c64_command = new SubsysCommand(cmd->user_interface,SUBSYSID_C64,
                drive==c1541_B?p18mount::DMA_LOAD_MNT_B:C64_DMA_LOAD_MNT,run_code,cmd->path.c_str(),cmd->filename.c_str());
#else
            printf("Mounting %s to drive A\n", cmd->path.c_str());
            drive_command = new SubsysCommand(cmd->user_interface, SUBSYSID_DRIVE_A, MENU_1541_MOUNT_D64, cmd->mode, 0, cmd->path.c_str());
            SubsysResultCode_e mounted = drive_command->execute().status;
            if (mounted != SSRET_OK) return mounted;
            c64_command = new SubsysCommand(cmd->user_interface, SUBSYSID_C64, C64_DMA_LOAD_MNT, run_code, cmd->path.c_str(), cmd->filename.c_str());
#endif
        } else if (run_code) {
            c64_command = new SubsysCommand(cmd->user_interface, SUBSYSID_C64, C64_DMA_LOAD, run_code, cmd->path.c_str(), cmd->filename.c_str());
        } else {
            c64_command = new SubsysCommand(cmd->user_interface, SUBSYSID_C64, C64_DMA_LOAD_RAW, run_code, cmd->path.c_str(), cmd->filename.c_str());
        }
        SubsysResultCode_e loaded = c64_command->execute().status;
        if (loaded != SSRET_OK) return loaded;
        if (cmd->user_interface) {
            cmd->user_interface->menu_response_to_action = menu_action;
        }
    } else {
        printf("Error opening file. %s\n", FileSystem::get_error_string(fres));
        return SSRET_CANNOT_OPEN_FILE;
    }
    return SSRET_OK;
}

SubsysResultCode_t FileTypePRG :: start_prg(const char *filename, bool run)
{
    int func = run ? RUNCODE_DMALOAD_RUN : RUNCODE_DMALOAD;
    SubsysCommand *c64_command = new SubsysCommand(NULL, SUBSYSID_C64, C64_DMA_LOAD, func, "", filename);
    return c64_command->execute(); 
}
