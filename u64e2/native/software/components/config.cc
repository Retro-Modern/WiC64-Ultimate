/*
 *   1541 Ultimate - The Storage Solution for your Commodore computer.
 *   Copyright (C) 2009  Gideon Zweijtzer - Gideon's Logic Architectures
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Abstract:
 *   This module implements functions to store/retrieve configuration items
 */
extern "C" {
    #include "dump_hex.h"
    #include "small_printf.h"
}
#include "config.h"
#include <string.h>
#if U64 && P08_SERVICE
#include "p12_storage.h"
#include "FreeRTOS.h"
#include "task.h"
#endif
#include "blockdev_flash.h"
#include "filemanager.h"

#if U64
#include "u64.h"
#endif

/*** CONFIGURATION MANAGER ***/
ConfigManager :: ConfigManager() : stores(16, NULL), pages(16, NULL)
{
#if U64 && P08_SERVICE
    for(unsigned i=0;i<4;i++)p12_private_claims[i]=-1;
#endif
	flash = get_flash();
	if(!flash) {
		printf("Error opening Flash device...\n");
		num_pages = 0;
	} else {
    	num_pages = flash->get_number_of_config_pages();
    	printf("ConfigManager opened flash: %p\n", flash);
    }
	safeMode = false;

#if U64
    if (U64_RESTORE_REG == 1) {
        safeMode = true;
    }
#elif SAFEMODE
    safeMode = true;
#else
    // If the reset button is pressed during boot, and it's not U64, then
    // safe mode is enabled.
    if ((ioRead8(ITU_BUTTON_REG) & ITU_BUTTON0) != 0) {
        safeMode = true;
    }
#endif
    if (safeMode) {
        printf("SAFE MODE ENABLED. Loading defaults...\n");
    }

#ifndef RECOVERYAPP
    // Now, also open the Flash File system!
    init_flash_disk();
#if !P05_RAM_DIAGNOSTIC
    FileManager :: getFileManager()->create_dir(CFG_FILEPATH); // if it doens't exist, create it
#endif
#endif
}

ConfigManager :: ~ConfigManager()
{
    printf("Destructor ConfigManger...\n");
    ConfigStore *s;
    for(int n = 0; n < stores.get_elements();n++) {
        s = (ConfigStore *)stores[n];
		delete s;
    }
    stores.clear_list();

    ConfigPage *p;
    for(int n = 0; n < pages.get_elements();n++) {
        p = (ConfigPage *)pages[n];
        delete p;
    }

}

ConfigStore *ConfigManager :: register_store(uint32_t page_id, const char *name,
                                t_cfg_definition *defs, ConfigurableObject *ob) 
{
	if(!flash) {
        flash = get_flash();
        printf("register_store %s: Can't open flash\n", name);
		return NULL; // fail
	}
#if U64 && P08_SERVICE
    if(p12::private_id(page_id))return NULL; // private namespace is not a menu/API store
#endif
    if(page_id == 0) {
        printf("ERROR: Requesting to register a store with ID=0\n");
        return NULL;
    }

    // Check if the store was already opened, just add the object to it
    for (int i=0; i<stores.get_elements(); i++) {
        ConfigStore *cfgStore = stores[i];
        if (strcmp(cfgStore->get_store_name(), name) == 0) {
            if (ob) {
                cfgStore->addObject(ob);
            }
            return cfgStore;
        }
    }

    int page_size = flash->get_config_page_size();

    // Try to obtain page object that already represents the page in Flash
    ConfigPage *page = NULL;
    for(int n=0; n<pages.get_elements(); n++) {
        ConfigPage *p = pages[n];
        if (p->get_id() == page_id) {
            page = p;
            break;
        }
    }

    bool write = false;
    // Try to find the page in Flash
    if (!page) {
        uint32_t id;
#if U64 && P08_SERVICE
        // The widened Winbond window prepends eight physical sectors.
        // Prefer every previously visible native setting before looking in
        // those sectors, including when an old/inactive duplicate ID exists.
        const char *type = flash->get_type_string();
        const bool widened_winbond = num_pages == 24 && type &&
            (!strcmp(type, "Winbond W25Q64") || !strcmp(type, "Winbond W25Q128"));
        for(int search=0;search<num_pages;search++) {
            int i = widened_winbond ? (search + 8) % 24 : search;
#else
        for(int i=0;i<num_pages;i++) {
#endif
            flash->read_config_page(i, 4, &id);
            if (page_id == id) {
                page = new ConfigPage(flash, id, i, page_size);
                pages.append(page);
                break;
            }
        }
    }

    // Not found in config pages, maybe it's on the flash storage itself?
    if (!page) {
        char fn[20];
        sprintf(fn, "page_%08x.bin", page_id);
        File *df;
        FileManager *fm = FileManager :: getFileManager(); 
        FRESULT fres = fm->fopen(CFG_FILEPATH, fn, FA_READ, &df);
        if (fres == FR_OK) {
            page = new ConfigPage(NULL, page_id, -1, page_size);
            pages.append(page);
            page->read_from_file(df);
            fm->fclose(df);
        }
    }

    // if still no luck, try to create a page in flash
    if (!page) {
        uint32_t id;
        for(int i=0;i<num_pages;i++) {
            flash->read_config_page(i, 4, &id);
            if (id == 0xFFFFFFFF) {
                //printf("Found empty spot on config page %d, for ID=%8x. Size=%d. Defs=%p. Name=%s\n", i, store_id, page_size, defs, name);
#if U64 && P08_SERVICE
                portENTER_CRITICAL();
                if(p12_private_slot_reserved(i)){portEXIT_CRITICAL();continue;}
                // RAM diagnostic registration does not write the owner ID.
                // Already allocated blank pages still belong to their store.
                bool already_allocated=false;
                for(int n=0;n<pages.get_elements();n++)if(pages[n]->get_flash_index()==i)already_allocated=true;
                if(already_allocated){portEXIT_CRITICAL();continue;}
#endif
                page = new ConfigPage(flash, page_id, i, page_size);
                pages.append(page);
                write = true;
#if U64 && P08_SERVICE
                portEXIT_CRITICAL();
#endif
                break;
            }
        }
    }

    // No space in Flash! Issue warning and create page on disk
    if (!page) {
        page = new ConfigPage(NULL, page_id, -1, page_size);
        pages.append(page);
        write = true; // write to disk
    }
    ConfigStore *s = new ConfigStore(page, name, defs, ob);
    stores.append(s);
    page->add_store(s);

    if (write) {
        page->write();
    }
    s->read(safeMode);
    return s;
}

#if U64 && P08_SERVICE
bool ConfigManager::p12_private_slot_reserved(int slot) const
{
    for(unsigned i=0;i<4;i++)if(p12_private_claims[i]==slot)return true;
    return false;
}
bool ConfigManager::p15_public_page_exclusive(ConfigPage *page,int slot)
{
    bool found=false,exclusive=true;
    portENTER_CRITICAL();
    for(int n=0;n<pages.get_elements();n++){
        ConfigPage *candidate=pages[n];
        if(candidate==page)found=true;
        if(candidate!=page && candidate->get_flash_index()==slot)exclusive=false;
    }
    portEXIT_CRITICAL();return found&&exclusive;
}
bool ConfigManager::p12_private_slot_owned(uint32_t id,int slot) const
{
    return p12::private_id(id)&&slot>=0&&p12_private_claims[id-p12::PRIVATE_ID_BASE]==slot;
}
int ConfigManager::p12_reserve_private_slots(const bool extra_blocked[24],int slots[4])
{
    if(!flash||(num_pages!=16&&num_pages!=24)||flash->get_config_page_size()!=512)return int(p12::UNSUPPORTED_FLASH);
    uint32_t ids[24];bool blocked[24]={};
    for(int i=0;i<num_pages;i++){flash->read_config_page(i,4,&ids[i]);blocked[i]=extra_blocked[i];}
    const char *type=flash->get_type_string();
    const bool widened_winbond=num_pages==24&&type&&
        (!strcmp(type,"Winbond W25Q64")||!strcmp(type,"Winbond W25Q128"));
    // No flash operation occurs inside this short allocation critical section.
    portENTER_CRITICAL();
    for(int i=0;i<pages.get_elements();i++){
        int slot=pages[i]->get_flash_index();if(slot>=0&&slot<num_pages)blocked[slot]=true;
    }
    if(widened_winbond){
        // Keep BOTH journal banks in one visibility window. An old seed bank
        // in the legacy last16 must never be left behind while its successor
        // is committed outside the old firmware's view (entropy rollback).
        bool legacy_private=false;
        for(int i=8;i<24;i++)if(p12::private_id(ids[i]))legacy_private=true;
        for(unsigned p=0;p<4;p++)if(p12_private_claims[p]>=8)legacy_private=true;
        for(int i=0;i<24;i++)if(legacy_private?(i<8):(i>=8))blocked[i]=true;
    }
    p12::Result result=p12::select_slots(ids,blocked,unsigned(num_pages),p12_private_claims,slots);
    if(result==p12::OK||result==p12::NO_SPACE)for(unsigned i=0;i<4;i++)p12_private_claims[i]=slots[i];
    portEXIT_CRITICAL();return int(result);
}
#endif

void ConfigManager :: add_custom_store(ConfigStore *cfg)
{
	stores.append(cfg);
}

void ConfigManager :: remove_store(ConfigStore *cfg)
{
    stores.remove(cfg);
}

ConfigStore *ConfigManager :: find_store(const char *storename)
{
    for(int i=0; i < stores.get_elements(); i++) {
        ConfigStore *st = stores[i];
        if (strcasecmp(st->get_store_name(), storename) == 0) {
            return st;
        }
        if (strcasecmp(st->get_alt_store_name(), storename) == 0) {
            return st;
        }
    }
    return NULL;
}

ConfigStore *ConfigManager :: find_store(uint32_t page_id)
{
    for(int i=0; i < stores.get_elements(); i++) {
        ConfigStore *st = stores[i];
        if (st->get_page()->get_id() == page_id) {
            return st;
        }
    }
    return NULL;
}

//   ===================
/*** CONFIGURATION STORE ***/
//   ===================
ConfigStore :: ConfigStore(ConfigPage *page, const char *name,
                           t_cfg_definition *defs, ConfigurableObject *ob) : store_name(name), items(16, NULL), objects(4, NULL)
{
    if (ob) {
        objects.append(ob);
    }
    this->page = page;
    staleEffect = true;
    staleFlash = false;
    hidden = false;
    hook_obj = NULL;
    sort_order = 0;
    
    for(int i=0;i<64;i++) {
        if(defs[i].type == CFG_TYPE_END)
            break;
        if(defs[i].id == 0xFF)
            break;
        ConfigItem *item = new ConfigItem(this, &defs[i]);
        items.append(item);
    }
}

ConfigStore :: ~ConfigStore()
{
    ConfigItem *i;
    for(int n = 0; n < items.get_elements();n++) {
    	i = items[n];
		delete i;
    }
    items.clear_list();
}
        
void ConfigStore :: addObject(ConfigurableObject *obj)
{
    objects.append(obj);
}

int ConfigStore :: unregister(ConfigurableObject *obj)
{
    objects.remove(obj);
    return objects.get_elements();
}

void ConfigStore :: at_open_config(void)
{
    for(int i=0; i<objects.get_elements(); i++) {
        objects[i]->on_edit();
    }
}

int ConfigPage :: pack(void)
{
    memset(mem_block, 0xFF, block_size);

    uint8_t *b = &mem_block[4];
    (*(uint32_t *)mem_block) = id;
    int remain = block_size - 4;
    int size;
    for(int n = 0; n < stores.get_elements(); n++) {
        ConfigStore *s = stores[n];
        size = s->pack(b, remain);
        remain -= size;
        b += size;
    }
    return block_size - remain;
}

void ConfigPage :: unpack(void)
{
    for(int n = 0; n < stores.get_elements(); n++) {
        ConfigStore *s = stores[n];
        s->unpack(mem_block, block_size);
    }
}

void ConfigPage :: unpack(ConfigStore *s)
{
    s->unpack(mem_block, block_size);
}

int ConfigStore :: pack(uint8_t *b, int remain)
{
    ConfigItem *i;
    int len;
    int total = 0;
    //    printf("Packing ConfigStore %s.\n", store_name);
    for(int n = 0; n < items.get_elements();n++) {
    	i = items[n];
    	len = i->pack(b, remain);
        b += len;
        remain -= len;
        total += len;
        if(remain < 1) {
            printf("Configuration item doesn't fit. Dropped.\n");
            break;
        }
    }
    *b = 0xFF;

    return total;
}

void ConfigStore :: effectuate()
{
    if (objects.get_elements() == 0) {
        staleEffect = false;
        return;
    }
    if (!staleEffect) {
        printf("Effectuate for %s not needed; not stale.\n", get_store_name());
        return;
    }
    // printf("Calling Effectuate on %s for %d objects.\n", get_store_name(), objects.get_elements());
    for(int i=0; i<objects.get_elements(); i++) {
        ConfigurableObject *obj = objects[i];
        if(obj) {
            obj->effectuate_settings();
        }
    }
    staleEffect = false;
}
    
void ConfigStore :: write()
{
#if P05_RAM_DIAGNOSTIC
    // Runtime values stay usable, but do not claim that they were persisted.
    if (page) page->write();
    return;
#endif
	printf("Writing config store '%s' to flash..", store_name.c_str());
	if(page) {
	    page->write();
        staleFlash = false;
	}
}

void ConfigStore :: convert_to_group(const char *name, int sort_order)
{
    ConfigGroup *grp = ConfigGroupCollection::getGroup(name, sort_order);
    if (grp) {
        for(int i=0; i < items.get_elements(); i++) {
            grp->append(items[i]);
        }
    }
}

void ConfigPage :: write()
{
#if P05_RAM_DIAGNOSTIC
    // Covers automatic first-registration and explicit save paths alike.
    // Keep a RAM representation; never write a flash page or /flash file.
    pack();
    return;
#endif
	int size = pack();

    if (flash_page < 0) {
        char fn[20];
        File *df;
        sprintf(fn, "page_%08x.bin", id);
        FileManager *fm = FileManager :: getFileManager();
        FRESULT fres = fm->create_dir(CFG_FILEPATH);
        fres = fm->fopen(CFG_FILEPATH, fn, FA_CREATE_ALWAYS | FA_WRITE, &df );
        if (fres == FR_OK) {
        	int size = pack();
            uint32_t tr;
            df->write(mem_block, (uint32_t)size, &tr);
            fm->fclose(df);
            printf("Written %s to flash disk\n", fn);
        } else {
            printf("Could not open '%s' for writing\n", fn);
        }
        return;
    }
    printf("Page: %d", flash_page);
	//dump_hex_relative(mem_block, size);
	if(flash) {
	    flash->write_config_page(flash_page, mem_block);
	    printf(" done.\n");
	} else {
		printf(" error.\n");
	}
}

#if U64 && P08_SERVICE
bool ConfigPage::p15_write_verified()
{
    // Never expose a general write bypass. These are ordinary nonsecret native
    // network settings and the separate WiC64 fixed-timezone preference only.
    if (id != 0x57313550u && id != 0x4E657477u && id != 0x57494649u) return false;
    static bool writing = false;
    struct Claim {
        bool &busy;
        bool held;
        Claim(bool &v):busy(v),held(false) {
            portENTER_CRITICAL();
            if (!busy) { busy = true; held = true; }
            portEXIT_CRITICAL();
        }
        ~Claim() { if (held) { portENTER_CRITICAL(); busy = false; portEXIT_CRITICAL(); } }
    } claim(writing);
    if (!claim.held || !flash || !mem_block || block_size != 512) return false;
    const char *type = flash->get_type_string();
    const bool known = type && (!strcmp(type,"Winbond W25Q80") || !strcmp(type,"Winbond W25Q16") ||
        !strcmp(type,"Winbond W25Q32") || !strcmp(type,"Winbond W25Q64") || !strcmp(type,"Winbond W25Q128") ||
        !strcmp(type,"Infineon S25FL064L") || !strcmp(type,"Infineon S25FL128L"));
    const int count = flash->get_number_of_config_pages(), pages = flash->get_number_of_pages();
    if (!known || flash->get_page_size()!=256 || flash->get_config_page_size()!=512 ||
        flash->get_sector_size(0)!=4096 || (count!=16 && count!=24) ||
        pages<=count*16 || pages>65536 || pages%16 || flash_page<0 || flash_page>=count) return false;
    ConfigManager *manager = ConfigManager::getConfigManager();
    if (!manager || manager->get_flash_access()!=flash || manager->p12_private_slot_reserved(flash_page) ||
        !manager->p15_public_page_exclusive(this,flash_page)) return false;
    const int physical = pages-count*16+flash_page*16;
    if (physical<0 || physical+15>=pages || flash->get_sector_size(physical*256)!=4096 ||
        flash->page_to_sector(physical)!=physical/16 || flash->page_to_sector(physical+15)!=physical/16) return false;
    alignas(4) uint8_t before[512], check[512], raw[256];
    flash->read_config_page(flash_page,512,before);
    // The config-driver view must refer to the same two physical pages. A
    // broken mapping cannot be allowed to erase a different sector.
    for (unsigned n=0;n<2;n++) {
        if (!flash->read_page(physical+int(n),raw) || memcmp(raw,before+n*256,256)) return false;
    }
    uint32_t owner;memcpy(&owner,before,4);
    if (owner!=id && owner!=0xffffffffu) return false;
    if (owner==0xffffffffu) {
        for (unsigned n=0;n<512;n++) if (before[n]!=0xff) return false;
        // write_config_page erases the complete 4 KiB sector, not just the
        // 512-byte native record. An erased header may hide orphaned/torn
        // private data in the tail; unknown bytes must never be reclaimed.
        // Physical pages 0/1 were read and compared above; inspect 2..15 too.
        for (unsigned n=2;n<16;n++) {
            if (!flash->read_page(physical+int(n),raw)) return false;
            for (unsigned b=0;b<256;b++) if (raw[b]!=0xff) return false;
        }
    }
    const int used=pack();
    if (used<4 || used>512) return false;
    uint32_t packed_id;memcpy(&packed_id,mem_block,4);
    if (packed_id!=id) return false;
    // Recheck ownership immediately before the only mutation. No critical
    // section surrounds flash I/O; the driver bounds each SPI operation.
    if (manager->p12_private_slot_reserved(flash_page)) return false;
    flash->read_config_page(flash_page,512,check);
    if (memcmp(check,before,512)) return false;
    if (!memcmp(mem_block,before,512)) return true; // no extra erase for a no-op
    flash->write_config_page(flash_page,mem_block);
    flash->read_config_page(flash_page,512,check);
    if (memcmp(check,mem_block,512)) return false;
    for (unsigned n=0;n<2;n++) {
        if (!flash->read_page(physical+int(n),raw) || memcmp(raw,mem_block+n*256,256)) return false;
    }
    return true;
}
#endif

void ConfigStore :: unpack(uint8_t *mem_block, int block_size)
{
    int index = 4;
    uint8_t id;
    int len;
    ConfigItem *i;
    
    while(index < block_size) {
        id  = mem_block[index];
        if(id == 0xFF) {
            break;
        }
        len = (int)mem_block[index+2];
        if(len > (block_size-index-3)) {
            printf("Illegal length. Doesn't fit.\n");
            break;
        }            
        // find ID in our store        
        for(int n = 0;n < items.get_elements(); n++) {
        	i = items[n];
        	if(id == i->definition->id) {
                i->unpack(&mem_block[index+1], len);
            }
        }
        index += len + 3;
    }
}

void ConfigPage :: read_from_file(File *f)
{
    uint32_t tr;
    f->read(mem_block, (uint32_t)block_size, &tr);
    // printf("%d bytes read from config file\n", tr);
}

void ConfigPage :: read(bool ignoreData)
{
    if (flash_page < 0) {
        char fn[20];
        sprintf(fn, "page_%08x.bin", id);
        File *df;
        FileManager *fm = FileManager :: getFileManager(); 
        FRESULT fres = fm->fopen(CFG_FILEPATH, fn, FA_READ, &df);
        if (fres == FR_OK) {
            read_from_file(df);
            fm->fclose(df);
        }
        return;
    }

    if(flash && !ignoreData) {
        flash->read_config_page(flash_page, block_size, mem_block);
    } else {
        memset(mem_block, 0xFF, block_size);
    }
}

void ConfigStore :: read(bool ignore)
{
	if(page) {
	    page->read(ignore);
	    page->unpack(this);
	}
	staleEffect = true;
	staleFlash = false;
	check_bounds();
}

ConfigItem *ConfigStore :: find_item(uint8_t id)
{
    ConfigItem *i;
    for(int n = 0;n < items.get_elements(); n++) {
    	i = items[n];
        if(i->definition->id == id) {
            return i;
        }
    }
    return NULL;
}

ConfigItem *ConfigStore :: find_item(const char *str)
{
    ConfigItem *i;
    for(int n = 0;n < items.get_elements(); n++) {
    	i = items[n];
        if(strcasecmp(i->definition->item_text, str) == 0) {
            return i;
        }
    }
    return NULL;
}

void ConfigStore :: set_change_hook(uint8_t id, t_change_hook hook)
{
    ConfigItem *i = find_item(id);
    if(i) {
    	i->setChangeHook(hook);
    }
}

void ConfigStore :: disable(uint8_t id)
{
    ConfigItem *i = find_item(id);
    if (i) {
        i->setEnabled(false);
    }
}

void ConfigStore :: enable(uint8_t id)
{
    ConfigItem *i = find_item(id);
    if (i) {
        i->setEnabled(true);
    }
}

int ConfigStore :: get_value(uint8_t id)
{
    ConfigItem *i = find_item(id);
    if(i)
        return i->value;
    return -1;
}
    
const char *ConfigStore :: get_string(uint8_t id)
{
    ConfigItem *i = find_item(id);
    if(i) {
        if(i->string)
            return i->string;
        else
            return "__not a string__";
    }
    return "__id not found__";
}

void ConfigStore :: set_value(uint8_t id, int value)
{
    ConfigItem *i = find_item(id);
    if(i) {
        i->setValue(value);
    }
}

void ConfigStore :: set_string(uint8_t id, const char *s)
{
    ConfigItem *i = find_item(id);
    if(i) {
        i->setString(s);
    }
}

void ConfigStore :: dump(void)
{
    ConfigItem *i;
    for(int n = 0; n < items.get_elements(); n++) {
    	i = items[n];
        printf("ID %02x: ", i->definition->id);
        if ((i->definition->type == CFG_TYPE_STRING) || (i->definition->type ==CFG_TYPE_STRFUNC)) {
            printf("%s = '%s'\n", i->definition->item_text, i->string);
        } else if(i->definition->type == CFG_TYPE_STRPASS) {
            printf("%s = '%s'\n", i->definition->item_text, "*****");
        } else if(i->definition->type == CFG_TYPE_ENUM) {
            printf("%s = %s\n", i->definition->item_text, i->definition->items[i->value]);
        } else {
            printf("%s = %d\n", i->definition->item_text, i->value);
        }
    }
}

void ConfigStore :: reset(void)
{
    ConfigItem *i;
    for(int n = 0; n < items.get_elements(); n++) {
        i = items[n];
        i->reset();
    }
    staleEffect = true;
    staleFlash = true;
}

void ConfigStore :: check_bounds(void)
{
    ConfigItem *i;
    for(int n = 0; n < items.get_elements(); n++) {
    	i = items[n];
		if((i->definition->type == CFG_TYPE_ENUM) || 
		   (i->definition->type == CFG_TYPE_VALUE)) {
			if(i->value < i->definition->min) {
				i->value = i->definition->min;
			    staleEffect = true;
			    staleFlash = true;
			} else if(i->value > i->definition->max) {
				i->value = i->definition->max;
			    staleEffect = true;
			    staleFlash = true;
			}
		}
	}
}


/*** CONFIGURATION ITEM ***/
ConfigItem :: ConfigItem(ConfigStore *s, t_cfg_definition *d)
{
	hook = NULL;
	order = NULL;
	definition = d;
    store = s;
    if ((d->type == CFG_TYPE_STRING)||(d->type == CFG_TYPE_INFO)||(d->type == CFG_TYPE_STRFUNC)||(d->type == CFG_TYPE_STRPASS)) {
        string = new char[d->max+1];
    } else {
        string = NULL;
    }
    enabled = true;
    reset();
}

ConfigItem :: ~ConfigItem()
{
    if(string)
        delete[] string;
}

ConfigItem *ConfigItem :: separator()
{
    // due to poor design, this cannot be const. But it will be referenced later,
    // so we make it static. Otherwise it ends up on the stack.
    static t_cfg_definition def = {
        .id = 0xFE,
        .type = CFG_TYPE_SEP,
        .item_text = "",
        .item_format = "",
        .items = NULL,
        .min = 0,
        .max = 0,
        .def = 0,
    };
    static ConfigItem *sep = NULL;
    if (!sep) {
        sep = new ConfigItem((ConfigStore *)NULL, &def);
    }
    return sep;
}

ConfigItem *ConfigItem :: heading(const char *name)
{
    // due to poor design, this cannot be const. But it will be referenced later,
    // so we make it static. Otherwise it ends up on the stack.
    static t_cfg_definition def = {
        .id = 0xFE,
        .type = CFG_TYPE_SEP,
        .item_text = "",
        .item_format = "",
        .items = NULL,
        .min = 0,
        .max = 0,
        .def = 0,
    };
    ConfigItem *it = new ConfigItem((ConfigStore *)NULL, &def);
    it->set_item_altname(name);
    return it;
}

void ConfigItem :: reset(void)
{
    if ((definition->type == CFG_TYPE_STRING) || (definition->type == CFG_TYPE_STRFUNC) || (definition->type == CFG_TYPE_STRPASS)) {
        strncpy(string, (const char *)definition->def, definition->max);
        value = 0;
    } else {
        value = (int)definition->def;
    }
}

void ConfigItem :: unpack(uint8_t *buffer, int len)
{
    // first byte we get is the type
    if(*buffer != definition->type) {
        printf("Error! Entry type mismatch!!\n");
        return;
    }
    buffer++;
    int field = (int)*(buffer++);
    switch(definition->type) {
        case CFG_TYPE_VALUE:
        case CFG_TYPE_ENUM:
            value = 0;
            while(field--) {
                value <<= 8;
                value |= (int)*(buffer++);
            }
            if(value < definition->min)
                value = definition->def;
            if(value > definition->max)
                value = definition->def;
            break;
        case CFG_TYPE_STRING:
        case CFG_TYPE_STRFUNC:
        case CFG_TYPE_STRPASS:
            if(field > definition->max)
                field = definition->max;
            strncpy(string, (char *)buffer, field);
            string[field] = '\0';
            break;
        default:
            printf("Error: unknown type, reading flash configuration.\n");
    }
}

int ConfigItem :: pack(uint8_t *buffer, int len)
{
    // first byte we get is the id, then type, then length
    if(len > 0) {
        *(buffer++) = definition->id;
        len--;
    }
    if(len > 0) {
        *(buffer++) = definition->type;
        len--;
    }
    switch(definition->type) {
        case CFG_TYPE_VALUE:
//            printf("Value %s = %d\n", definition->item_text, value);
            if(len < 5) {
                printf("Int doesn't fit anymore.\n");
                return 0;
            }
            *(buffer++) = (uint8_t)4;
            *(buffer++) = (uint8_t)(value >> 24);
            *(buffer++) = (uint8_t)(value >> 16);
            *(buffer++) = (uint8_t)(value >> 8);
            *(buffer++) = (uint8_t)(value >> 0);
            return 7;
        case CFG_TYPE_ENUM:
//            printf("Enum %s = %s\n", definition->item_text, definition->items[value]);
            if(len < 2) {
                printf("Enum doesn't fit anymore.\n");
                return 0;
            }
            *(buffer++) = (uint8_t)1;
            *(buffer++) = (uint8_t)(value >> 0);
            return 4;
        case CFG_TYPE_STRING:
        case CFG_TYPE_STRFUNC:
        case CFG_TYPE_STRPASS:
//            printf("String %s = %s\n", definition->item_text, string);
            if(2+strlen(string) > len) {
                printf("String doesn't fit.\n");
                return 0;
            }
            *(buffer++) = (uint8_t)strlen(string);
            strcpy((char *)buffer, string);
            return 3+strlen(string);
        case CFG_TYPE_FUNC:
        case CFG_TYPE_SEP:
        case CFG_TYPE_INFO:
            break; // do nothing, do not store
        default:
            printf("Error: unknown type packing flash configuration.\n");
    }
    return 0;
}

// note:the buffer needs to be at least 3 bytes bigger than what width indicates
// width is the actual width in characters on the screen, and two additional bytes are needed to set the color
const char *ConfigItem :: get_display_string(char *buffer, int width, int act, int inact)
{
	static char buf[32];
    const char *src = altname.length() ? altname.c_str() : definition->item_text;
    int room = width - (int)strlen(src) - 1;
    if (room > (int)sizeof(buf) - 1) {
        room = sizeof(buf) - 1;
    } else if (room < 0) {
        room = 0;
    }
    int keep;

    memset(buffer, ' ', width+2);
    buffer[width+2] = '\0';

    switch(definition->type) {
        case CFG_TYPE_VALUE:
            sprintf(buf, definition->item_format, value);
            break;
        case CFG_TYPE_ENUM:
            sprintf(buf, definition->item_format, definition->items[value]);
            break;
        case CFG_TYPE_STRING:
        case CFG_TYPE_STRFUNC:
        case CFG_TYPE_INFO:
            if ((int)strlen(string) <= room) {
                sprintf(buf, definition->item_format, string);
                break;
            }
            // Cut a string that does not fit beside the name, and say so.
            keep = (room > 3) ? room - 3 : 0;
            strncpy(buf, string, keep);
            strcpy(buf + keep, "...");
            break;
        case CFG_TYPE_STRPASS:
            if (*string)
                strcpy(buf, "******");
            else
                strcpy(buf, "<none>");
            break;
        case CFG_TYPE_FUNC:
        case CFG_TYPE_SEP:
            sprintf(buf, definition->item_format);
            break;
        default:
            sprintf(buf, "Unknown type.");
    }

    int len = strlen(buf);

    char *dst;
    // left align copy
    dst = buffer;
    while(*src) {
        *(dst++) = *(src++);
    }
    // right align copy
    dst = &buffer[width+1];
    for(int b = len-1; b >= 0; b--)
        *(dst--) = buf[b];
    *(dst--) = (enabled) ? act : inact;
    *(dst--) = '\033'; // escape code = set color
    return (const char *)buffer;
}

int   ConfigItem :: fetch_possible_settings(IndexedList<ConfigSetting *> &list)
{
    char buf[32];
    int i,ret = 0;
    
    switch(definition->type) {
        case CFG_TYPE_VALUE:
            for(i=definition->min;i<=definition->max;i++) {
                sprintf(buf, definition->item_format, i);
                list.append(new ConfigSetting(i, this, buf));
            }
            ret = definition->max - definition->min + 1;
            break;
        case CFG_TYPE_ENUM:
            for(i=0;i<=definition->max-definition->min;i++) {
                int v = listedValue(i);
                sprintf(buf, definition->item_format, definition->items[v]);
                list.append(new ConfigSetting(v, this, buf));
            }
            ret = definition->max - definition->min + 1;
            break;
        default:
            printf("Item not contextable\n");
    }
    return ret;   
}

void ConfigItem :: execute(int sel)
{
    printf("Setting option to %d.\n", sel);
    value = sel;
    setChanged();
}

void ConfigItem :: setString(const char *s)
{
    if(this->string) {
        strncpy(this->string, s, this->definition->max);
        this->string[this->definition->max] = 0;  // Safe since the "string" buffer is max+1 (see ConfigItem constructor)
        if (strlen(s) > this->definition->max) {
            this->string[this->definition->max - 1] = '*';  // Indicate string was truncated
        }
        if ((definition->type == CFG_TYPE_STRING) || (definition->type == CFG_TYPE_STRFUNC) || (definition->type == CFG_TYPE_STRPASS)) {
            setChanged();
        }
    }
}

int ConfigItem :: next(int a)
{
    int value = getValue();
    int ret = 0;
    if (order && definition->type == CFG_TYPE_ENUM) {
        int n = 1 + definition->max - definition->min;
        return setValue(order[((listPosition(value) + a) % n + n) % n]);
    }
    switch(definition->type) {
        case CFG_TYPE_ENUM:
        case CFG_TYPE_VALUE:
            value += a;
            // circular
            while (value > definition->max) {
                value -= (1 + definition->max - definition->min);
            }
            ret = setValue(value);
            break;

        default:
            break;
    }
    return ret;
}

int ConfigItem :: previous(int a)
{
    int value = getValue();
    int ret = 0;
    if (order && definition->type == CFG_TYPE_ENUM) {
        int n = 1 + definition->max - definition->min;
        return setValue(order[((listPosition(value) - a) % n + n) % n]);
    }
    switch(definition->type) {
        case CFG_TYPE_ENUM:
        case CFG_TYPE_VALUE:
            value -= a;
            // circular
            while (value < definition->min) {
                value += (1 + definition->max - definition->min);
            }
            ret = setValue(value);
            break;
        default:
            break;
    }
    return ret;
}

int ConfigItem :: listPosition(int v)
{
    if (!order) {
        return v - definition->min;
    }
    for (int pos = 0; pos <= definition->max - definition->min; pos++) {
        if (order[pos] == v) {
            return pos;
        }
    }
    return 0;
}

int ConfigItem :: setChanged()
{
    store->set_need_flash_write(true);
    int ret = 0;
    if(hook) {
        ret = hook(this);
    } else {
        store->set_need_effectuate();
    }
    return ret;
}

ConfigSetting :: ConfigSetting(int index, ConfigItem *p, char *name) : setting_name(name)
{
	parent = p;
	setting_index = index;
}

Flash *get_flash(void) __attribute__((weak));

Flash *get_flash(void)
{
	return new Flash(); // stubbed base
}

const char *en_dis[]    = { "Disabled", "Enabled" };
