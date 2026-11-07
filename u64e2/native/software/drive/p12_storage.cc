#include "p12_storage.h"
#include <string.h>

namespace p12 {
namespace {
uint16_t get16(const uint8_t *p){return uint16_t(p[0])|uint16_t(p[1])<<8;}
uint32_t get32(const uint8_t *p){return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
void put16(uint8_t *p,uint16_t n){p[0]=uint8_t(n);p[1]=uint8_t(n>>8);}
void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=uint8_t(n>>(8*i));}
uint32_t crc_step(uint32_t crc,const uint8_t *p,unsigned n){while(n--){crc^=*p++;for(unsigned b=0;b<8;b++)crc=(crc>>1)^((crc&1)?0xedb88320u:0);}return crc;}
uint32_t crc32(const uint8_t *p,unsigned n){return ~crc_step(0xffffffffu,p,n);}
bool blank(const uint8_t *p,unsigned n){while(n--)if(*p++!=0xff)return false;return true;}
bool owner_header(const uint8_t *p,unsigned index){return get32(p)==PRIVATE_ID_BASE+index&&!memcmp(p+4,"W12S",4)&&p[8]==1&&p[9]==index/PARTS&&p[10]==index%PARTS&&p[11]==PARTS;}
bool valid_header(const uint8_t *p,unsigned index){
 if(!owner_header(p,index)||!get32(p+12)||get16(p+16)>MAX_BLOB||p[18]||p[19]||get32(p+24)!=crc32(p,24))return false;
 for(unsigned i=28;i<HEADER_BYTES;i++)if(p[i])return false;return true;
}
}
const char *result_name(Result r){static const char *n[]={"OK","EMPTY","BUSY","UNSUPPORTED_FLASH","NO_SPACE","COLLISION","CORRUPT","IO_ERROR","VERIFY_FAILED","TOO_LARGE","GENERATION_EXHAUSTED"};return unsigned(r)<sizeof(n)/sizeof(*n)?n[r]:"UNKNOWN";}
const char *state_name(State s){static const char *n[]={"UNINITIALIZED","EMPTY","READY","WRITING","ERROR"};return unsigned(s)<sizeof(n)/sizeof(*n)?n[s]:"UNKNOWN";}
Result select_slots(const uint32_t *ids,const bool *blocked,unsigned count,const int previous[PRIVATE_SLOTS],int out[PRIVATE_SLOTS])
{
 for(unsigned p=0;p<PRIVATE_SLOTS;p++)out[p]=-1;
 if(!ids||!blocked||!previous||(count!=16&&count!=24))return UNSUPPORTED_FLASH;
 bool collision=false;
 for(unsigned p=0;p<PRIVATE_SLOTS;p++){
  unsigned matches=0;
  for(unsigned s=0;s<count;s++)if(ids[s]==PRIVATE_ID_BASE+p){matches++;if(!blocked[s])out[p]=int(s);else collision=true;}
  if(matches>1){out[p]=-1;collision=true;}
  if(previous[p]>=0){
   unsigned s=unsigned(previous[p]);
   if(s>=count||blocked[s]||(ids[s]!=0xffffffffu&&ids[s]!=PRIVATE_ID_BASE+p)||(out[p]>=0&&out[p]!=int(s))){collision=true;continue;}
   if(out[p]<0)out[p]=int(s);
  }
 }
 for(unsigned a=0;a<PRIVATE_SLOTS;a++)for(unsigned b=a+1;b<PRIVATE_SLOTS;b++)if(out[a]>=0&&out[a]==out[b])collision=true;
 if(collision)return COLLISION;
 Result result=OK;
 for(unsigned p=0;p<PRIVATE_SLOTS;p++)if(out[p]<0){
  for(unsigned s=0;s<count;s++){
   if(ids[s]!=0xffffffffu||blocked[s])continue;
   bool used=false;for(unsigned k=0;k<PRIVATE_SLOTS;k++)if(out[k]==int(s))used=true;
   if(!used){out[p]=int(s);break;}
  }
  if(out[p]<0)result=NO_SPACE;
 }
 return result;
}
Storage::Storage(Device &d):device(d),active_bank(-1),inspect_result(EMPTY),read_io_failed(false)
{
 memset(&shape,0,sizeof(shape));memset(&current,0,sizeof(current));current.state=UNINITIALIZED;current.last_error=EMPTY;current.capacity=MAX_BLOB;
 for(unsigned i=0;i<PRIVATE_SLOTS;i++)current.slots[i]=-1;
}
void Storage::publish(){device.publish_status(current);}
Result Storage::fail(Result r,bool dirty){current.state=ERROR_STATE;current.last_error=r;current.writable=false;current.dirty|=dirty;if(dirty)current.persisted=false;publish();return r;}
uint32_t Storage::page_for(unsigned part,unsigned within)const
{
 return shape.total_pages-uint32_t(shape.config_slots)*16+uint32_t(current.slots[part])*16+within;
}
bool Storage::read_header(unsigned part,uint8_t header[HEADER_BYTES])
{
 if(part>=PRIVATE_SLOTS||current.slots[part]<0)return false;
 alignas(4) uint8_t page[PROGRAM_BYTES];if(!device.read_page(page_for(part,0),page)){read_io_failed=true;return false;}memcpy(header,page,HEADER_BYTES);return true;
}
bool Storage::read_bank(unsigned bank,uint8_t *out,uint16_t capacity,uint32_t &generation,uint16_t &length,const uint8_t *compare,bool *equal)
{
 uint8_t h[PARTS][HEADER_BYTES];generation=0;length=0;if(equal)*equal=false;
 for(unsigned p=0;p<PARTS;p++)if(!read_header(bank*PARTS+p,h[p])||!valid_header(h[p],bank*PARTS+p))return false;
 if(memcmp(h[0]+12,h[1]+12,12))return false;
 length=get16(h[0]+16);generation=get32(h[0]+12);if((out||compare)&&capacity<length)return false;
 uint32_t crc=0xffffffffu;bool same=true;unsigned done=0;
 for(unsigned part=0;part<PARTS&&done<length;part++){
  for(unsigned p=0;p<16&&done<length;p++){
   alignas(4) uint8_t page[PROGRAM_BYTES];if(!device.read_page(page_for(bank*PARTS+part,p),page)){read_io_failed=true;return false;}
   unsigned begin=p?0:HEADER_BYTES,n=PROGRAM_BYTES-begin;if(n>unsigned(length)-done)n=length-done;
   crc=crc_step(crc,page+begin,n);
   if(out)memcpy(out+done,page+begin,n);
   if(compare&&memcmp(compare+done,page+begin,n))same=false;
   done+=n;
  }
 }
 if(done!=length||~crc!=get32(h[0]+20))return false;if(equal)*equal=same;return true;
}
bool Storage::inspect()
{
 inspect_result=UNSUPPORTED_FLASH;read_io_failed=false;
 if(!device.geometry(shape)||!shape.trusted||shape.program_bytes!=PROGRAM_BYTES||shape.sector_bytes!=SECTOR_BYTES||
    shape.record_bytes!=RECORD_BYTES||(shape.config_slots!=16&&shape.config_slots!=24)||shape.total_pages%16||shape.total_pages<=uint32_t(shape.config_slots)*16)return false;
 current.initialized=true;current.config_slots=shape.config_slots;
 bool blocked[MAX_CONFIG_SLOTS]={};bool any_owned=false;bool owned_bank[BANKS]={};
 for(unsigned s=0;s<shape.config_slots;s++){
  alignas(4) uint8_t record[RECORD_BYTES];if(!device.read_record(s,record)){inspect_result=IO_ERROR;return false;}
  uint32_t id=get32(record);
  if(private_id(id)){any_owned=true;owned_bank[unsigned(id-PRIVATE_ID_BASE)/PARTS]=true;if(!owner_header(record,unsigned(id-PRIVATE_ID_BASE)))blocked[s]=true;}
  else if(id==0xffffffffu){
   for(unsigned p=0;p<16;p++){
    alignas(4) uint8_t page[PROGRAM_BYTES];uint32_t address=shape.total_pages-uint32_t(shape.config_slots)*16+s*16+p;
    if(!device.read_page(address,page)){inspect_result=IO_ERROR;return false;}
    if(!blank(page,PROGRAM_BYTES)){blocked[s]=true;break;}
   }
  }
 }
 int slots[PRIVATE_SLOTS];inspect_result=device.reserve(blocked,slots);
 for(unsigned p=0;p<PRIVATE_SLOTS;p++)current.slots[p]=int16_t(slots[p]);
 current.writable=inspect_result==OK;active_bank=-1;current.generation=0;current.length=0;current.persisted=false;current.recovered=false;
 uint32_t gen[BANKS]={};uint16_t length[BANKS]={};bool valid[BANKS]={};
 for(unsigned b=0;b<BANKS;b++)valid[b]=read_bank(b,0,0,gen[b],length[b]);
 if(read_io_failed){inspect_result=IO_ERROR;return false;}
 if(valid[0]&&valid[1]&&gen[0]==gen[1]){current.writable=false;inspect_result=COLLISION;current.last_error=COLLISION;current.state=ERROR_STATE;return true;}
 for(unsigned b=0;b<BANKS;b++)if(valid[b]&&(active_bank<0||gen[b]>current.generation)){active_bank=int(b);current.generation=gen[b];current.length=length[b];}
 current.persisted=active_bank>=0&&!current.dirty;
 current.recovered=active_bank>=0&&((owned_bank[0]&&!valid[0])||(owned_bank[1]&&!valid[1]));
 current.state=active_bank>=0?READY:any_owned?ERROR_STATE:EMPTY_STATE;
 current.last_error=inspect_result==OK?(active_bank>=0?OK:any_owned?CORRUPT:EMPTY):inspect_result;
 return true;
}
Result Storage::initialize()
{
 if(!device.try_lock())return BUSY;
 Result r;if(!inspect())r=fail(inspect_result,false);else{r=current.last_error;publish();}
 device.unlock();return r;
}
Result Storage::load(uint8_t *out,uint16_t capacity,uint16_t &length)
{
 length=0;if(!out&&capacity)return TOO_LARGE;if(!device.try_lock())return BUSY;
 Result r=OK;
 if(!inspect())r=fail(inspect_result,false);
 else if(active_bank<0){r=current.last_error;publish();}
 else if(capacity<current.length||(!out&&current.length))r=fail(TOO_LARGE,false);
 else {
  uint32_t gen;uint16_t n;
  if(!read_bank(unsigned(active_bank),out,capacity,gen,n))r=fail(IO_ERROR,false);
  else{length=n;current.persisted=true;current.dirty=false;current.state=READY;publish();}
 }
 device.unlock();return r;
}
Result Storage::save(const uint8_t *bytes,uint16_t length)
{
 if(length>MAX_BLOB||(!bytes&&length))return TOO_LARGE;if(!device.try_lock())return BUSY;
 Result r=OK;
 if(!inspect()){r=fail(inspect_result,true);device.unlock();return r;}
 if(!current.writable){r=fail(inspect_result,true);device.unlock();return r;}
 if(active_bank>=0&&current.length==length){uint32_t gen;uint16_t n;bool equal=false;
  bool valid=read_bank(unsigned(active_bank),0,length,gen,n,bytes,&equal);
  if(read_io_failed){r=fail(IO_ERROR,true);device.unlock();return r;}
  if(valid&&n==length&&equal){current.dirty=false;current.persisted=true;current.last_error=OK;current.state=READY;publish();device.unlock();return OK;}
 }
 if(current.generation==0xffffffffu){r=fail(GENERATION_EXHAUSTED,true);device.unlock();return r;}
 unsigned target=active_bank==0?1:0;uint32_t generation=current.generation+1,checksum=crc32(bytes,length);
 current.state=WRITING;current.dirty=true;current.persisted=false;current.last_error=OK;publish();
 for(unsigned part=0;part<PARTS;part++){
  unsigned index=target*PARTS+part;unsigned slot=unsigned(current.slots[index]);
  if(!device.erase_reserved(slot,PRIVATE_ID_BASE+index)){r=fail(IO_ERROR,true);device.unlock();return r;}
  uint8_t header[HEADER_BYTES]={};put32(header,PRIVATE_ID_BASE+index);memcpy(header+4,"W12S",4);header[8]=1;header[9]=uint8_t(target);header[10]=uint8_t(part);header[11]=PARTS;
  put32(header+12,generation);put16(header+16,length);put32(header+20,checksum);put32(header+24,crc32(header,24));
  for(unsigned p=0;p<16;p++){
   alignas(4) uint8_t page[PROGRAM_BYTES];memset(page,0xff,sizeof(page));unsigned start=p?0:HEADER_BYTES;
   if(!p)memcpy(page,header,HEADER_BYTES);
   unsigned base=part*(SECTOR_BYTES-HEADER_BYTES)+(p?p*PROGRAM_BYTES-HEADER_BYTES:0);
   if(base<length){unsigned n=PROGRAM_BYTES-start;if(n>unsigned(length)-base)n=length-base;memcpy(page+start,bytes+base,n);}
   if(!blank(page,sizeof(page))&&!device.program_reserved(slot,PRIVATE_ID_BASE+index,p,page)){r=fail(IO_ERROR,true);device.unlock();return r;}
  }
 }
 uint32_t actual_generation;uint16_t actual_length;bool equal=false;
 if(!read_bank(target,0,length,actual_generation,actual_length,bytes,&equal)||actual_generation!=generation||actual_length!=length||!equal){r=fail(VERIFY_FAILED,true);device.unlock();return r;}
 active_bank=int(target);current.generation=generation;current.length=length;current.state=READY;current.last_error=OK;current.dirty=false;current.persisted=true;current.recovered=false;publish();
 device.unlock();return r;
}
} // namespace p12

#if U64 && P08_SERVICE && !defined(P12_STORAGE_HOST_TEST)
#include "config.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
namespace p12 {
namespace {
Status native_status_cache={UNINITIALIZED,EMPTY,false,false,false,false,false,0,0,MAX_BLOB,0,{-1,-1,-1,-1}};
class NativeDevice;
NativeDevice *native_device_pointer=0;
}
}
extern "C" bool p12_native_erase_reserved(unsigned slot,uint32_t owner);
extern "C" bool p12_native_program_reserved(unsigned slot,uint32_t owner,unsigned page,const uint8_t *data);
namespace p12 {
namespace {
class NativeDevice:public Device {
 SemaphoreHandle_t mutex;ConfigManager *manager;Flash *flash;Geometry checked;bool locked,geometry_valid;
public:
 NativeDevice():mutex(xSemaphoreCreateMutex()),manager(ConfigManager::getConfigManager()),flash(manager->get_flash_access()),locked(false),geometry_valid(false){memset(&checked,0,sizeof(checked));native_device_pointer=this;}
 bool try_lock(){if(!mutex||xSemaphoreTake(mutex,0)!=pdTRUE)return false;locked=true;return true;}
 void unlock(){locked=false;xSemaphoreGive(mutex);}
 bool geometry(Geometry &out){
  geometry_valid=false;if(!flash)return false;
  const char *type=flash->get_type_string();
  bool known=type&&(!strcmp(type,"Winbond W25Q80")||!strcmp(type,"Winbond W25Q16")||!strcmp(type,"Winbond W25Q32")||!strcmp(type,"Winbond W25Q64")||!strcmp(type,"Winbond W25Q128")||!strcmp(type,"Infineon S25FL064L")||!strcmp(type,"Infineon S25FL128L"));
  if(!known||flash->get_page_size()!=PROGRAM_BYTES||flash->get_config_page_size()!=RECORD_BYTES||flash->get_sector_size(0)!=SECTOR_BYTES)return false;
  int slots=flash->get_number_of_config_pages(),pages=flash->get_number_of_pages();
  if((slots!=16&&slots!=24)||pages<=slots*16||pages%16||pages>65536)return false;
  alignas(4) uint8_t record[RECORD_BYTES],page[PROGRAM_BYTES];unsigned first=unsigned(pages-slots*16);
  for(int s=0;s<slots;s++){
   unsigned physical=first+unsigned(s)*16;
   if(flash->get_sector_size(int(physical*PROGRAM_BYTES))!=SECTOR_BYTES||flash->page_to_sector(int(physical))!=int(physical/16)||flash->page_to_sector(int(physical+15))!=int(physical/16))return false;
   flash->read_config_page(s,RECORD_BYTES,record);
   for(unsigned p=0;p<2;p++)if(!flash->read_page(int(physical+p),page)||memcmp(page,record+p*PROGRAM_BYTES,PROGRAM_BYTES))return false;
  }
  checked.total_pages=uint32_t(pages);checked.program_bytes=PROGRAM_BYTES;checked.sector_bytes=SECTOR_BYTES;
  checked.record_bytes=RECORD_BYTES;checked.config_slots=uint16_t(slots);checked.trusted=true;out=checked;geometry_valid=true;return true;
 }
 bool read_record(unsigned slot,uint8_t out[RECORD_BYTES]){if(!geometry_valid||slot>=checked.config_slots)return false;flash->read_config_page(int(slot),RECORD_BYTES,out);return true;}
 bool read_page(uint32_t page,uint8_t out[PROGRAM_BYTES]){
  if(!geometry_valid||page<checked.total_pages-uint32_t(checked.config_slots)*16||page>=checked.total_pages)return false;
  return flash->read_page(int(page),out);
 }
 Result reserve(const bool blocked[MAX_CONFIG_SLOTS],int out[PRIVATE_SLOTS]){return Result(manager->p12_reserve_private_slots(blocked,out));}
 bool erase_reserved(unsigned slot,uint32_t owner){return p12_native_erase_reserved(slot,owner);}
 bool program_reserved(unsigned slot,uint32_t owner,unsigned page,const uint8_t data[PROGRAM_BYTES]){return p12_native_program_reserved(slot,owner,page,data);}
 void publish_status(const Status &s){portENTER_CRITICAL();native_status_cache=s;portEXIT_CRITICAL();}
 bool guard(unsigned slot,uint32_t owner,unsigned page,bool erasing,uint32_t &physical){
  if(!locked||!geometry_valid||slot>=checked.config_slots||!private_id(owner)||!manager->p12_private_slot_owned(owner,int(slot))||page>=16)return false;
  alignas(4) uint8_t record[RECORD_BYTES];flash->read_config_page(int(slot),RECORD_BYTES,record);uint32_t id=get32(record);
  if(id!=owner&&id!=0xffffffffu)return false;
  if(id==owner&&!owner_header(record,unsigned(owner-PRIVATE_ID_BASE)))return false;
  if(!erasing&&page&&id!=owner)return false;
  physical=checked.total_pages-uint32_t(checked.config_slots)*16+slot*16+page;
  return physical>=checked.total_pages-uint32_t(checked.config_slots)*16&&physical<checked.total_pages&&flash->page_to_sector(int(physical))==int(physical/16);
 }
 Flash *get_flash()const{return flash;}
};
Storage &native_storage(){static NativeDevice device;static Storage storage(device);return storage;}
}
Result initialize(){return native_storage().initialize();}
Result load(uint8_t *out,uint16_t capacity,uint16_t &length){return native_storage().load(out,capacity,length);}
Result save(const uint8_t *bytes,uint16_t length){return native_storage().save(bytes,length);}
bool persist_callback(void *,const uint8_t *bytes,uint16_t length){return save(bytes,length)==OK;}
bool get_status(Status &out){portENTER_CRITICAL();out=native_status_cache;portEXIT_CRITICAL();return true;}
}
extern "C" __attribute__((noinline)) bool p12_native_erase_reserved(unsigned slot,uint32_t owner)
{
 uint32_t physical;p12::NativeDevice *d=p12::native_device_pointer;
 if(!d||!d->guard(slot,owner,0,true,physical))return false;
 // Existing driver bounds its own SPI critical section; there is no outer
 // critical section and no service/C64/Drive lock around this operation.
 return d->get_flash()->erase_sector(int(physical/16));
}
extern "C" __attribute__((noinline)) bool p12_native_program_reserved(unsigned slot,uint32_t owner,unsigned page,const uint8_t *data)
{
 uint32_t physical;p12::NativeDevice *d=p12::native_device_pointer;
 if(!data||!d||!d->guard(slot,owner,page,false,physical))return false;
 return d->get_flash()->write_page(int(physical),data);
}
#endif
