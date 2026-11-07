#ifndef P12_STORAGE_H
#define P12_STORAGE_H
#include <stdint.h>
namespace p12 {
enum {MAX_BLOB=6000, BANKS=2, PARTS=2, PRIVATE_SLOTS=4, MAX_CONFIG_SLOTS=24,
      PROGRAM_BYTES=256, SECTOR_BYTES=4096, RECORD_BYTES=512, HEADER_BYTES=64};
static const uint32_t PRIVATE_ID_BASE=0x57494330u;
inline bool private_id(uint32_t id){return id>=PRIVATE_ID_BASE&&id<PRIVATE_ID_BASE+PRIVATE_SLOTS;}
enum Result {OK,EMPTY,BUSY,UNSUPPORTED_FLASH,NO_SPACE,COLLISION,CORRUPT,IO_ERROR,VERIFY_FAILED,TOO_LARGE,GENERATION_EXHAUSTED};
enum State {UNINITIALIZED,EMPTY_STATE,READY,WRITING,ERROR_STATE};
struct Status {
 State state;Result last_error;bool initialized,writable,dirty,persisted,recovered;
 uint32_t generation;uint16_t length,capacity,config_slots;int16_t slots[PRIVATE_SLOTS];
};
struct Geometry {uint32_t total_pages;uint16_t program_bytes,sector_bytes,record_bytes,config_slots;bool trusted;};
/* Pure bounded allocator shared with ConfigManager and host tests. A set bit
   excludes native in-memory reservations and non-erased unowned sectors. */
Result select_slots(const uint32_t *ids,const bool *blocked,unsigned count,const int previous[PRIVATE_SLOTS],int out[PRIVATE_SLOTS]);
class Device {
public:
 virtual ~Device(){}
 virtual bool try_lock()=0;virtual void unlock()=0;
 virtual bool geometry(Geometry &out)=0;
 virtual bool read_record(unsigned slot,uint8_t out[RECORD_BYTES])=0;
 virtual bool read_page(uint32_t page,uint8_t out[PROGRAM_BYTES])=0;
 virtual Result reserve(const bool blocked[MAX_CONFIG_SLOTS],int out[PRIVATE_SLOTS])=0;
 virtual bool erase_reserved(unsigned slot,uint32_t owner)=0;
 virtual bool program_reserved(unsigned slot,uint32_t owner,unsigned page,const uint8_t data[PROGRAM_BYTES])=0;
 virtual void publish_status(const Status &){}
};
class Storage {
 Device &device;Geometry shape;Status current;int active_bank;
 bool inspect();Result inspect_result;bool read_io_failed;
 bool read_header(unsigned part,uint8_t header[HEADER_BYTES]);
 bool read_bank(unsigned bank,uint8_t *out,uint16_t capacity,uint32_t &generation,uint16_t &length,const uint8_t *compare=0,bool *equal=0);
 void publish();Result fail(Result result,bool dirty);
 uint32_t page_for(unsigned part,unsigned within)const;
public:
 explicit Storage(Device &backend);
 Result initialize();
 Result load(uint8_t *out,uint16_t capacity,uint16_t &length);
 Result save(const uint8_t *bytes,uint16_t length);
 Status status()const{return current;}
};
const char *result_name(Result);const char *state_name(State);
/* Global native access. Initialize/load after native configuration registration.
   All I/O must occur without service/C64/Drive locks. The status is cached POD,
   copied under only a short critical section; it never contains secret bytes. */
Result initialize();Result load(uint8_t *out,uint16_t capacity,uint16_t &length);
Result save(const uint8_t *bytes,uint16_t length);
bool persist_callback(void *,const uint8_t *bytes,uint16_t length);
bool get_status(Status &out);
}
#endif
