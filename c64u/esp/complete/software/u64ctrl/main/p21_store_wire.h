#ifndef P21_STORE_WIRE_H
#define P21_STORE_WIRE_H
#include <stdint.h>
#include <stddef.h>
/* Private UART store, independent of unchanged TLS command 0x20.
 * Header28: echoed rpc[4], 'WS21'[4], version, op/status, bodyLE16,
 * tokenLE64, argLE32, request-budget-ms / reply-detailLE32.
 * CAPS: empty/zero request -> OK body[featuresLE32=3,maxLE32=3900,chunkLE16=1024,reservedLE16=0].
 * LOAD: token/arg/body=0, budget1..15000 -> BUSY+new token. STATUS then
 *   OK+LOADED+meta16 or EMPTY+LOADED+zero meta16. No namespace creation.
 * BEGIN: token/arg=0, body meta16(expected-generation,total,CRC), budget
 *   1..15000 -> BUSY+new token. Worker validates existing record/CAS;
 *   STATUS -> OK+STAGING+meta16(next-generation,total,CRC), or CONFLICT/BLOCKED.
 * WRITE: token, arg=strict next byte offset, nonempty body<=1024, budget0; OK header-only replyarg=next offset.
 * COMMIT: token, body/arg/budget0 -> BUSY until verified DURABLE; repeated
 *   COMMIT/STATUS with SAME token only queries, never writes a second time.
 * STATUS: token, body/arg/budget0 -> phase in arg, meta16 on OK/EMPTY,
 *   UNKNOWN means a write may have landed; resolve by a new LOAD after idle.
 * READ: token, arg=byte offset, bodyLE16=max-count1..1024, budget0;
 *   only LOADED snapshot; OK body chunk, replyarg=offset; EOF empty allowed.
 * CLOSE: token, all other fields0. Discards snapshot/staging only. Inflight
 *   COMMIT cannot be cancelled: UNKNOWN until worker result, no durable erase.
 * EMPTY is distinct from corrupt/unknown-schema/unavailable BLOCKED. Client
 * must never replace a BLOCKED/UNKNOWN load with an empty successful store.
 * Meta16: generationLE64,lengthLE32,CRC32IEEELE32. Generation0 means absent;
 * successful COMMIT increments exactly once. Payload is opaque, max3900.
 * CRC detects corruption, not authentication. No secret bodies may be logged.
 */
#define P21_STORE_COMMAND 0x21
#define P21_STORE_VERSION 1
#define P21_STORE_HEADER 28
#define P21_STORE_CHUNK 1024
#define P21_STORE_MAX 3900
#define P21_STORE_MAX_BUDGET 15000
#define P21_STORE_META 16
#define P21_WIFI_SAVE_FAILED 0x7f21
#define P21_STORE_FEATURES 3U
#define P21_STORE_FEATURE_PERSISTENCE 1U
#define P21_STORE_FEATURE_DURABLE_WIFI 2U
enum p21_store_op {P21_STORE_CAPS=0,P21_STORE_LOAD=1,P21_STORE_BEGIN=2,
 P21_STORE_WRITE=3,P21_STORE_COMMIT=4,P21_STORE_STATUS=5,P21_STORE_CLOSE=6,P21_STORE_READ=7};
enum p21_store_status {P21_STORE_OK=0,P21_STORE_BUSY=1,P21_STORE_EMPTY=2,
 P21_STORE_BAD=3,P21_STORE_BLOCKED=4,P21_STORE_CONFLICT=5,P21_STORE_TIMEOUT=6,
 P21_STORE_FAILED=7,P21_STORE_UNKNOWN=8,P21_STORE_CLOSED=9};
enum p21_store_phase {P21_STORE_IDLE=0,P21_STORE_LOADING=1,P21_STORE_LOADED=2,
 P21_STORE_CHECKING=3,P21_STORE_STAGING=4,P21_STORE_COMMITTING=5,P21_STORE_DURABLE=6,P21_STORE_STOPPED=7};
static inline uint16_t p21_get16(const uint8_t*p){return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
static inline uint32_t p21_get32(const uint8_t*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline uint64_t p21_get64(const uint8_t*p){return (uint64_t)p21_get32(p)|((uint64_t)p21_get32(p+4)<<32);}
static inline void p21_put16(uint8_t*p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static inline void p21_put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static inline void p21_put64(uint8_t*p,uint64_t v){p21_put32(p,(uint32_t)v);p21_put32(p+4,(uint32_t)(v>>32));}
static inline int p21_magic(const uint8_t*p){return p[4]=='W'&&p[5]=='S'&&p[6]=='2'&&p[7]=='1';}
static inline void p21_envelope(uint8_t*p,uint8_t op,uint16_t n,uint64_t token,uint32_t arg,uint32_t detail){
 p[4]='W';p[5]='S';p[6]='2';p[7]='1';p[8]=P21_STORE_VERSION;p[9]=op;
 p21_put16(p+10,n);p21_put64(p+12,token);p21_put32(p+20,arg);p21_put32(p+24,detail);
}
static inline uint32_t p21_crc32(const uint8_t*p,size_t n){uint32_t c=0xffffffffU;while(n--){c^=*p++;for(unsigned b=0;b<8;b++)c=(c>>1)^((0U-(c&1U))&0xedb88320U);}return ~c;}
#endif
