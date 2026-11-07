#ifndef P18_TLS_WIRE_H
#define P18_TLS_WIRE_H
#include <stdint.h>
#include <stddef.h>
/* Additive UART extension; every legacy command and rpc_header remains unchanged.
 * No wire structs: explicit little-endian byte access avoids cross-CPU ABI drift.
 * Request: rpc_header[4], magic[4], version[1], op[1], body_len[2],
 * token[8], arg[4], remaining_budget_ms[4], body[0..1024].
 * Reply: same, but byte9=status, arg=state flags and offset24=signed TLS detail.
 */
#define P18_TLS_COMMAND 0x20
#define P18_TLS_VERSION 1
#define P18_TLS_HEADER 28
#define P18_TLS_CHUNK 1024
#define P18_TLS_MAX_BUDGET 60000
#define P18_TLS_CAP_FEATURES 15U
#define P18_TLS_CAP_OPERATION_WINDOWS 16U
#define P18_TLS_CAP_TRUSTED_CA 32U
#define P18_TLS_OPERATION_QUERY 0x4f503138U
#define P18_TLS_CA_QUERY 0x43413131U
#define P18_TLS_BEGIN_PERSISTENT 1U
#define P18_TLS_FLAG_READY 1U
#define P18_TLS_FLAG_WRITE_DONE 2U
#define P18_TLS_FLAG_CLEAN_EOF 4U
#define P18_TLS_PUMP_EOF 1U
/* BEGIN body: trusted UTC seconds[8], fresh private entropy[64], DNS hostname
 * with one terminating NUL (1..253 ASCII hostname bytes). No IP literal support
 * in v1: CPU selects its existing native TLS path before BEGIN for numeric hosts.
 * CAPS body reply: feature mask[4], max chunk[2], reserved zero[2].
 * Optional BOOTSTRAP request has no body/token/arg/budget. OK returns exactly
 * 32 fresh private bytes and zero token/state/detail; CAPS stays unchanged.
 * Older v1 services may return BAD for this optional operation.
 * PUMP request body feeds encrypted TCP input, arg bit0 marks transport EOF;
 * its reply drains encrypted output. No retries after an ambiguous RPC loss.
 * WRITE queues one <=1024 plaintext block. PUMP/STATUS reports WRITE_DONE only
 * after its entire block was encrypted; next WRITE clears WRITE_DONE.
 * READ drains <=arg (1..1024) plaintext, reports EOF only after close_notify.
 * CLOSE requests abort and never destroys an active worker's TLS context.
 * One bounded TLS session; its worker alone owns the TLS MbedTLS contexts.
 * TLS dispatch uses bounded copies and never waits for session crypto or keeps
 * a UART buffer. BOOTSTRAP uses its own bounded, exclusively owned boot DRBG.
 * A normal CAPS query (arg0) always retains the legacy feature mask15. An
 * optional CAPS arg=P18_TLS_OPERATION_QUERY reports operation-window support;
 * CAPS arg=P18_TLS_CA_QUERY additionally reports trusted-CA chain building.
 * Both use the same eight-byte body; unknown queries return BAD.
 * an explicit BAD or missing window bit permits CPU native fallback BEFORE
 * BEGIN only. Persistent BEGIN arg1 requires this successful negotiation.
 * Legacy BEGIN arg0 starts the unchanged total session deadline for HTTP.
 * Persistent BEGIN starts bounded handshake window0; OPERATION budget0/seq0
 * ends it only after worker/write/output quiescence. A later OPERATION with
 * positive remaining budget starts exactly the next nonzero sequence while
 * idle. OPERATION budget0/currentseq ends that window. END may report BUSY:
 * drain/pump it under the SAME CPU operation deadline, without replaying a
 * missing RPC. Duplicate START, old sequences and wrapping sequences fail.
 * PUMP/STATUS/READ/WRITE never renew any deadline. Session UTC remains anchored
 * to BEGIN independently of operation windows. One CPU command owns one window,
 * including all of its available/read/write chunks; HTTP remains legacy mode.
 */
enum p18_tls_op {P18_TLS_CAPS=0,P18_TLS_BEGIN=1,P18_TLS_PUMP=2,
 P18_TLS_WRITE=3,P18_TLS_READ=4,P18_TLS_CLOSE=5,P18_TLS_STATUS=6,P18_TLS_BOOTSTRAP=7,
 P18_TLS_OPERATION=8};
enum p18_tls_status {P18_TLS_OK=0,P18_TLS_WANT=1,P18_TLS_EOF=2,
 P18_TLS_BAD=3,P18_TLS_BUSY=4,P18_TLS_TIMEOUT=5,P18_TLS_VERIFY=6,
 P18_TLS_FAILED=7,P18_TLS_CLOSED=8};
static inline uint16_t p18_get16(const uint8_t*p){return (uint16_t)p[0]|((uint16_t)p[1]<<8);}
static inline uint32_t p18_get32(const uint8_t*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline uint64_t p18_get64(const uint8_t*p){return (uint64_t)p18_get32(p)|((uint64_t)p18_get32(p+4)<<32);}
static inline void p18_put16(uint8_t*p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static inline void p18_put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static inline void p18_put64(uint8_t*p,uint64_t v){p18_put32(p,(uint32_t)v);p18_put32(p+4,(uint32_t)(v>>32));}
static inline int p18_magic(const uint8_t*p){return p[4]=='W'&&p[5]=='T'&&p[6]=='1'&&p[7]=='8';}
static inline void p18_envelope(uint8_t*p,uint8_t op,uint16_t n,uint64_t token,uint32_t arg,uint32_t budget){
 p[4]='W';p[5]='T';p[6]='1';p[7]='8';p[8]=P18_TLS_VERSION;p[9]=op;
 p18_put16(p+10,n);p18_put64(p+12,token);p18_put32(p+20,arg);p18_put32(p+24,budget);
}
#endif
