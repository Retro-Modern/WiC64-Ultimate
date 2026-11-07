#ifndef P18_WIC64_LOG_H
#define P18_WIC64_LOG_H
#include <stdint.h>
namespace p08 {struct RequestTrace;}
#pragma pack(push, 8)
namespace p18log {
enum Level {OFF=0,ERROR=1,INFO=2,DEBUG=3};
enum Event {BEGIN=0,PHASE=1,FINISH=2,DELIVERY=3,PACKET=4,HTTP=5};
enum Color {DEFAULT=0,HOST=1,DEVICE=2,FAILURE=3};
enum CaptureFlag {REDACTED=1,TRUNCATED=2,FRAME_HEADER=4,CONTINUATION=8,URL_REDACTED=16,PROTECTED=32,
                  PUBLIC_PRG=64,PRG_LENGTH_ADJUSTED=128,HTTP_COMPLETE=128};
enum {SCHEMA=2,CAPACITY=128,PAGE_SIZE=8,SAMPLE_CAPACITY=128,URL_CAPACITY=72,
      LINE_CAPACITY=256,MAX_RECORD_LINES=12};
// Schema 2 deliberately retains only sanitized bytes. Opaque payloads, WLAN,
// known credentials and recognized protected authentication flows are redacted.
// Explicit opt-in previews may contain application data and public URL paths.
struct Entry {
 uint32_t seq,tick_ms,request_id,length,elapsed_ms,tls_tx,tls_rx;
 int32_t engine_error;
 uint16_t http_status;
 uint8_t command,protocol,event,phase,lifecycle,status,error,level;
 uint32_t wire_length,packet_offset;
 uint8_t sample[SAMPLE_CAPACITY];
 char url[URL_CAPACITY];
 uint8_t sample_length,flags,color,reserved;
};
struct Snapshot {
 Entry entries[PAGE_SIZE];
 uint32_t generation,next_after,oldest_seq,newest_seq,dropped,overwritten;
 uint8_t count,level;
 bool reset,busy,more,available,previews_enabled;
};
// Single try-lock: contention returns false/busy, never waits. initialize is
// the only allocator, and is called once at Service startup. OOM leaves the
// log unavailable; snapshots truthfully report available=false.
bool snapshot(uint32_t generation,uint32_t after,uint8_t limit,Snapshot &out);
bool initialize(uint32_t public_boot_nonce);
bool control(bool set_level,Level new_level,bool clear_ring,bool set_previews=false,bool new_previews=false);
bool configure_previews(bool enabled);
bool previews_enabled();
bool configure(Level new_level);
// Internal durable preference restore; ordinary controls still require load.
bool restore_configuration(Level,bool previews);
bool configuration(Level &,bool &previews);
bool clear();
Level level();
const char *command_name(uint8_t command);
const char *protocol_name(uint8_t protocol);
uint8_t record_color(const Entry &);
// Every transport uses these exact ASCII lines, without a newline or ANSI.
// Returns zero after the last line. Each nonzero line fits LINE_CAPACITY;
// every record has at most MAX_RECORD_LINES. Always NUL-terminates if cap>0.
unsigned format_record(const Entry &,unsigned line,char *out,unsigned capacity);
unsigned format_line(const Entry &,char *out,unsigned capacity,bool compact=false);
void record(Event,const p08::RequestTrace &);
void local_begin(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms);
void local_finish(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,
                  uint8_t status,uint8_t error,uint16_t http_status,uint32_t length);
void local_delivery(uint32_t request_id,uint8_t lifecycle,uint32_t tick_ms);
// Request: call only after the complete validated request has been accepted.
// Reply: call only after a successful mailbox publication, with its exact
// offset/count. Header bytes derive from the same published protocol/status/
// total/flags; length includes payload, wire_length includes this frame header.
void request_packet(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,
                    const uint8_t *payload,uint32_t length);
void response_packet(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,
                     uint8_t status,uint8_t response_flags,const uint8_t *payload,
                     uint32_t total,uint32_t offset,uint16_t published_count);
// URL is sanitized directly from bounded input before retention. No raw URL
// is copied into a temporary or persistent logger buffer.
void http_detail(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,
                 const uint8_t *url,uint32_t length,uint16_t status=0,bool protected_flow=false,
                 const uint8_t *raw_request=0,uint32_t raw_length=0);
// Called with the actual final HTTP body length/status. A credential-bearing
// response must mark protected_flow before any reply publication or preview.
void http_result(uint8_t command,uint8_t protocol,uint32_t request_id,uint32_t tick_ms,
                 const uint8_t *url,uint32_t length,uint16_t status,uint32_t body_length,
                 bool protected_flow=false);
#if defined(P18_LOG_HOST_TEST)
void test_reset();
bool test_force_sequence(uint32_t next);
bool test_force_counters(uint32_t generation,uint32_t dropped,uint32_t overwritten);
bool test_hold_lock(bool acquire);
bool test_contains(const uint8_t *bytes,unsigned length);
void test_fail_allocation(bool fail);
#endif
}
#pragma pack(pop)
#endif
