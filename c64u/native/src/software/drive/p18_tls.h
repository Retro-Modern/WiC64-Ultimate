#ifndef P18_TLS_H
#define P18_TLS_H
#include "p14_tls.h"
#include "p18_tls_wire.h"
namespace p18 {
/* Fallback is permitted only for an explicit stock UNSUPPORTED response or
 * absent capability transport before BEGIN. Once BEGIN
 * was attempted, no request can be replayed through the native TLS backend. */
const char *engine_name();
void native_engine_selected();
// Optional private bootstrap operation. Returns only a validated fresh seed;
// every failure leaves out[32] zero. No TLS/session or HTTP request is begun.
bool bootstrap_seed(uint8_t out[32],uint32_t timeout_ms);
enum ProbeResult { PROBE_SUPPORTED, PROBE_UNSUPPORTED, PROBE_FAILED };
class Stream {
    p14::TlsIo io_;
    p08::BackendContext *backend_;
    p14::TlsError error_;
    uint64_t token_;
    uint32_t flags_,operation_sequence_;
    bool tcp_eof_,eof_sent_,started_,drain_next_,persistent_,operation_active_;
    uint8_t frame_[P18_TLS_HEADER+P18_TLS_CHUNK];
    uint8_t input_[P18_TLS_CHUNK],output_[P18_TLS_CHUNK];
    uint16_t input_n_,output_n_,output_at_,body_n_;
    bool budget();
    bool healthy() const;
    bool transact(uint8_t,uint32_t,const uint8_t *,uint16_t,bool begin=false,bool finish=false);
    bool flush();
    bool pump();
    bool pause();
    bool status_ok();
public:
    Stream(const p14::TlsIo &,p08::BackendContext &,bool persistent=false);
    ~Stream();
    ProbeResult probe();
    p14::TlsError connect(const char *);
    // One persistent TCP command owns one window, never one read/write chunk.
    bool begin_operation();
    bool end_operation();
    int read(uint8_t *,uint32_t,bool available=false);
    int write(const uint8_t *,uint32_t);
    p14::TlsError error() const{return error_;}
};
}
#endif
