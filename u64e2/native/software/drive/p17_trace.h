#ifndef P17_REQUEST_TRACE_H
#define P17_REQUEST_TRACE_H
#include <stdint.h>
#include <string.h>
#if defined(P18_LOG) && P18_LOG
#include "p18_log.h"
#endif
#if defined(P08_HTTP_HOST) || defined(P14_TLS_HOST_TEST) || defined(P14_PLATFORM_HOST_TEST) || defined(P08_SERVICE_HOST_TEST)
#include <mutex>
#endif
#if defined(P08_HTTP_HOST) || defined(P14_TLS_HOST_TEST) || defined(P14_PLATFORM_HOST_TEST)
#include <time.h>
#else
#include "FreeRTOS.h"
#include "task.h"
#endif

#pragma pack(push, 8)
namespace p08 {
// One bounded network-operation record, retained across status/metadata reads.
// It never contains an endpoint, SSID, MAC,
// payload, credential, certificate, seed, hash or fingerprint.
enum TracePhase {
 TRACE_NONE=0, TRACE_COMMAND, TRACE_DNS, TRACE_CONNECT,
 TRACE_TLS_LIBRARY, TRACE_TLS_ENTROPY, TRACE_TLS_TRUST,
 TRACE_TLS_SESSION, TRACE_TLS_HANDSHAKE,
 TRACE_HTTP_WRITE, TRACE_HTTP_HEADERS, TRACE_HTTP_BODY, TRACE_PHASE_COUNT
};
enum TraceLifecycle {
 TRACE_IDLE=0, TRACE_EXECUTING, TRACE_BACKEND_DONE, TRACE_RESPONSE_READY,
 TRACE_WAIT_DIRECTION, TRACE_INITIAL_GRANT, TRACE_COMPLETE, TRACE_ABANDONED
};
enum TraceCryptoKind {
 TRACE_CRYPTO_NONE=0, TRACE_CRYPTO_ECC_KEYGEN, TRACE_CRYPTO_ECC_VERIFY,
 TRACE_CRYPTO_ECC_SHARED, TRACE_CRYPTO_RSA_PKCS1, TRACE_CRYPTO_RSA_PSS,
 TRACE_CRYPTO_KIND_COUNT
};
struct CryptoTraceBin {
 uint32_t total_tick_ms,max_tick_ms,calls;
 uint16_t last_bits,max_bits;
};
struct RequestTrace {
 uint32_t sequence,request_id,started_tick_ms,touched_tick_ms,phase_tick_ms;
 uint32_t phase_elapsed_tick_ms[TRACE_PHASE_COUNT],elapsed_tick_ms;
 uint32_t backend_elapsed_tick_ms,grant_elapsed_tick_ms,response_length;
 uint32_t remote_budget_ms,tls_connect_calls,tls_call_started_tick_ms;
 uint32_t tls_last_call_tick_ms,tls_max_call_tick_ms;
 uint32_t tls_inflight_tick_ms,tls_send_calls,tls_recv_calls;
 uint32_t tls_sent_bytes,tls_received_bytes;
 // Time spent inside send/receive callbacks, including budget checks.
 // Outer readiness waits and cryptographic work are deliberately excluded.
 uint32_t tls_io_tick_ms,tls_io_max_tick_ms;
 // Bounded public-primitive timing. Bins count entered outer calls; elapsed
 // totals and maxima include completed calls only, never unfinished work.
 CryptoTraceBin crypto[TRACE_CRYPTO_KIND_COUNT-1];
 uint32_t crypto_total_tick_ms,crypto_last_call_tick_ms,crypto_max_call_tick_ms;
 uint32_t crypto_call_started_tick_ms,crypto_inflight_tick_ms;
 uint16_t crypto_last_bits,crypto_max_bits,crypto_active_bits;
 uint8_t crypto_last_kind,crypto_max_kind,crypto_active_kind;
 bool crypto_call_active,crypto_call_interrupted;
 int32_t engine_error;
 uint16_t progress,progress_total,http_status;
 uint8_t command,protocol,phase,lifecycle,status,error;
 bool tls_call_active,tls_call_interrupted;
};
inline uint32_t trace_now_ms() {
#if defined(P08_HTTP_HOST) || defined(P14_TLS_HOST_TEST) || defined(P14_PLATFORM_HOST_TEST)
 timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
 return uint32_t(uint64_t(t.tv_sec)*1000+uint32_t(t.tv_nsec/1000000));
#else
 return uint32_t(xTaskGetTickCount())*(1000U/configTICK_RATE_HZ);
#endif
}
#if defined(P08_HTTP_HOST) || defined(P14_TLS_HOST_TEST) || defined(P14_PLATFORM_HOST_TEST) || defined(P08_SERVICE_HOST_TEST)
inline std::mutex &trace_mutex(){static std::mutex m;return m;}
struct TraceGuard {std::lock_guard<std::mutex> lock;TraceGuard():lock(trace_mutex()){} };
#else
struct TraceGuard {TraceGuard(){portENTER_CRITICAL();}~TraceGuard(){portEXIT_CRITICAL();}};
#endif
inline bool trace_running(const RequestTrace &r){return r.lifecycle==TRACE_EXECUTING;}
inline bool trace_command(uint8_t command) {
 return command==0x01||command==0x0f||command==0x2b||command==0x3f||
  command==0x21||command==0x22||command==0x23||command==0x2e||command==0x30||command==0x40||
  command==0x0a||command==0x0b||command==0x0e||command==0x1e||command==0x1f||
  command==0x33||command==0x34||command==0x35||command==0x3e;
}
inline void trace_accrue(RequestTrace &r,uint32_t now) {
 if(trace_running(r)&&r.phase<TRACE_PHASE_COUNT){
  r.phase_elapsed_tick_ms[r.phase]+=uint32_t(now-r.phase_tick_ms);r.phase_tick_ms=now;
 }
 r.touched_tick_ms=now;r.elapsed_tick_ms=uint32_t(now-r.started_tick_ms);
}
inline void trace_begin(RequestTrace &r,uint8_t command,uint8_t protocol,uint32_t request_id=0) {
 if(!trace_command(command))return;
 TraceGuard guard;uint32_t sequence=r.sequence+1;if(!sequence)sequence=1;
 memset(&r,0,sizeof(r));r.sequence=sequence;r.request_id=request_id;
 r.command=command;r.protocol=protocol;r.phase=TRACE_COMMAND;r.lifecycle=TRACE_EXECUTING;
 r.started_tick_ms=r.touched_tick_ms=r.phase_tick_ms=trace_now_ms();
#if defined(P18_LOG) && P18_LOG
 p18log::record(p18log::BEGIN,r);
#endif
}
inline void trace_enter_backend(RequestTrace &r,uint8_t command,uint8_t protocol) {
 if(!trace_command(command))return;
 // Service starts the record before dispatch so local commands are included.
 // Standalone backend clients start a record here instead.
 bool reuse;{TraceGuard guard;reuse=trace_running(r)&&r.request_id&&r.command==command&&r.protocol==protocol;}
 if(!reuse)trace_begin(r,command,protocol);
}
inline void trace_phase(RequestTrace &r,TracePhase phase,uint16_t current=0,uint16_t total=0) {
 TraceGuard guard;if(!trace_running(r)||phase>=TRACE_PHASE_COUNT)return;
 bool changed=r.phase!=uint8_t(phase);trace_accrue(r,trace_now_ms());r.phase=uint8_t(phase);r.progress=current;r.progress_total=total;
#if defined(P18_LOG) && P18_LOG
 if(changed)p18log::record(p18log::PHASE,r);
#else
 (void)changed;
#endif
}
inline void trace_engine_error(RequestTrace &r,int32_t error) {
 TraceGuard guard;if(trace_running(r))r.engine_error=error;
}
inline void trace_remote_budget(RequestTrace &r,uint32_t milliseconds) {
 TraceGuard guard;if(trace_running(r))r.remote_budget_ms=milliseconds;
}
inline void trace_tls_call_begin(RequestTrace &r) {
 TraceGuard guard;if(!trace_running(r))return;
 r.tls_connect_calls++;r.tls_call_started_tick_ms=trace_now_ms();r.tls_inflight_tick_ms=0;r.tls_call_active=true;r.tls_call_interrupted=false;
}
inline void trace_tls_call_end(RequestTrace &r) {
 TraceGuard guard;if(!trace_running(r)||!r.tls_call_active)return;
 r.tls_last_call_tick_ms=uint32_t(trace_now_ms()-r.tls_call_started_tick_ms);
 if(r.tls_last_call_tick_ms>r.tls_max_call_tick_ms)r.tls_max_call_tick_ms=r.tls_last_call_tick_ms;
 r.tls_call_active=false;r.tls_inflight_tick_ms=0;
}
inline void trace_tls_io(RequestTrace &r,bool writing,int count) {
 TraceGuard guard;if(!trace_running(r))return;
 if(writing){r.tls_send_calls++;if(count>0)r.tls_sent_bytes+=uint32_t(count);}
 else {r.tls_recv_calls++;if(count>0)r.tls_received_bytes+=uint32_t(count);}
}
inline void trace_tls_io_time(RequestTrace &r,uint32_t elapsed) {
 TraceGuard guard;if(!trace_running(r))return;
 // Saturate an aggregate rather than displaying a wrapped, smaller duration.
 const uint32_t room=0xffffffffu-r.tls_io_tick_ms;
 r.tls_io_tick_ms=elapsed>room?0xffffffffu:r.tls_io_tick_ms+elapsed;
 if(elapsed>r.tls_io_max_tick_ms)r.tls_io_max_tick_ms=elapsed;
}
inline uint32_t trace_saturating_add(uint32_t value,uint32_t amount) {
 return amount>0xffffffffu-value?0xffffffffu:value+amount;
}
inline uint32_t trace_crypto_call_begin(RequestTrace &r,TraceCryptoKind kind,uint16_t bits) {
 TraceGuard guard;
 if(!trace_running(r)||!r.sequence||r.crypto_call_active||kind<=TRACE_CRYPTO_NONE||kind>=TRACE_CRYPTO_KIND_COUNT)return 0;
 CryptoTraceBin &bin=r.crypto[unsigned(kind)-1];
 bin.calls=trace_saturating_add(bin.calls,1);
 r.crypto_active_kind=uint8_t(kind);r.crypto_active_bits=bits;
 r.crypto_call_started_tick_ms=trace_now_ms();r.crypto_inflight_tick_ms=0;
 r.crypto_call_active=true;r.crypto_call_interrupted=false;
 return r.sequence;
}
inline void trace_crypto_call_end(RequestTrace &r,uint32_t sequence) {
 TraceGuard guard;
 if(!sequence||!trace_running(r)||r.sequence!=sequence||!r.crypto_call_active)return;
 unsigned kind=r.crypto_active_kind;
 if(kind<=TRACE_CRYPTO_NONE||kind>=TRACE_CRYPTO_KIND_COUNT)return;
 uint32_t elapsed=uint32_t(trace_now_ms()-r.crypto_call_started_tick_ms);
 CryptoTraceBin &bin=r.crypto[kind-1];
 bin.total_tick_ms=trace_saturating_add(bin.total_tick_ms,elapsed);
 bin.last_bits=r.crypto_active_bits;
 if(elapsed>=bin.max_tick_ms){bin.max_tick_ms=elapsed;bin.max_bits=r.crypto_active_bits;}
 r.crypto_total_tick_ms=trace_saturating_add(r.crypto_total_tick_ms,elapsed);
 r.crypto_last_call_tick_ms=elapsed;r.crypto_last_kind=uint8_t(kind);r.crypto_last_bits=r.crypto_active_bits;
 if(!r.crypto_max_kind||elapsed>r.crypto_max_call_tick_ms){r.crypto_max_call_tick_ms=elapsed;r.crypto_max_kind=uint8_t(kind);r.crypto_max_bits=r.crypto_active_bits;}
 r.crypto_call_active=false;r.crypto_inflight_tick_ms=0;
 r.crypto_active_kind=TRACE_CRYPTO_NONE;r.crypto_active_bits=0;
}
// Called under TraceGuard, like the surrounding TLS interval freeze.
inline void trace_interrupt_crypto_call(RequestTrace &r,uint32_t now) {
 if(!r.crypto_call_active)return;
 r.crypto_inflight_tick_ms=uint32_t(now-r.crypto_call_started_tick_ms);
 r.crypto_call_active=false;r.crypto_call_interrupted=true;
}
// Called only under TraceGuard. Preserve the last observed unfinished interval
// without making a terminal snapshot look like a still-live TLS call.
inline void trace_interrupt_tls_call(RequestTrace &r,uint32_t now) {
 if(!r.tls_call_active)return;
 r.tls_inflight_tick_ms=uint32_t(now-r.tls_call_started_tick_ms);
 r.tls_call_active=false;r.tls_call_interrupted=true;
}
inline void trace_finish(RequestTrace &r,uint8_t status,uint8_t error,uint16_t http_status,uint32_t length) {
 TraceGuard guard;if(!trace_running(r))return;
 uint32_t now=trace_now_ms();trace_accrue(r,now);trace_interrupt_tls_call(r,now);trace_interrupt_crypto_call(r,now);r.backend_elapsed_tick_ms=r.elapsed_tick_ms;
 r.status=status;r.error=error;r.http_status=http_status;r.response_length=length;
 if(!status)r.engine_error=0;
 r.lifecycle=TRACE_BACKEND_DONE;
#if defined(P18_LOG) && P18_LOG
 p18log::record(p18log::FINISH,r);
#endif
}
inline void trace_service_state(RequestTrace &r,uint32_t request_id,TraceLifecycle lifecycle) {
 TraceGuard guard;if(!r.sequence||r.request_id!=request_id){
#if defined(P18_LOG) && P18_LOG
  p18log::local_delivery(request_id,uint8_t(lifecycle),trace_now_ms());
#endif
  return;
 }
 if(r.lifecycle==TRACE_COMPLETE||r.lifecycle==TRACE_ABANDONED)return;
 bool changed=r.lifecycle!=uint8_t(lifecycle);uint32_t now=trace_now_ms();trace_accrue(r,now);r.lifecycle=uint8_t(lifecycle);
 if(lifecycle==TRACE_COMPLETE||lifecycle==TRACE_ABANDONED){trace_interrupt_tls_call(r,now);trace_interrupt_crypto_call(r,now);}
 if(lifecycle==TRACE_INITIAL_GRANT)r.grant_elapsed_tick_ms=r.elapsed_tick_ms;
#if defined(P18_LOG) && P18_LOG
 if(changed)p18log::record(p18log::DELIVERY,r);
#else
 (void)changed;
#endif
}
inline void trace_snapshot(const RequestTrace &r,RequestTrace &out) {
 TraceGuard guard;out=r;
 if(out.sequence&&out.lifecycle!=TRACE_COMPLETE&&out.lifecycle!=TRACE_ABANDONED)
  trace_accrue(out,trace_now_ms());
 if(out.tls_call_active)out.tls_inflight_tick_ms=uint32_t(trace_now_ms()-out.tls_call_started_tick_ms);
 if(out.crypto_call_active)out.crypto_inflight_tick_ms=uint32_t(trace_now_ms()-out.crypto_call_started_tick_ms);
}
inline const char *trace_crypto_kind_name(unsigned kind) {
 static const char *names[]={"None","ECC keygen","ECC verify","ECC shared","RSA PKCS1","RSA PSS"};
 return kind<TRACE_CRYPTO_KIND_COUNT?names[kind]:"Unknown";
}
inline const char *trace_phase_name(unsigned phase) {
 static const char *names[]={"NONE","COMMAND","DNS","CONNECT","TLS_LIBRARY",
  "TLS_ENTROPY","TLS_TRUST","TLS_SESSION","TLS_HANDSHAKE","HTTP_WRITE","HTTP_HEADERS","HTTP_BODY"};
 return phase<TRACE_PHASE_COUNT?names[phase]:"UNKNOWN";
}
inline const char *trace_lifecycle_name(unsigned state) {
 static const char *names[]={"IDLE","EXECUTING","BACKEND_DONE","RESPONSE_READY",
  "WAIT_DIRECTION","INITIAL_GRANT","COMPLETE","ABANDONED"};
 return state<=TRACE_ABANDONED?names[state]:"UNKNOWN";
}
}
#pragma pack(pop)
#endif
