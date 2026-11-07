#ifndef P14_TLS_H
#define P14_TLS_H
#include <stdint.h>

namespace p08 { struct BackendContext; }
namespace p14 {

enum TlsError {
    TLS_OK=0, TLS_ARGUMENT, TLS_MEMORY, TLS_UNSEEDED,
    TLS_TIME_UNAVAILABLE, TLS_HANDSHAKE, TLS_VERIFY,
    TLS_READ, TLS_WRITE, TLS_DEADLINE, TLS_CANCELLED
};

// The socket remains owned by the caller. send/recv must be nonblocking and
// return >=0 bytes, -1 on a fatal error, or -2 when the socket would block.
// wait uses the SAME complete-request deadline and cancellation state.
struct TlsIo {
    void *context;
    int (*send)(void *,const uint8_t *,uint32_t);
    int (*recv)(void *,uint8_t *,uint32_t);
    bool (*wait)(void *,bool writing);
    bool (*cancelled)(void *);
    uint32_t (*remaining_ms)(void *);
};

class TlsStream {
    void *state_;
    TlsError error_;
    TlsStream(const TlsStream &)=delete;
    TlsStream &operator=(const TlsStream &)=delete;
    TlsError connect_mode(const char *,bool,const TlsIo &,p08::BackendContext &,bool);
public:
    TlsStream();
    ~TlsStream();
    // The backend owns its provisioned private NV seed. It is consulted only
    // to initialize/reseed the process-wide DRBG, never for each connection.
    TlsError connect(const char *host,bool numeric_host,const TlsIo &,p08::BackendContext &);
    // Persistent TCP negotiates bounded operation windows before ESP BEGIN.
    // The legacy connect API retains its complete-HTTP-request deadline.
    TlsError connect_persistent(const char *host,bool numeric_host,const TlsIo &,p08::BackendContext &);
    TlsError begin_operation();
    TlsError end_operation();
    int read(uint8_t *,uint32_t);
    // One nonblocking TLS read. -2 means WANT_READ/WRITE, not a failure.
    int read_available(uint8_t *,uint32_t);
    int write(const uint8_t *,uint32_t);
    TlsError error() const {return error_;}
};

const char *tls_error_name(TlsError);
// Only the service's durable fresh-seed import may reset this process-wide
// state. Ordinary Stop/Start and program/session changes must not call it.
bool tls_forget_entropy();

#if defined(P14_TLS_HOST_TEST)
// Owned test processes only: production has no interface to replace roots or
// disable verification. Call before creating any TLS stream in that process.
bool tls_test_trust_pem(const uint8_t *,uint32_t);
void tls_test_reset_rng();
#endif
}
#endif
