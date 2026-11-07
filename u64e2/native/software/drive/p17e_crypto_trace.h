#ifndef P17E_CRYPTO_TRACE_H
#define P17E_CRYPTO_TRACE_H

namespace p08 { struct RequestTrace; }
namespace p14 {
// Bind only around a synchronous wolfSSL_connect call while the existing
// single-client TLS engine lease is held. Destruction precedes lease release.
// No endpoint, certificate, signature, key or hash bytes enter this record.
class CryptoTraceScope {
    p08::RequestTrace *trace_;
    CryptoTraceScope(const CryptoTraceScope &)=delete;
    CryptoTraceScope &operator=(const CryptoTraceScope &)=delete;
public:
    explicit CryptoTraceScope(p08::RequestTrace &);
    ~CryptoTraceScope();
};
}
#endif
