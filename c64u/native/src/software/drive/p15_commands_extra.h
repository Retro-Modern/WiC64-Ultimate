#ifndef P15_COMMANDS_EXTRA_H
#define P15_COMMANDS_EXTRA_H
#include "p08_http.h"
namespace p08 {
bool p15_execute_extra(BackendContext &,uint8_t command,uint8_t protocol,
    const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &);
#if defined(P08_HTTP_HOST)
// Explicit modeled clock/settings only; production always uses verified UTC
// and the dedicated native nonsecret configuration page.
struct P15ExtraTestOps {
    void *context;
    bool (*utc)(void *,uint64_t &);
    uint32_t (*milliseconds)(void *);
    void (*delay)(void *,uint32_t);
    uint8_t (*timezone)(void *);
    bool (*save_timezone)(void *,uint8_t);
    bool (*load_server)(void *,char *,uint32_t);
    bool (*save_server)(void *,const char *);
};
void p15_extra_test_ops(const P15ExtraTestOps &);
#endif
}
#endif
