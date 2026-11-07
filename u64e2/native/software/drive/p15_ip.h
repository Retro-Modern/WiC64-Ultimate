#ifndef P15_IP_H
#define P15_IP_H
#include "p08_http.h"
namespace p08 {
struct P15IpSettings { bool dhcp; char address[5][16]; };
struct P15IpSnapshot {
    bool dhcp; char active[5][16]; char configured[5][16];
};
struct P15IpOps {
    void *context;
    bool (*snapshot)(void *,const NetworkInfo &,P15IpSnapshot &);
    bool (*selected)(void *,const NetworkInfo &,uint8_t preference);
    // Must verify selected NIC and expected configuration, persist/read back
    // before effectuation, and restore RAM settings on persistence failure.
    bool (*apply)(void *,const NetworkInfo &,const P15IpSettings &,const P15IpSnapshot &);
};
struct P15IpStatus {
    uint8_t state; // 0 idle,1 staged,2 queued,3 commit begun,4 applied,5 failed,6 abandoned
    uint32_t request; bool persisted,applied;
};
void p15_ip_set_ops(const P15IpOps &);
void p15_ip_reset(const uint8_t session[8]);
void p15_ip_request_context(const uint8_t session[8],uint32_t request);
void p15_ip_response_consumed(const uint8_t session[8],uint32_t request);
void p15_ip_tick();
void p15_ip_status(P15IpStatus &);
bool p15_execute_ip(BackendContext &,uint8_t command,uint8_t protocol,
    const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &);
}
#endif
