#include "p18_log_stream.h"

#if defined(P18_LOG) && P18_LOG
#include "p18_log.h"
#include <stdint.h>
#include <string.h>
#include <errno.h>
#if defined(P18_LOG_STREAM_HOST_TEST)
// Deterministic socket, configuration and scheduler boundaries; the listener,
// authentication, cursor and partial-write state machine below are production.
#include "p18_log_stream_test_boundary.h"
#else
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "socket_keepalive.h"
#include "network_config.h"
#include "init_function.h"
#endif

namespace {
enum { AUTH_MS=30000, SEND_MS=5000, POLL_MS=10, REFRESH_MS=250,
       PASSWORD_MAX=31, AUTH_ATTEMPTS=5, STACK_WORDS=768 };
enum Phase { AUTH, STREAM };

// One task and one fixed workspace. No allocation, task creation or buffer
// growth occurs on accept. The lwIP listener backlog is also capped at one.
struct LogServer {
    int listener, peer;
    Phase phase;
    TickType_t accepted, tx_started, retry_started, refresh_started, listen_retry_started;
    uint32_t generation, after;
    unsigned tx_length, tx_offset, password_length, attempts, entry, record_line;
    bool invalid_password, skip_lf, retry_wait, unavailable_reported;
    char password[PASSWORD_MAX+1];
    char tx[p18log::LINE_CAPACITY+24];
    p18log::Snapshot page;
};
static LogServer server;

static TickType_t ticks(unsigned ms)
{
    TickType_t value=pdMS_TO_TICKS(ms);
    return value ? value : 1;
}
static bool elapsed(TickType_t now,TickType_t since,unsigned ms)
{
    // All budgets are below half the tick range; unsigned subtraction also
    // handles a tick wrap during authentication or a partial write.
    return (TickType_t)(now-since)>=ticks(ms);
}
static void erase(char *p,unsigned n)
{
    volatile char *v=p;
    while(n--) *v++=0;
}
static void close_socket(int fd)
{
    if(fd>=0) { shutdown(fd,2); lwip_close(fd); }
}
static void drop_peer(LogServer &s)
{
    close_socket(s.peer);
    s.peer=-1;
    erase(s.password,sizeof(s.password));
    s.password_length=0;
    s.tx_length=s.tx_offset=0;
    // Samples can contain sanitized application text; do not leave a previous
    // client's snapshot available to an unauthenticated replacement peer.
    memset(&s.page,0,sizeof(s.page));
    memset(s.tx,0,sizeof(s.tx));
}
static bool retryable()
{
    return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR;
}
static bool queue_text(LogServer &s,const char *text,TickType_t now)
{
    unsigned n=0;
    while(n<sizeof(s.tx) && text[n]) ++n;
    if(n==sizeof(s.tx) || s.tx_length) return false;
    memcpy(s.tx,text,n);
    s.tx_length=n;
    s.tx_offset=0;
    s.tx_started=now;
    return true;
}
static bool flush_once(LogServer &s,TickType_t now)
{
    if(!s.tx_length) return true;
    if(elapsed(now,s.tx_started,SEND_MS)) { drop_peer(s); return false; }
    int n=send(s.peer,s.tx+s.tx_offset,s.tx_length-s.tx_offset,MSG_DONTWAIT);
    if(n<0 && retryable()) return true;
    if(n<=0 || (unsigned)n>s.tx_length-s.tx_offset) { drop_peer(s); return false; }
    s.tx_offset+=(unsigned)n;
    if(s.tx_offset==s.tx_length) s.tx_length=s.tx_offset=0;
    return true;
}
static bool configured_password(char (&out)[PASSWORD_MAX+1])
{
    memset(out,0,sizeof(out));
    if(!networkConfig.cfg) return false;
    const char *p=networkConfig.cfg->get_string(CFG_NETWORK_PASSWORD);
    if(!p) return false;
    // Fail closed if the configuration ever exceeds its declared 31 bytes.
    for(unsigned i=0;i<sizeof(out);++i) {
        out[i]=p[i];
        if(!p[i]) return true;
    }
    erase(out,sizeof(out));
    return false;
}
static void accepted_peer(LogServer &s,int fd,TickType_t now)
{
    if(s.peer>=0) { close_socket(fd); return; }
    s.peer=fd;
    s.accepted=s.refresh_started=now;
    s.generation=s.after=0;
    s.entry=s.record_line=0;
    s.attempts=s.password_length=0;
    s.tx_length=s.tx_offset=0;
    s.invalid_password=s.skip_lf=s.retry_wait=s.unavailable_reported=false;
    erase(s.password,sizeof(s.password));
    memset(&s.page,0,sizeof(s.page));
    net_enable_client_keepalive(fd);
    char expected[PASSWORD_MAX+1];
    bool valid=configured_password(expected);
    bool empty=valid && !expected[0];
    erase(expected,sizeof(expected));
    if(!valid) { drop_peer(s); return; }
    s.phase=empty ? STREAM : AUTH;
    queue_text(s,empty ? "\033[0mWiC64: Live log (PuTTY Raw)\r\n" :
               "WiC64: Ultimate network password (local echo off)\r\nPassword: ",now);
}
static bool finish_password(LogServer &s,TickType_t now)
{
    char expected[PASSWORD_MAX+1];
    bool valid=configured_password(expected);
    unsigned difference=s.invalid_password || !valid;
    // Compare every byte, including zero padding; no prefix/length timing leak.
    for(unsigned i=0;i<sizeof(expected);++i)
        difference|=(unsigned char)expected[i]^(unsigned char)s.password[i];
    bool success=valid && (!expected[0] || !difference);
    erase(expected,sizeof(expected));
    erase(s.password,sizeof(s.password));
    s.password_length=0;
    s.invalid_password=false;
    if(success) {
        s.phase=STREAM;
        queue_text(s,"\r\n\033[0mWiC64: Live log (PuTTY Raw)\r\n",now);
        return true;
    }
    if(++s.attempts>=AUTH_ATTEMPTS) { drop_peer(s); return false; }
    s.retry_wait=true;
    s.retry_started=now;
    queue_text(s,"\r\nAuthentication failed.\r\nPassword: ",now);
    return true;
}
static void auth_once(LogServer &s,TickType_t now)
{
    if(elapsed(now,s.accepted,AUTH_MS)) { drop_peer(s); return; }
    if(s.tx_length) return;
    if(s.retry_wait) {
        if(!elapsed(now,s.retry_started,250*s.attempts)) return;
        s.retry_wait=false;
    }
    unsigned char ch;
    int n=recv(s.peer,&ch,1,MSG_DONTWAIT);
    if(n<0 && retryable()) return;
    if(n<=0) { drop_peer(s); return; }
    if(s.skip_lf) { s.skip_lf=false; if(ch=='\n') return; }
    if(ch=='\r' || ch=='\n') {
        s.skip_lf=ch=='\r';
        finish_password(s,now);
    } else if(ch=='\b' || ch==127) {
        if(s.password_length) s.password[--s.password_length]=0;
    } else if(ch<32 || ch>126) {
        // Raw is intentional: Telnet negotiation, NUL and terminal control
        // characters are invalid. Input is never echoed, printed or logged.
        s.invalid_password=true;
    } else if(s.password_length<PASSWORD_MAX) {
        s.password[s.password_length++]=(char)ch;
    } else s.invalid_password=true;
}
static bool queue_record(LogServer &s,TickType_t now)
{
    const p18log::Entry &e=s.page.entries[s.entry];
    const char *color="\033[0m";
    switch(p18log::record_color(e)) {
        case p18log::HOST: color="\033[36m"; break;
        case p18log::DEVICE: color="\033[32m"; break;
        case p18log::FAILURE: color="\033[31m"; break;
        default: break;
    }
    unsigned prefix=(unsigned)strlen(color);
    memcpy(s.tx,color,prefix);
    unsigned n=p18log::format_record(e,s.record_line,s.tx+prefix,p18log::LINE_CAPACITY);
    if(!n) {
        s.after=e.seq;
        ++s.entry;
        s.record_line=0;
        return false;
    }
    if(n>=p18log::LINE_CAPACITY) n=p18log::LINE_CAPACITY-1;
    // Defense in depth against ANSI injection if a future formatter changes.
    for(unsigned i=0;i<n;++i)
        if((unsigned char)s.tx[prefix+i]<32 || (unsigned char)s.tx[prefix+i]>126)
            s.tx[prefix+i]='?';
    memcpy(s.tx+prefix+n,"\033[0m\r\n",6);
    s.tx_length=prefix+n+6;
    s.tx_offset=0;
    s.tx_started=now;
    if(++s.record_line>=p18log::MAX_RECORD_LINES) {
        s.after=e.seq;
        ++s.entry;
        s.record_line=0;
    }
    return true;
}
static void stream_once(LogServer &s,TickType_t now)
{
    // Probe disconnects even while a line is pending. Stream input has no
    // commands, and each iteration discards at most 32 bytes.
    char input[32];
    int n=recv(s.peer,input,sizeof(input),MSG_DONTWAIT);
    erase(input,sizeof(input));
    if(n==0 || (n<0 && !retryable())) { drop_peer(s); return; }
    if(s.tx_length) return;
    if(s.entry<s.page.count) { queue_record(s,now); return; }
    if(!s.page.more && !elapsed(now,s.refresh_started,REFRESH_MS)) return;
    s.refresh_started=now;
    // snapshot() releases its single try-lock before returning. Neither
    // socket operation nor formatting takes place while the log is locked.
    if(!p18log::snapshot(s.generation,s.after,p18log::PAGE_SIZE,s.page)) return;
    s.entry=s.record_line=0;
    if(!s.page.available) {
        if(!s.unavailable_reported) {
            queue_text(s,"\033[31mWiC64: Log unavailable\033[0m\r\n",now);
            s.unavailable_reported=true;
        }
        return;
    }
    s.unavailable_reported=false;
    bool reset=s.generation && s.page.reset;
    s.generation=s.page.generation;
    if(s.page.reset) s.after=0;
    if(reset) queue_text(s,"\033[0mWiC64: Log cleared or cursor reset\r\n",now);
}
static int open_listener()
{
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0) return -1;
    int on=1;
    unsigned long nonblocking=1;
    struct sockaddr_in address;
    memset(&address,0,sizeof(address));
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=INADDR_ANY;
    address.sin_port=htons(p18log::STREAM_PORT);
    // Never continue with a potentially blocking accept after ioctl failure.
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&on,sizeof(on))<0 ||
       lwip_ioctl(fd,FIONBIO,&nonblocking)<0 ||
       bind(fd,(struct sockaddr *)&address,sizeof(address))<0 ||
       listen(fd,p18log::STREAM_MAX_CLIENTS)<0) {
        close_socket(fd);
        return -1;
    }
    return fd;
}
static void poll_server(LogServer &s,TickType_t now)
{
    if(s.listener<0) {
        if(elapsed(now,s.listen_retry_started,1000)) {
            s.listen_retry_started=now;
            s.listener=open_listener();
        }
    }
    // One accept per poll bounds a flood. Further peers are immediately closed
    // and cannot consume another task, credential buffer or log snapshot.
    if(s.listener>=0) {
        int fd=accept(s.listener,0,0);
        if(fd>=0) accepted_peer(s,fd,now);
        else if(!retryable()) {
            close_socket(s.listener);
            s.listener=-1;
            s.listen_retry_started=now;
        }
    }
    if(s.peer<0) return;
    if(!flush_once(s,now)) return;
    if(s.phase==AUTH) auth_once(s,now);
    else stream_once(s,now);
}
static void log_task(void *)
{
    memset(&server,0,sizeof(server));
    server.listener=server.peer=-1;
    for(;;) {
        poll_server(server,xTaskGetTickCount());
        vTaskDelay(ticks(POLL_MS));
    }
}
static void start_log(void *,void *)
{
    // InitFunction executes once. Task allocation failure leaves the listener
    // absent; it does not panic, affect the WiC64 service or change settings.
    xTaskCreate(log_task,"WiC64 Raw Log",STACK_WORDS,0,PRIO_NETSERVICE,0);
}
InitFunction init_wic64_raw_log("WiC64 Raw Log",start_log,0,0,111);
}
#endif
