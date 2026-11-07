#include "p12_tcp.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <new>
#if P14_TLS
#include "p14_tls.h"
#endif
#if defined(P08_HTTP_HOST)
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#define TCP_SOCKET socket
#define TCP_CONNECT connect
#define TCP_SEND send
#define TCP_RECV recv
#define TCP_CLOSE close
#define TCP_SELECT select
#define TCP_FCNTL fcntl
#define TCP_GETSOCKOPT getsockopt
#define TCP_SETSOCKOPT setsockopt
#else
extern "C" {
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
}
#define TCP_SOCKET lwip_socket
#define TCP_CONNECT lwip_connect
#define TCP_SEND lwip_send
#define TCP_RECV lwip_recv
#define TCP_CLOSE lwip_close
#define TCP_SELECT lwip_select
#define TCP_FCNTL lwip_fcntl
#define TCP_GETSOCKOPT lwip_getsockopt
#define TCP_SETSOCKOPT lwip_setsockopt
#endif

namespace p08 {
namespace {
struct Budget;
struct Stream {
    int fd;uint8_t mac[6];char ip[16];void *adapter;uint8_t pending[65535];unsigned used,unconfirmed;uint32_t ticket;bool ended;
    const Budget *budget;
#if P14_TLS
    p14::TlsStream *tls;
#endif
    Stream():fd(-1),adapter(0),used(0),unconfirmed(0),ticket(0),ended(false),budget(0)
#if P14_TLS
      ,tls(0)
#endif
    {memset(mac,0,6);memset(ip,0,sizeof(ip));}
} stream;
uint32_t next_ticket=0;
uint32_t clock_ms() {
#ifdef P08_HTTP_HOST
    timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return uint32_t(uint64_t(t.tv_sec)*1000+t.tv_nsec/1000000);
#else
    return uint32_t(xTaskGetTickCount())*(1000U/configTICK_RATE_HZ);
#endif
}
struct Budget {
    BackendContext &c; uint32_t began,limit;mutable bool saw_cancel;
    Budget(BackendContext &ctx):c(ctx),began(clock_ms()),limit(ctx.current_remote_timeout_ms),saw_cancel(false) {
        if(!limit || limit>60000)limit=5000;
    }
    bool cancelled()const {
        if(saw_cancel||c.cancel_requested)return true;
        if(c.should_cancel&&c.should_cancel(c.cancel_context))saw_cancel=true;
        return saw_cancel;
    }
    uint32_t remaining()const {
        uint32_t elapsed=clock_ms()-began;
        return elapsed>=limit||cancelled()?0:limit-elapsed;
    }
};
BackendResult result(uint8_t s,uint8_t e=HTTP_NONE,uint32_t n=0) {
    BackendResult r={s,e,0,false,n,0};return r;
}
uint8_t budget_error(const Budget &budget,uint8_t fallback) {
    if(budget.cancelled())return HTTP_CANCELLED;
    if(budget.remaining())return fallback;
    return budget.cancelled()?HTTP_CANCELLED:HTTP_DEADLINE;
}
bool again(){return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR;}
bool wait_fd(int fd,bool writing,const Budget &b) {
    while(b.remaining()) {
        uint32_t ms=b.remaining();if(ms>50)ms=50;
        fd_set f;FD_ZERO(&f);FD_SET(fd,&f);timeval t={0,int(ms*1000)};
        int n=TCP_SELECT(fd+1,writing?0:&f,writing?&f:0,0,&t);
        if(n>0)return b.remaining()!=0;
        if(n<0 && errno!=EINTR)return false;
    }
    return false;
}
struct ActiveBudget {
    ActiveBudget(const Budget &b){stream.budget=&b;}
    ~ActiveBudget(){stream.budget=0;}
};
#if P14_TLS
uint8_t tls_error(p14::TlsError error) {
    switch(error){
    case p14::TLS_OK:return HTTP_NONE;
    case p14::TLS_UNSEEDED:return HTTP_TLS_UNSEEDED;
    case p14::TLS_TIME_UNAVAILABLE:return HTTP_TLS_TIME;
    case p14::TLS_VERIFY:return HTTP_TLS_CERTIFICATE;
    case p14::TLS_DEADLINE:return HTTP_DEADLINE;
    case p14::TLS_CANCELLED:return HTTP_CANCELLED;
    case p14::TLS_READ:case p14::TLS_WRITE:return HTTP_TLS_RECORD;
    default:return HTTP_TLS_HANDSHAKE;
    }
}
int tls_send(void *,const uint8_t *p,uint32_t n){
    int sent=TCP_SEND(stream.fd,p,n,
#ifdef P08_HTTP_HOST
        MSG_NOSIGNAL
#else
        0
#endif
    );return sent<0?(again()?-2:-1):sent;
}
int tls_recv(void *,uint8_t *p,uint32_t n){int got=TCP_RECV(stream.fd,p,n,MSG_DONTWAIT);return got<0?(again()?-2:-1):got;}
bool tls_wait(void *,bool writing){return stream.budget&&wait_fd(stream.fd,writing,*stream.budget);}
bool tls_cancelled(void *){return !stream.budget||stream.budget->cancelled();}
uint32_t tls_remaining(void *){return stream.budget?stream.budget->remaining():0;}
#endif
bool dns_name(const char *host){
    unsigned first=0;bool letter=false;
    for(unsigned i=0;;i++){
        char c=host[i];if((c>='a'&&c<='z')||(c>='A'&&c<='Z'))letter=true;
        if(!c||c=='.'){
            if(i==first||i-first>63||host[first]=='-'||host[i-1]=='-')return false;
            if(!c)return letter;
            first=i+1;
        }
    }
}
bool destination(const uint8_t *bytes,uint32_t length,char host[254],uint16_t &port) {
    if(!bytes || !length || length>260)return false;
    if(!bytes[length-1])length--;
    unsigned split=0;
    while(split<length && bytes[split]!=':') {
        uint8_t c=bytes[split];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'))return false;
        split++;
    }
    if(!split || split>=254 || split+1>=length)return false;
    unsigned value=0;
    for(unsigned i=split+1;i<length;i++) {
        if(bytes[i]<'0'||bytes[i]>'9'||i-split>5)return false;
        value=value*10+bytes[i]-'0';if(value>65535)return false;
    }
    if(!value)return false;
    memcpy(host,bytes,split);host[split]=0;port=uint16_t(value);return true;
}
bool available(unsigned &count,const Budget &budget) {
    // This target has no FIONREAD and MSG_PEEK sees only the first pbuf.
    // Keep a bounded WiC64-owned receive cache instead. AVAILABLE includes
    // every currently queued fragment, up to its 16-bit protocol maximum.
    while(stream.fd>=0 && !stream.ended && stream.used<sizeof(stream.pending) && budget.remaining()) {
        int n;
#if P14_TLS
        if(stream.tls)n=stream.tls->read_available(stream.pending+stream.used,sizeof(stream.pending)-stream.used);
        else
#endif
        n=TCP_RECV(stream.fd,stream.pending+stream.used,sizeof(stream.pending)-stream.used,MSG_DONTWAIT);
#if P14_TLS
        if(stream.tls&&n==-2)break;
        if(stream.tls&&n<0){stream.ended=true;break;}
#endif
        if(n>0)stream.used+=unsigned(n);
        else if(n==0){stream.ended=true;break;}
        else if(errno==EINTR)continue;
        else if(again())break;
        else {stream.ended=true;break;}
    }
    count=stream.used;return !stream.ended||stream.used;
}
void close_transport() {
    if(stream.fd>=0)TCP_CLOSE(stream.fd);
    stream.fd=-1;
#if P14_TLS
    if(stream.tls){stream.tls->~TlsStream();free(stream.tls);stream.tls=0;}
#endif
    stream.ended=true;
}
#if P14_TLS
// A WiC64 command owns one operation window, including available() and every
// write/read chunk. This guard dies before ActiveBudget, so END uses the same
// original command budget. Reset/close may destroy its TLS owner first.
struct PersistentOperation {
    p14::TlsStream *owner;
    BackendResult &out;
    bool active;
    explicit PersistentOperation(BackendResult &value):owner(stream.tls),out(value),active(false){}
    bool begin(){
        if(!owner)return true;
        p14::TlsError error=owner->begin_operation();
        if(error!=p14::TLS_OK){out=result(4,tls_error(error));p12_tcp_reset();return false;}
        active=true;return true;
    }
    ~PersistentOperation(){
        if(!active||stream.tls!=owner)return;
        p14::TlsError error=owner->end_operation();
        if(error!=p14::TLS_OK){
            // A missing END acknowledgement is never retried or followed by a
            // new window. Drop its unconfirmed plaintext ticket with the slot.
            out=result(4,tls_error(error));p12_tcp_reset();
        }
    }
};
#endif
}
void p12_tcp_reset() {
    close_transport();
    stream.used=stream.unconfirmed=0;stream.ticket=0;stream.ended=false;memset(stream.mac,0,6);memset(stream.ip,0,sizeof(stream.ip));stream.adapter=0;
}
uint32_t p12_tcp_read_ticket(){return stream.unconfirmed?stream.ticket:0;}
void p12_tcp_finalize_read(uint32_t ticket,bool delivered) {
    if(!delivered||!ticket||ticket!=stream.ticket||!stream.unconfirmed)return;
    stream.used-=stream.unconfirmed;
    if(stream.used)memmove(stream.pending,stream.pending+stream.unconfirmed,stream.used);
    stream.unconfirmed=0;stream.ticket=0;
    if(!stream.used&&stream.ended)p12_tcp_reset();
}
bool p12_execute_tcp(BackendContext &c,uint8_t command,const uint8_t *request,
    uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out) {
    if(command!=0x21&&command!=0x22&&command!=0x23&&command!=0x2e&&command!=0x30&&command!=0x40)return false;
    out=result(2,HTTP_ARGUMENT);
    // Every OPEN attempt owns/replaces the slot, including rejected input.
    if(command==0x21||command==0x40||command==0x2e)p12_tcp_reset();
    if(!response||!capacity||length>MAX_REQUEST||(length&&!request))return true;
    if(command==0x2e) {
        out=c.network.connected&&c.network.mac_valid?result(0):result(3,HTTP_CONNECT);return true;
    }
    if(command!=0x21&&command!=0x40&&command!=0x23&&length)return true;
    if(!c.network.connected||!c.network.mac_valid) {
        p12_tcp_reset();out=result(3,HTTP_CONNECT);return true;
    }
    if((stream.fd>=0||stream.used) && (memcmp(stream.mac,c.network.mac,6)||memcmp(stream.ip,c.network.ip,sizeof(stream.ip))||stream.adapter!=c.network.adapter_handle))p12_tcp_reset();
    Budget budget(c);ActiveBudget active(budget);
    if(command==0x21||command==0x40) {
        char host[254];uint16_t port;
        if(!destination(request,length,host,port)||(command==0x40&&!dns_name(host)))return true;
#if !P14_TLS
        if(command==0x40){out=result(1,HTTP_UNSUPPORTED);return true;}
#endif
        // A new valid OPEN deliberately replaces the old stream.
        p12_tcp_reset();uint8_t ip[4];
        if(!resolve_backend_ipv4(c,host,ip,budget.remaining())) {out=result(4,budget_error(budget,HTTP_DNS));return true;}
        stream.fd=TCP_SOCKET(AF_INET,SOCK_STREAM,0);
        timeval cleanup={0,200000};
        if(stream.fd<0||!bind_selected_socket(c,stream.fd)||
           TCP_SETSOCKOPT(stream.fd,SOL_SOCKET,SO_SNDTIMEO,&cleanup,sizeof(cleanup))<0||
           TCP_FCNTL(stream.fd,F_SETFL,O_NONBLOCK)<0) {
            p12_tcp_reset();out=result(4,HTTP_SOCKET);return true;
        }
        sockaddr_in target;memset(&target,0,sizeof(target));target.sin_family=AF_INET;target.sin_port=htons(port);
#ifndef P08_HTTP_HOST
        target.sin_len=sizeof(target);
#endif
        memcpy(&target.sin_addr,ip,4);
        bool ok=budget.remaining()!=0;
        if(ok&&TCP_CONNECT(stream.fd,reinterpret_cast<sockaddr*>(&target),sizeof(target))<0) {
            ok=(errno==EINPROGRESS||errno==EWOULDBLOCK||errno==EALREADY)&&wait_fd(stream.fd,true,budget);
            int error=0;socklen_t size=sizeof(error);
            if(ok)ok=TCP_GETSOCKOPT(stream.fd,SOL_SOCKET,SO_ERROR,&error,&size)==0&&!error;
        }
        if(!ok||!budget.remaining()) {p12_tcp_reset();out=result(4,budget_error(budget,HTTP_CONNECT));return true;}
#if P14_TLS
        if(command==0x40){
            void *memory=malloc(sizeof(p14::TlsStream));
            if(!memory){p12_tcp_reset();out=result(1,HTTP_SOCKET);return true;}
            stream.tls=new(memory) p14::TlsStream();
            p14::TlsIo io={&stream,tls_send,tls_recv,tls_wait,tls_cancelled,tls_remaining};
            uint8_t error=tls_error((stream.tls->connect_persistent)(host,false,io,c));
            if(error){p12_tcp_reset();out=result(error==HTTP_TLS_TIME?3:4,error);return true;}
        }
#endif
        if(!budget.remaining()){p12_tcp_reset();out=result(4,budget_error(budget,HTTP_CONNECT));return true;}
        memcpy(stream.mac,c.network.mac,6);memcpy(stream.ip,c.network.ip,sizeof(stream.ip));stream.adapter=c.network.adapter_handle;out=result(0);return true;
    }
    if(stream.fd<0&&!stream.used) {out=result(4,HTTP_CONNECT);return true;}
    if(command==0x30&&capacity<2)return true;
#if P14_TLS
    PersistentOperation operation(out);
    if(!operation.begin())return true;
#endif
    unsigned count=0;
    bool open=available(count,budget);
    if(!open) {
        uint8_t error=HTTP_READ;
#if P14_TLS
        if(stream.tls)error=tls_error(stream.tls->error());
#endif
        close_transport();out=result(4,budget_error(budget,error));return true;
    }
    if(!budget.remaining()){close_transport();out=result(4,budget.cancelled()?HTTP_CANCELLED:HTTP_DEADLINE);return true;}
    if(command==0x30) {
        if(count>65535)count=65535;
        response[0]=uint8_t(count);response[1]=uint8_t(count>>8);out=result(0,0,2);return true;
    }
    if(command==0x23) {
        if(stream.ended){close_transport();out=result(4,HTTP_WRITE);return true;}
        unsigned offset=0;
        while(offset<length&&budget.remaining()) {
            int n;
#if P14_TLS
            if(stream.tls)n=(stream.tls->write)(request+offset,length-offset);
            else
#endif
            n=TCP_SEND(stream.fd,request+offset,length-offset,
#ifdef P08_HTTP_HOST
                MSG_NOSIGNAL
#else
                0
#endif
            );
            if(n>0)offset+=unsigned(n);
            else if(n<0&&again()) {if(!wait_fd(stream.fd,true,budget))break;}
            else break;
        }
        if(offset!=length||!budget.remaining()) {close_transport();out=result(4,budget_error(budget,HTTP_WRITE));return true;}
        out=result(0);return true;
    }
    if(stream.unconfirmed){
        if(stream.unconfirmed>capacity){out=result(1,HTTP_LENGTH);return true;}
        count=stream.unconfirmed;
    }else{
        if(count>capacity)count=capacity;
        if(count>8192)count=8192;
        if(count){stream.unconfirmed=count;if(!++next_ticket)++next_ticket;stream.ticket=next_ticket;}
    }
    if(count)memcpy(response,stream.pending,count);
    out=result(0,0,count);return true;
}
}
