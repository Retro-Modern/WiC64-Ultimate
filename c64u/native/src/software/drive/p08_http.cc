#include "p08_http.h"
#include "p18_version.h"
#include "p16_http_redirect.h"
#if P14_TLS
#include "p14_tls.h"
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#if defined(P08_HTTP_HOST)
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#define P8_SOCKET socket
#define P8_CONNECT connect
#define P8_SEND send
#define P8_RECV recv
#define P8_CLOSE close
#define P8_SELECT select
#define P8_GETSOCKOPT getsockopt
#define P8_SETSOCKOPT setsockopt
#define P8_FCNTL fcntl
#else
extern "C" {
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
}
#include "network_interface.h"
#include "wifi.h"
#define P8_SOCKET lwip_socket
#define P8_CONNECT lwip_connect
#define P8_SEND lwip_send
#define P8_RECV lwip_recv
#define P8_CLOSE lwip_close
#define P8_SELECT lwip_select
#define P8_GETSOCKOPT lwip_getsockopt
#define P8_SETSOCKOPT lwip_setsockopt
#define P8_FCNTL lwip_fcntl
#endif

namespace p08 {
namespace {
uint32_t now_ms() {
#if defined(P08_HTTP_HOST)
    timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return uint32_t(uint64_t(t.tv_sec)*1000+uint32_t(t.tv_nsec/1000000));
#else
    return uint32_t(xTaskGetTickCount())*(1000U/configTICK_RATE_HZ);
#endif
}
struct Deadline {
    uint32_t start,limit;const volatile bool *cancel;
    bool (*check)(void *);void *context;mutable uint32_t last_check;mutable bool saw_cancel;
    Deadline(uint32_t ms,const volatile bool *c,bool (*f)(void *),void *ctx):start(now_ms()),limit(ms),cancel(c),check(f),context(ctx),last_check(start-10),saw_cancel(false){}
    bool cancelled() const {
        if(saw_cancel || (cancel && *cancel))return true;
        uint32_t now=now_ms();
        if(check && uint32_t(now-last_check)>=10){last_check=now;if(check(context))saw_cancel=true;}
        return saw_cancel;
    }
    uint32_t remaining()const {uint32_t n=uint32_t(now_ms()-start);return cancelled()||n>=limit?0:limit-n;}
};
void wipe_secret(void *memory,unsigned length) {
    volatile uint8_t *bytes=static_cast<volatile uint8_t*>(memory);while(length--)*bytes++=0;
}
BackendResult fail(uint8_t status,uint8_t error,uint16_t code=0) {
    BackendResult r={status,error,0,false,0,code};return r;
}
BackendResult http_fail(uint8_t status,uint8_t error,uint16_t code=0) {
    BackendResult r=fail(status,error,code);r.http_performed=true;return r;
}
BackendResult good(uint32_t size=0) {BackendResult r={0,0,0,false,size,0};return r;}
bool again(){return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR;}
bool ready(int fd,bool writing,const Deadline &d) {
    while(d.remaining()) {
        uint32_t n=d.remaining();if(n>100)n=100;
        fd_set f;FD_ZERO(&f);FD_SET(fd,&f);timeval t;t.tv_sec=0;t.tv_usec=n*1000;
        int r=P8_SELECT(fd+1,writing?0:&f,writing?&f:0,0,&t);
        if(r>0)return !d.cancelled();if(r<0&&errno!=EINTR)return false;
    }return false;
}
struct Socket {
    int fd;const Deadline &deadline;bool encrypted;
#if P14_TLS
    p14::TlsStream tls;
    static int send_tls(void *opaque,const uint8_t *bytes,uint32_t count) {
        Socket *s=static_cast<Socket*>(opaque);
#ifdef P08_HTTP_HOST
        int n=P8_SEND(s->fd,bytes,count,MSG_NOSIGNAL);
#else
        int n=P8_SEND(s->fd,bytes,count,0);
#endif
        return n<0?(again()?-2:-1):n;
    }
    static int recv_tls(void *opaque,uint8_t *bytes,uint32_t count) {
        Socket *s=static_cast<Socket*>(opaque);int n=P8_RECV(s->fd,bytes,count,0);
        return n<0?(again()?-2:-1):n;
    }
    static bool wait_tls(void *opaque,bool writing){Socket *s=static_cast<Socket*>(opaque);return ready(s->fd,writing,s->deadline);}
    static bool cancelled_tls(void *opaque){return static_cast<Socket*>(opaque)->deadline.cancelled();}
    static uint32_t remaining_tls(void *opaque){return static_cast<Socket*>(opaque)->deadline.remaining();}
#endif
    explicit Socket(const Deadline &d):fd(-1),deadline(d),encrypted(false){}
    ~Socket(){if(fd>=0)P8_CLOSE(fd);}
    uint8_t secure(const char *host,bool numeric_host,BackendContext *context,bool phased=false) {
#if P14_TLS
        if(!context)return HTTP_TLS_UNSEEDED;
        p14::TlsIo io={this,send_tls,recv_tls,wait_tls,cancelled_tls,remaining_tls};
        p14::TlsError error=phased?(tls.connect_persistent)(host,numeric_host,io,*context):
            (tls.connect)(host,numeric_host,io,*context);
        if(error!=p14::TLS_OK)return tls_error(error);
        encrypted=true;return HTTP_NONE;
#else
        (void)host;(void)numeric_host;(void)context;(void)phased;return HTTP_UNSUPPORTED;
#endif
    }
    uint8_t operation(bool begin) {
#if P14_TLS
        if(encrypted)return tls_error(begin?(tls.begin_operation)():(tls.end_operation)());
#else
        (void)begin;
#endif
        return HTTP_NONE;
    }
    int receive(uint8_t *bytes,uint32_t count) {
#if P14_TLS
        // TLS may already own decrypted bytes while the socket is not readable.
        // Its implementation attempts TLS first and waits in either direction.
        if(encrypted)return (tls.read)(bytes,count);
#endif
        if(!ready(fd,false,deadline))return -1;
        return P8_RECV(fd,bytes,count,0);
    }
    int transmit(const uint8_t *bytes,uint32_t count) {
#if P14_TLS
        if(encrypted)return (tls.write)(bytes,count);
#endif
        if(!ready(fd,true,deadline))return -1;
#ifdef P08_HTTP_HOST
        return P8_SEND(fd,bytes,count,MSG_NOSIGNAL);
#else
        return P8_SEND(fd,bytes,count,0);
#endif
    }
#if P14_TLS
    static uint8_t tls_error(p14::TlsError error) {
        switch(error){
        case p14::TLS_OK:return HTTP_NONE;
        case p14::TLS_UNSEEDED:return HTTP_TLS_UNSEEDED;
        case p14::TLS_TIME_UNAVAILABLE:return HTTP_TLS_TIME;
        case p14::TLS_VERIFY:return HTTP_TLS_CERTIFICATE;
        case p14::TLS_READ:case p14::TLS_WRITE:return HTTP_TLS_RECORD;
        case p14::TLS_DEADLINE:return HTTP_DEADLINE;
        case p14::TLS_CANCELLED:return HTTP_CANCELLED;
        default:return HTTP_TLS_HANDSHAKE;
        }
    }
#endif
    uint8_t failure(uint8_t otherwise)const {
        if(deadline.cancelled())return HTTP_CANCELLED;
        if(!deadline.remaining())return HTTP_DEADLINE;
#if P14_TLS
        if(tls.error()!=p14::TLS_OK)return tls_error(tls.error());
#endif
        return otherwise;
    }
private:Socket(const Socket&);
};
struct Url {char host[254],authority[262],path[MAX_URL+1];uint16_t port;bool secure;};
bool scheme(const uint8_t *bytes,uint32_t count,bool &secure,unsigned &prefix) {
    static const char plain[]="http://",tls[]="https://";
    for(unsigned kind=0;kind<2;kind++){
        const char *expected=kind?tls:plain;unsigned n=kind?8:7;
        if(count<n)continue;bool match=true;
        for(unsigned i=0;i<n;i++){uint8_t v=bytes[i];if(v>='A'&&v<='Z')v+=32;if(v!=uint8_t(expected[i])){match=false;break;}}
        if(match){secure=kind!=0;prefix=n;return true;}
    }return false;
}
bool numeric(const char *s,uint8_t ip[4]) {
    for(unsigned part=0;part<4;part++) {
        unsigned digits=0,n=0;
        while(*s>='0'&&*s<='9'){if(++digits>3)return false;n=n*10+*s++-'0';}
        if(!digits||n>255)return false;ip[part]=uint8_t(n);
        if(part<3&&*s++!='.')return false;
    }return !*s;
}
bool parse_url(const uint8_t *bytes,uint32_t count,Url &out) {
    if(!bytes||!count||count>MAX_URL)return false;if(!bytes[count-1])count--;
    unsigned prefix=0;if(!scheme(bytes,count,out.secure,prefix))return false;
    for(unsigned i=0;i<count;i++)if(bytes[i]<0x21||bytes[i]>0x7e||bytes[i]=='#'||bytes[i]=='\\')return false;
    unsigned p=prefix,begin=p;while(p<count&&bytes[p]!='/'&&bytes[p]!=':'&&bytes[p]!='?')p++;
    unsigned hostlen=p-begin;if(!hostlen||hostlen>=sizeof(out.host))return false;
    for(unsigned i=begin;i<p;i++)if(!((bytes[i]>='A'&&bytes[i]<='Z')||(bytes[i]>='a'&&bytes[i]<='z')||(bytes[i]>='0'&&bytes[i]<='9')||bytes[i]=='.'||bytes[i]=='-'))return false;
    memcpy(out.host,bytes+begin,hostlen);out.host[hostlen]=0;
    bool only_digits=true;for(unsigned i=0;i<hostlen;i++)if((out.host[i]<'0'||out.host[i]>'9')&&out.host[i]!='.')only_digits=false;
    uint8_t numeric_check[4];if(only_digits&&!numeric(out.host,numeric_check))return false;
    if(out.secure&&!only_digits){
        unsigned label=0;for(unsigned i=0;i<=hostlen;i++)if(i==hostlen||out.host[i]=='.'){
            if(i==label||i-label>63||out.host[label]=='-'||out.host[i-1]=='-')return false;label=i+1;
        }
    }
    out.port=out.secure?443:80;
    if(p<count&&bytes[p]==':') {
        p++;unsigned digits=0,n=0;while(p<count&&bytes[p]>='0'&&bytes[p]<='9'){if(++digits>5)return false;n=n*10+bytes[p++]-'0';}
        if(!digits||!n||n>65535)return false;out.port=uint16_t(n);
    }
    if(p<count&&bytes[p]!='/'&&bytes[p]!='?')return false;unsigned authority=p-begin;if(authority>=sizeof(out.authority))return false;
    memcpy(out.authority,bytes+begin,authority);out.authority[authority]=0;
    if(p==count){strcpy(out.path,"/");return true;}
    unsigned extra=bytes[p]=='?'?1:0;if(count-p+extra>MAX_URL)return false;
    if(extra)out.path[0]='/';memcpy(out.path+extra,bytes+p,count-p);out.path[count-p+extra]=0;return true;
}
#if !defined(P08_HTTP_HOST)
// A single permanent context outlives delayed DNS callbacks. It is never reused
// while pending. A timed-out/cancelled caller never frees callback storage.
struct Resolver {SemaphoreHandle_t sem;bool pending;err_t result;char host[254];ip_addr_t address;};
static Resolver resolver={};
static void resolved(const char *,const ip_addr_t *address,void *argument) {
    Resolver *r=static_cast<Resolver*>(argument);portENTER_CRITICAL();
    r->result=address?ERR_OK:ERR_VAL;if(address)r->address=*address;
    r->pending=false;xSemaphoreGive(r->sem);portEXIT_CRITICAL();
}
static void start_resolve(void *argument) {
    Resolver *r=static_cast<Resolver*>(argument);ip_addr_t address;
    err_t e=dns_gethostbyname(r->host,&address,resolved,r);
    if(e==ERR_OK)resolved(r->host,&address,r);
    else if(e!=ERR_INPROGRESS)resolved(r->host,0,r);
}
#endif
bool resolve(const char *host,uint8_t out[4],const Deadline &d) {
    if(numeric(host,out))return true;
#if defined(P08_HTTP_HOST)
    addrinfo hints={};hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;addrinfo *result=0;
    if(getaddrinfo(host,0,&hints,&result)||!result)return false;
    memcpy(out,&reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr,4);freeaddrinfo(result);return d.remaining()!=0;
#else
    if(!resolver.sem)resolver.sem=xSemaphoreCreateBinary();if(!resolver.sem)return false;
    portENTER_CRITICAL();
    if(resolver.pending){portEXIT_CRITICAL();return false;}
    while(xSemaphoreTake(resolver.sem,0)==pdTRUE){}
    memcpy(resolver.host,host,strlen(host)+1);resolver.pending=true;resolver.result=ERR_INPROGRESS;
    portEXIT_CRITICAL();
    if(tcpip_try_callback(start_resolve,&resolver)!=ERR_OK){portENTER_CRITICAL();resolver.pending=false;portEXIT_CRITICAL();return false;}
    while(d.remaining()) {
        uint32_t left=d.remaining();if(left>100)left=100;
        TickType_t ticks=(left*configTICK_RATE_HZ+999)/1000;if(!ticks)ticks=1;
        if(xSemaphoreTake(resolver.sem,ticks)==pdTRUE) {
            if(resolver.result!=ERR_OK||!IP_IS_V4(&resolver.address))return false;
            memcpy(out,ip_2_ip4(&resolver.address),4);return !d.cancelled();
        }
    }return false;
#endif
}
struct Reader {
    Socket &connection;const Deadline &deadline;uint8_t data[512];unsigned pos,end;bool broken;
    Reader(Socket &s,const Deadline &d):connection(s),deadline(d),pos(0),end(0),broken(false){}
    int byte() {
        if(!deadline.remaining()){broken=true;return -1;}
        while(pos==end) {
            int n=connection.receive(data,sizeof(data));if(n<0&&again()&&!connection.encrypted)continue;
            if(n<=0){broken=true;return -1;}pos=0;end=unsigned(n);
        }return data[pos++];
    }
    bool line(char *out,unsigned capacity,unsigned &length) {
        length=0;for(;;){int c=byte();if(c<0)return false;
            if(c=='\r'){if(byte()!='\n')return false;out[length]=0;return true;}
            if(c=='\n'||c==0||c==127||(c<32&&c!='\t')||length+1>=capacity)return false;
            out[length++]=char(c);
        }
    }
    bool body(uint8_t *out,uint32_t count) {for(uint32_t i=0;i<count;i++){int c=byte();if(c<0)return false;out[i]=uint8_t(c);}return true;}
    int part(uint8_t *out,uint32_t count) {
        if(!count||!deadline.remaining())return -1;
        if(pos==end){
            int n;do{n=connection.receive(data,sizeof(data));}while(n<0&&again()&&!connection.encrypted&&deadline.remaining());
            if(n<=0)return n;pos=0;end=unsigned(n);
        }
        unsigned n=end-pos;if(n>count)n=count;memcpy(out,data+pos,n);pos+=n;return int(n);
    }
};
bool same(const char *a,const char *b) {
    while(*a&&*b){unsigned char x=*a++,y=*b++;if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y)return false;}return !*a&&!*b;
}
bool token(unsigned char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||(c&&strchr("!#$%&'*+-.^_`|~",c));}
bool decimal(const char *value,uint32_t limit,uint32_t &out) {
    if(!*value)return false;out=0;for(;*value;value++){if(*value<'0'||*value>'9'||(unsigned(*value-'0')>limit||out>(limit-unsigned(*value-'0'))/10))return false;out=out*10+*value-'0';}return out<=limit;
}
struct Workspace {Url url;char current[MAX_URL+1],location[MAX_URL+1],line[2049],request[512],token_key[65],token[257];bool key_seen,token_seen,location_seen,portal_authority;char initial_host[254];uint16_t initial_port;bool initial_secure,bearer_suppressed;};
struct Headers {uint16_t code;bool have_length,chunked;uint32_t length;};
bool security_value(const char *value,unsigned maximum) {
    unsigned n=0;for(;value[n];n++)if(n==maximum||static_cast<unsigned char>(value[n])<0x21||static_cast<unsigned char>(value[n])>0x7e)return false;
    return true;
}
bool headers(Reader &reader,Workspace &w,Headers &out,uint32_t capacity) {
    unsigned n=0,total=0;if(!reader.line(w.line,sizeof(w.line),n)||n<13)return false;
    if(memcmp(w.line,"HTTP/1.",7)||(w.line[7]!='0'&&w.line[7]!='1')||w.line[8]!=' '||w.line[9]<'1'||w.line[9]>'5'||w.line[10]<'0'||w.line[10]>'9'||w.line[11]<'0'||w.line[11]>'9'||w.line[12]!=' ')return false;
    out.code=(w.line[9]-'0')*100+(w.line[10]-'0')*10+w.line[11]-'0';
    // Reject every informational chain before parsing headers, whether its
    // final response was coalesced in this read or arrives separately.
    if(out.code<200)return false;
    out.have_length=false;out.chunked=false;out.length=0;w.location[0]=0;w.token_key[0]=w.token[0]=0;w.key_seen=w.token_seen=w.location_seen=false;bool encoding_seen=false;
    for(unsigned lines=0;lines<64;lines++) {
        if(!reader.line(w.line,sizeof(w.line),n))return false;total+=n+2;if(total>8192)return false;if(!n)return !(out.chunked&&out.have_length)&&(!w.key_seen||security_value(w.token_key,64))&&(!w.token_seen||security_value(w.token,256));
        char *colon=strchr(w.line,':');if(!colon||colon==w.line)return false;for(char *p=w.line;p<colon;p++)if(!token(*p))return false;
        *colon=0;char *value=colon+1;while(*value==' '||*value=='\t')value++;char *end=value+strlen(value);while(end>value&&(end[-1]==' '||end[-1]=='\t'))*--end=0;
        if(same(w.line,"content-length")){if(out.have_length||!decimal(value,capacity,out.length))return false;out.have_length=true;}
        else if(same(w.line,"transfer-encoding")){if(out.chunked||!same(value,"chunked"))return false;out.chunked=true;}
        else if(same(w.line,"content-encoding")){if(encoding_seen||!same(value,"identity"))return false;encoding_seen=true;}
        else if(same(w.line,"wic64-security-token-key")){if(w.key_seen||strlen(value)>64)return false;w.key_seen=true;strcpy(w.token_key,value);}
        else if(same(w.line,"wic64-security-token")){if(w.token_seen||strlen(value)>256)return false;w.token_seen=true;strcpy(w.token,value);}
        else if(same(w.line,"location")){if(w.location_seen||!*value||strlen(value)>MAX_URL)return false;w.location_seen=true;strcpy(w.location,value);}
    }return false;
}
bool write_all(Socket &connection,const uint8_t *bytes,uint32_t length,const Deadline &d) {
    for(uint32_t done=0;done<length;){if(!d.remaining())return false;
        int n=connection.transmit(bytes+done,length-done);
        if(n<0&&again()&&!connection.encrypted)continue;if(n<=0)return false;done+=uint32_t(n);
    }return true;
}
bool chunked(Reader &reader,Workspace &w,uint8_t *body,uint32_t capacity,uint32_t &length) {
    length=0;unsigned n=0;
    for(unsigned chunks=0;chunks<65537;chunks++) {
        if(!reader.line(w.line,128,n)||!n)return false;uint32_t count=0;unsigned digits=0,i=0;
        for(;i<n&&w.line[i]!=';';i++){unsigned char c=w.line[i];unsigned x=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:16;
            if(x>15||++digits>8||(x>capacity||count>(capacity-x)/16))return false;count=count*16+x;}
        if(!digits||count>capacity-length)return false;
        if(!count){unsigned trailer=0;for(unsigned lines=0;lines<32;lines++){if(!reader.line(w.line,1025,n))return false;trailer+=n+2;if(trailer>1024)return false;if(!n)return true;if(!strchr(w.line,':'))return false;}return false;}
        if(!reader.body(body+length,count)||reader.byte()!='\r'||reader.byte()!='\n')return false;length+=count;
    }return false;
}
int redirect_url(Workspace &w) {
    if(!w.location_seen)return 0;
    // Resolve into a separate heap buffer: current is also the base URL.
    char *next=static_cast<char*>(malloc(MAX_URL+1));if(!next)return 0;
    struct FreeNext{char *p;~FreeNext(){wipe_secret(p,MAX_URL+1);free(p);}}free_next={next};
    if(!WiC64::HttpRedirect::resolve(w.current,w.location,next,MAX_URL+1))return 0;
    bool secure=false;unsigned prefix=0;
    if(!scheme(reinterpret_cast<const uint8_t*>(next),strlen(next),secure,prefix))return 0;
    if(w.url.secure&&!secure)return -1;
    strcpy(w.current,next);return 1;
}
void status_text(BackendContext &c,const char *text) {unsigned n=0;while(text[n]&&n<39){c.last_status[n]=text[n];n++;}c.last_status[n]=0;}
BackendResult text_reply(const char *text,uint8_t *out,uint32_t cap,bool nul=true) {
    uint32_t n=uint32_t(strlen(text))+(nul?1:0);if(n>cap)return fail(1,HTTP_LENGTH);if(n)memcpy(out,text,n);return good(n);
}
bool request_string(const uint8_t *p,uint32_t n,char *out,uint32_t capacity) {
    if(n&&p[n-1]==0)n--;if(n>=capacity)return false;
    for(uint32_t i=0;i<n;i++)if(p[i]<0x20||p[i]>0x7e)return false;
    if(n)memcpy(out,p,n);out[n]=0;return true;
}
// Decode the complete binary request before ordinary URL expansion. Only an
// outside-block terminal NUL is optional; a block's final binary NUL is data.
// Upstream sanitize() removes ASCII spaces after hex conversion, not inside it.
bool url_text(const uint8_t *p,uint32_t n,bool encoded,char *out) {
    if((!p&&n)||n>MAX_REQUEST)return false;
    static const char lower_hex[]="0123456789abcdef";
    uint32_t read=0,write=0;
    while(read<n){
        if(encoded&&p[read]=='<'&&read+1<n&&p[read+1]=='$'){
            if(n-read<4)return false;
            uint32_t count=uint32_t(p[read+2])|(uint32_t(p[read+3])<<8);
            read+=4;
            if(count>n-read||count>(MAX_URL-write)/2)return false;
            for(uint32_t i=0;i<count;i++){uint8_t value=p[read++];out[write++]=lower_hex[value>>4];out[write++]=lower_hex[value&15];}
        }else{
            uint8_t value=p[read++];
            if(!value&&read==n)break;
            if(value==' ')continue;
            if(value<0x21||value>0x7e||write==MAX_URL)return false;
            out[write++]=char(value);
        }
    }
    out[write]=0;return true;
}
bool expand_url(const BackendContext &c,const uint8_t *p,uint32_t n,char *out,bool encoded=false) {
    // Expand configured-server markers before every legacy %mac marker, even
    // when the configured server itself contains that identity marker.
    char *input=static_cast<char*>(malloc(2*(MAX_URL+1)));if(!input)return false;
    struct FreeInput{char *p;~FreeInput(){wipe_secret(p,2*(MAX_URL+1));free(p);}}free_input={input};
    if(!url_text(p,n,encoded,input))return false;
    char mac[13];for(unsigned i=0;i<6;i++)snprintf(mac+2*i,3,"%02X",c.network.mac[i]);
    char *expanded=input+MAX_URL+1;unsigned write=0;const char *read=input;
    if(*read=='!'){unsigned k=strlen(c.server);if(k>MAX_URL)return false;memcpy(expanded,c.server,k);write=k;read++;}
    while(*read){
        if(!strncmp(read,"%ser",4)){unsigned k=strlen(c.server);if(write+k>MAX_URL)return false;memcpy(expanded+write,c.server,k);write+=k;read+=4;}
        else{if(write==MAX_URL)return false;expanded[write++]=*read++;}
    }
    expanded[write]=0;write=0;read=expanded;
    while(*read){const char *replacement=0;unsigned consumed=0;
        if(!strncmp(read,"%mac",4)){if(!c.network.mac_valid)return false;replacement=mac;consumed=4;}
        if(replacement){unsigned k=strlen(replacement);if(write+k>MAX_URL)return false;memcpy(out+write,replacement,k);write+=k;
            if(consumed==4&&!strncmp(read,"%mac",4)){unsigned t=strlen(c.token);if(write+t>MAX_URL)return false;memcpy(out+write,c.token,t);write+=t;}
            read+=consumed;}
        else{if(write==MAX_URL)return false;out[write++]=*read++;}
    }out[write]=0;return true;
}
bool prg_url(const char *url) {size_t n=strlen(url);return n>=4&&!strcmp(url+n-4,".prg");}
} // namespace

namespace {
static bool valid_mac(const uint8_t mac[6]) {
    unsigned any=0,all=255;for(unsigned i=0;i<6;i++){any|=mac[i];all&=mac[i];}
    return any && all!=255 && !(mac[0]&1);
}
static bool portal_present(const PortalCredentials &);
static void publish_summary(BackendContext &c) {
    BackendSummary s={};s.preference=c.preference;
    s.selected=c.network.mac_valid?(c.network.wireless?NETWORK_WLAN:NETWORK_LAN):NETWORK_AUTO;
    s.connected=c.network.connected;s.mac_valid=c.network.mac_valid;memcpy(s.mac,c.network.mac,6);numeric(c.network.ip,s.ipv4);
    for(unsigned i=0;i<2;i++)if(c.profiles[i].used)s.profile_count++;
    const AdapterProfile *p=active_profile(static_cast<const BackendContext&>(c));
    s.portal_secret_present=portal_present(p?p->portal:static_cast<const PortalCredentials&>(c));
    s.port64_bearer_present=p&&p->port64_bearer[0];s.custom_bearer_present=p&&p->custom_bearer[0];
    s.credentials_dirty=c.credentials_dirty;s.credentials_saved=c.credentials_saved;
#if !defined(P08_HTTP_HOST)
    portENTER_CRITICAL();
#endif
    c.summary_cache=s;
#if !defined(P08_HTTP_HOST)
    portEXIT_CRITICAL();
#endif
}
static void sync_profile(BackendContext &c) {
    if(c.selected_profile<2&&c.profiles[c.selected_profile].used)
        c.profiles[c.selected_profile].portal=static_cast<const PortalCredentials&>(c);
}
static void select_profile(BackendContext &c) {
    sync_profile(c);
    uint8_t selected=255;
    if(c.network.mac_valid){
        for(unsigned i=0;i<2;i++)if(c.profiles[i].used&&!memcmp(c.profiles[i].mac,c.network.mac,6)){selected=i;break;}
        if(selected==255)for(unsigned i=0;i<2;i++)if(!c.profiles[i].used){
            AdapterProfile &p=c.profiles[i];memset(&p,0,sizeof(p));p.used=true;memcpy(p.mac,c.network.mac,6);selected=i;
#if defined(P08_HTTP_HOST)
            // Legacy host fixtures seed the public active-token view before
            // their first model adapter is selected. Native cold state is empty.
            if(c.selected_profile==255)p.portal=static_cast<const PortalCredentials&>(c);
#endif
            break;
        }
    }
    c.selected_profile=selected;
    if(selected<2)static_cast<PortalCredentials&>(c)=c.profiles[selected].portal;
    else {memset(static_cast<PortalCredentials*>(&c),0,sizeof(PortalCredentials));if(c.network.mac_valid)c.network.connected=false;}
    publish_summary(c);
}
static bool adapter_at(BackendContext &c,unsigned index,NetworkInfo &out) {
    memset(&out,0,sizeof(out));strcpy(out.ip,"0.0.0.0");
    if(c.network_hooks.adapter_at)return c.network_hooks.adapter_at(c.network_context,index,out);
#if defined(P08_HTTP_HOST)
    if(index)return false;out=c.network;return true;
#else
    if(index>=unsigned(NetworkInterface::getNumberOfInterfaces()))return false;
    NetworkInterface *i=NetworkInterface::getInterface(index);if(!i)return true;
    uint8_t ip[12];
    LOCK_TCPIP_CORE();
    i->getIpAddr(ip);i->getMacAddr(out.mac);out.wireless=i->is_wireless();out.adapter_handle=i;
    out.mac_valid=valid_mac(out.mac);out.connected=i->is_link_up()&&out.mac_valid&&(ip[0]||ip[1]||ip[2]||ip[3]);
    UNLOCK_TCPIP_CORE();
    snprintf(out.ip,sizeof(out.ip),"%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);return true;
#endif
}
static void select_network(BackendContext &c) {
    uint8_t previous[6]={};const AdapterProfile *prior=active_profile(c);if(prior)memcpy(previous,prior->mac,6);
    NetworkInfo best={};strcpy(best.ip,"0.0.0.0");
    for(unsigned n=0;n<8;n++){
        NetworkInfo candidate;if(!adapter_at(c,n,candidate))break;
        candidate.mac_valid=candidate.mac_valid&&valid_mac(candidate.mac);
        if(!candidate.mac_valid)continue;
        if(c.preference==NETWORK_LAN&&candidate.wireless)continue;
        if(c.preference==NETWORK_WLAN&&!candidate.wireless)continue;
        bool candidate_previous=!memcmp(candidate.mac,previous,6),best_previous=!memcmp(best.mac,previous,6);
        bool prefer_class=best.wireless&&!candidate.wireless;
        if(!candidate.connected&&!best.connected&&c.preference==NETWORK_AUTO){
            if(candidate_previous!=best_previous)prefer_class=candidate_previous;else if(best_previous)prefer_class=false;
        }
        if(!best.mac_valid||(candidate.connected&&!best.connected)||(candidate.connected==best.connected&&prefer_class))best=candidate;
    }
    c.network=best;select_profile(c);
}
struct BackendTransaction {
    BackendContext &c;bool entered;
    explicit BackendTransaction(BackendContext &context):c(context),entered(false){
#if !defined(P08_HTTP_HOST)
        portENTER_CRITICAL();
#endif
        if(!c.transaction_active){c.transaction_active=true;entered=true;}
#if !defined(P08_HTTP_HOST)
        portEXIT_CRITICAL();
#endif
        if(entered)select_network(c);
    }
    ~BackendTransaction(){if(entered){sync_profile(c);publish_summary(c);
#if !defined(P08_HTTP_HOST)
        portENTER_CRITICAL();
#endif
        c.transaction_active=false;
#if !defined(P08_HTTP_HOST)
        portEXIT_CRITICAL();
#endif
    }}
};
static bool apply_portal(PortalCredentials &c,bool is_key,const char *value) {
    if(!value)return false;
    size_t n=strlen(value);if(n>(is_key?64U:256U))return false;
    for(size_t i=0;i<n;i++)if(static_cast<unsigned char>(value[i])<0x21||static_cast<unsigned char>(value[i])>0x7e)return false;
    if(is_key){strcpy(c.token_key,value);c.token[0]=0;
        for(unsigned i=0;i<4;i++)if(!strcmp(c.token_keys[i],value)){strcpy(c.token,c.token_values[i]);break;}return true;}
    if(!c.token_key[0])return true;
    unsigned slot=4;for(unsigned i=0;i<4;i++)if(!strcmp(c.token_keys[i],c.token_key)){slot=i;break;}
    if(slot==4)for(unsigned i=0;i<4;i++)if(!c.token_keys[i][0]){slot=i;break;}
    if(slot==4){slot=c.token_replacement%4;c.token_replacement=uint8_t((slot+1)%4);}
    strcpy(c.token_keys[slot],c.token_key);strcpy(c.token_values[slot],value);strcpy(c.token,value);return true;
}
static bool portal_changed(const PortalCredentials &before,const PortalCredentials &after) {
    static_assert(sizeof(PortalCredentials)==1611,"Portal credential comparison must not include padding");
    return memcmp(&before,&after,sizeof(before))!=0;
}
static bool commit_portal_headers(BackendContext &c,const Workspace &w) {
    if(!w.key_seen&&!w.token_seen)return true;
    const char *key=w.key_seen?w.token_key:c.token_key;
    // A key-only rotation must never revive an old cached secret. Keep the
    // native four-key cache, but activate each new response as one full pair.
    if(!*key||(!w.token_seen&&strcmp(key,c.token_key)))return false;
    if(!w.token_seen)return true;
    PortalCredentials *staged=static_cast<PortalCredentials*>(malloc(sizeof(PortalCredentials)));
    if(!staged)return false;
    struct FreePortal{PortalCredentials *p;~FreePortal(){wipe_secret(p,sizeof(*p));free(p);}}free_portal={staged};
    *staged=static_cast<const PortalCredentials&>(c);
    if(!apply_portal(*staged,true,key)||!apply_portal(*staged,false,w.token))return false;
    if(!portal_changed(c,*staged))return true;
    static_cast<PortalCredentials&>(c)=*staged;sync_profile(c);
    bool saved=credentials_changed(c);
    return saved||!c.persist_credentials;
}
} // namespace

void backend_summary(const BackendContext &c,BackendSummary &out) {
#if !defined(P08_HTTP_HOST)
    portENTER_CRITICAL();
#endif
    out=c.summary_cache;
#if !defined(P08_HTTP_HOST)
    portEXIT_CRITICAL();
#endif
}
AdapterProfile *active_profile(BackendContext &c) {
    return c.selected_profile<2&&c.profiles[c.selected_profile].used?&c.profiles[c.selected_profile]:0;
}
const AdapterProfile *active_profile(const BackendContext &c) {
    return c.selected_profile<2&&c.profiles[c.selected_profile].used?&c.profiles[c.selected_profile]:0;
}
void set_network_hooks(BackendContext &c,const BackendNetworkHooks &hooks,void *opaque){if(c.transaction_active)return;c.network_hooks=hooks;c.network_context=opaque;}
bool set_network_preference(BackendContext &c,uint8_t mode) {
    if(mode>NETWORK_WLAN||c.transaction_active||(c.preferences_required&&!c.preferences_ready))return false;
    p12_reset_session(c);
    if(c.preference==mode){select_network(c);return !c.preferences_required||!c.credentials_dirty||credentials_changed(c);}
    c.preference=mode;select_network(c);bool saved=credentials_changed(c);return saved||!c.preferences_required;
}
bool bind_selected_socket_port(BackendContext &c,int socket,uint16_t port) {
    if(!c.network.connected||!c.network.mac_valid)return false;
    if(c.network_hooks.bind_socket){if(port)return false;return c.network_hooks.bind_socket(c.network_context,c.network,socket);}
#if defined(P08_HTTP_HOST)
    // Existing host fixtures intentionally model their network identity. New
    // selection tests supply a real source-address bind hook and check peers.
    if(!port)return true;
    uint8_t expected[4];if(!numeric(c.network.ip,expected))return false;
    sockaddr_in local={};local.sin_family=AF_INET;local.sin_port=htons(port);memcpy(&local.sin_addr,expected,4);
    return ::bind(socket,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0;
#else
    NetworkInterface *selected=static_cast<NetworkInterface*>(c.network.adapter_handle);bool found=false;
    for(unsigned n=0;n<unsigned(NetworkInterface::getNumberOfInterfaces());n++)if(NetworkInterface::getInterface(n)==selected){found=true;break;}
    if(!found||!selected)return false;
    uint8_t mac[6],addresses[12],expected[4];LOCK_TCPIP_CORE();selected->getMacAddr(mac);selected->getIpAddr(addresses);bool link=selected->is_link_up();UNLOCK_TCPIP_CORE();
    if(!link||memcmp(mac,c.network.mac,6)||!numeric(c.network.ip,expected)||memcmp(addresses,expected,4)||!selected->bindSocket(socket))return false;
    sockaddr_in local;memset(&local,0,sizeof(local));local.sin_len=sizeof(local);local.sin_family=AF_INET;local.sin_port=htons(port);memcpy(&local.sin_addr,expected,4);
    return lwip_bind(socket,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0;
#endif
}
bool bind_selected_socket(BackendContext &c,int socket){return bind_selected_socket_port(c,socket,0);}
bool resolve_backend_ipv4(BackendContext &c,const char *host,uint8_t out[4],uint32_t timeout_ms){
    if(!host||!out||timeout_ms<50||timeout_ms>60000)return false;
    unsigned n=0;for(;n<254&&host[n];n++){char b=host[n];if(!((b>='a'&&b<='z')||(b>='A'&&b<='Z')||(b>='0'&&b<='9')||b=='.'||b=='-'||b=='_'))return false;}
    if(!n||n>=254)return false;Deadline d(timeout_ms,&c.cancel_requested,c.should_cancel,c.cancel_context);return d.remaining()&&resolve(host,out,d);
}
// Optional command module is linked strongly in the native service. A weak
// fallback keeps the existing standalone HTTP/formatter host suites runnable.
bool __attribute__((weak)) p12_execute(BackendContext&,uint8_t,uint8_t,const uint8_t*,uint32_t,uint8_t*,uint32_t,BackendResult&){return false;}
void __attribute__((weak)) p12_reset_session(BackendContext&){}
bool __attribute__((weak)) p15_load_public_server(char *,uint32_t){return false;}
bool __attribute__((weak)) p15_save_public_server(const char *){return false;}

// A header belongs to the adapter frozen at transaction entry. Refreshing the
// provider while an HTTP response arrives never changes this profile's owner.
bool apply_security_header(BackendContext &c,bool is_key,const char *value) {
    const PortalCredentials before=static_cast<const PortalCredentials&>(c);
    if(!apply_portal(c,is_key,value))return false;
    sync_profile(c);
    if(portal_changed(before,c))credentials_changed(c);
    return true;
}

namespace {
struct CredentialWriter {
    uint8_t *p;uint16_t cap,pos;bool ok;
    CredentialWriter(uint8_t *out,uint16_t capacity):p(out),cap(capacity),pos(0),ok(out!=0){}
    void byte(uint8_t v){if(pos>=cap){ok=false;return;}p[pos++]=v;}
    void raw(const uint8_t *v,unsigned n){for(unsigned i=0;i<n;i++)byte(v[i]);}
    void text(const char *v,unsigned maximum){unsigned n=0;while(n<=maximum&&v[n])n++;
        if(n>maximum){ok=false;return;}byte(uint8_t(n));byte(uint8_t(n>>8));
        for(unsigned i=0;i<n;i++){uint8_t b=uint8_t(v[i]);if(b<0x21||b>0x7e)ok=false;byte(b);}}
};
struct CredentialReader {
    const uint8_t *p;uint16_t length,pos;bool ok;
    CredentialReader(const uint8_t *in,uint16_t size):p(in),length(size),pos(0),ok(in!=0){}
    uint8_t byte(){if(pos>=length){ok=false;return 0;}return p[pos++];}
    void raw(uint8_t *v,unsigned n){for(unsigned i=0;i<n;i++)v[i]=byte();}
    void text(char *v,unsigned maximum){unsigned n=byte();n|=unsigned(byte())<<8;
        if(!ok||n>maximum||n>unsigned(length-pos)){ok=false;return;}
        for(unsigned i=0;i<n;i++){uint8_t b=byte();if(b<0x21||b>0x7e)ok=false;v[i]=char(b);}v[n]=0;}
};
static bool hex_bearer(const char *s){unsigned n=0;for(;n<65&&s[n];n++)if(!((s[n]>='0'&&s[n]<='9')||(s[n]>='a'&&s[n]<='f')||(s[n]>='A'&&s[n]<='F')))return false;return n==0||n==64;}
static bool bounded_secret(const char *s,unsigned maximum){
    for(unsigned i=0;i<=maximum;i++){uint8_t v=uint8_t(s[i]);if(!v)return true;if(v<0x21||v>0x7e)return false;}return false;
}
static bool canonical_origin(const char *source,char out[97]) {
    size_t length=strlen(source);if(length<9||length>96||memcmp(source,"https://",8))return false;
    size_t end=8;while(end<length&&source[end]!=':')end++;
    if(end==8||source[8]=='.'||source[end-1]=='.')return false;
    size_t label=8;for(size_t i=8;i<=end;i++){
        if(i==end||source[i]=='.'){if(i==label||i-label>63||source[label]=='-'||source[i-1]=='-')return false;label=i+1;continue;}
        char v=source[i];if(!((v>='a'&&v<='z')||(v>='A'&&v<='Z')||(v>='0'&&v<='9')||v=='-'))return false;}
    unsigned port=443;if(end<length){port=0;if(++end==length)return false;for(size_t i=end;i<length;i++){if(source[i]<'0'||source[i]>'9'||port>6553)return false;port=port*10+unsigned(source[i]-'0');if(port>65535)return false;}if(!port)return false;}
    size_t host_end=8;while(host_end<length&&source[host_end]!=':')host_end++;
    memcpy(out,source,host_end);for(size_t i=8;i<host_end;i++)if(out[i]>='A'&&out[i]<='Z')out[i]+=32;
    unsigned digits=port>=10000?5:port>=1000?4:port>=100?3:port>=10?2:1;
    if(host_end+1+digits>96)return false; // target snprintf returns written, not required size
    int added=snprintf(out+host_end,97-host_end,":%u",port);return added==int(1+digits);
}
static bool secure_state_valid(const p14::SecureState &s) {
    unsigned seed=0,id=0;for(unsigned i=0;i<32;i++)seed|=s.seed[i];for(unsigned i=0;i<16;i++)id|=s.bootstrap_id[i];
    return s.provisioned?(seed&&id&&s.epoch):(seed==0&&id==0&&s.epoch==0);
}
static bool url_origin(const Url &url,char out[97]) {
    if(!url.secure)return false;unsigned host=strlen(url.host),port=url.port;
    unsigned digits=port>=10000?5:port>=1000?4:port>=100?3:port>=10?2:1;
    if(8+host+1+digits>96)return false;
    memcpy(out,"https://",8);for(unsigned i=0;i<host;i++){char c=url.host[i];out[8+i]=(c>='A'&&c<='Z')?char(c+32):c;}
    int n=snprintf(out+8+host,97-8-host,":%u",port);return n==int(1+digits);
}
static const char *request_bearer(const BackendContext *context,const Workspace &w) {
    if(!context||!w.url.secure||w.bearer_suppressed||same(w.url.host,"firmware.port64.de"))return 0;
    const AdapterProfile *profile=active_profile(*context);if(!profile||memcmp(profile->mac,context->network.mac,6))return 0;
    char origin[97];if(!url_origin(w.url,origin))return 0;
    // Two explicitly configured profiles may share an origin. The fixed
    // Port64 credential wins once; a remote rejection never retries another.
    if(!strcmp(origin,"https://api.port64.de:443")&&profile->port64_bearer[0])return hex_bearer(profile->port64_bearer)?profile->port64_bearer:0;
    if(profile->custom_bearer[0]&&hex_bearer(profile->custom_bearer)&&bounded_secret(profile->custom_origin,96)&&!strcmp(origin,profile->custom_origin))return profile->custom_bearer;
    return 0;
}
static bool portal_present(const PortalCredentials &p) {
    for(unsigned i=0;i<4;i++)if(p.token_values[i][0])return true;return p.token[0]!=0;
}
static bool valid_profile(const AdapterProfile &p) {
    if(!bounded_secret(p.portal.token_key,64)||!bounded_secret(p.portal.token,256)||
       !bounded_secret(p.port64_bearer,64)||!bounded_secret(p.custom_bearer,64)||!bounded_secret(p.custom_origin,96))return false;
    for(unsigned i=0;i<4;i++)if(!bounded_secret(p.portal.token_keys[i],64)||!bounded_secret(p.portal.token_values[i],256))return false;
    if(!valid_mac(p.mac)||p.portal.token_replacement>=4||!hex_bearer(p.port64_bearer)||!hex_bearer(p.custom_bearer))return false;
    if(bool(p.custom_bearer[0])!=bool(p.custom_origin[0]))return false;
    if(p.custom_origin[0]){char normalized[97];if(!canonical_origin(p.custom_origin,normalized)||strcmp(normalized,p.custom_origin))return false;}
    for(unsigned i=0;i<4;i++){
        if(!p.portal.token_keys[i][0]&&p.portal.token_values[i][0])return false;
        if(p.portal.token_keys[i][0])for(unsigned j=0;j<i;j++)if(!strcmp(p.portal.token_keys[i],p.portal.token_keys[j]))return false;
    }return true;
}
}
static BackendResult auth_profiles(BackendContext &c,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity) {
    if(protocol!='R'||length<3||request[0]!=1)return fail(2,HTTP_ARGUMENT);
    AdapterProfile *p=active_profile(c);if(!p)return fail(3,HTTP_CONNECT);
    uint8_t operation=request[1],profile=request[2];
    if(operation==0){
        if(length!=3||(profile!=2&&profile!=255))return fail(2,HTTP_ARGUMENT);
        const char *origin=(profile==1||profile==255)?p->custom_origin:"";size_t n=strlen(origin);
        if(capacity<8+n)return fail(2,HTTP_LENGTH);memcpy(response,"P64A",4);response[4]=1;
        response[5]=profile==2?(portal_present(p->portal)?4:0):uint8_t(((profile==0||profile==255)&&p->port64_bearer[0]?1:0)|((profile==1||profile==255)&&p->custom_bearer[0]?2:0));
        response[6]=uint8_t(n);response[7]=uint8_t(n>>8);if(n)memcpy(response+8,origin,n);return good(8+n);
    }
    if(operation==2){
        if(length!=3||profile>2)return fail(2,HTTP_ARGUMENT);
        if(profile==0)memset(p->port64_bearer,0,sizeof(p->port64_bearer));
        else if(profile==1){memset(p->custom_bearer,0,sizeof(p->custom_bearer));memset(p->custom_origin,0,sizeof(p->custom_origin));}
        else memset(&p->portal,0,sizeof(p->portal));
        return (credentials_changed(c)||!c.persist_credentials)?good():fail(1,HTTP_WRITE);
    }
    if(operation!=1||profile>1)return fail(2,HTTP_ARGUMENT);
    const uint8_t *token=request+3;char origin[97]={};
    if(profile==0){if(length!=67)return fail(2,HTTP_ARGUMENT);}
    else{
        if(length<5)return fail(2,HTTP_ARGUMENT);unsigned n=unsigned(request[3])|(unsigned(request[4])<<8);
        if(!n||n>96||length!=5+n+64)return fail(2,HTTP_ARGUMENT);
        char input[97];memcpy(input,request+5,n);input[n]=0;if(memchr(input,0,n)||!canonical_origin(input,origin)||!strcmp(origin,"https://api.port64.de:443"))return fail(2,HTTP_ARGUMENT);token=request+5+n;
    }
    char bearer[65];memcpy(bearer,token,64);bearer[64]=0;if(strlen(bearer)!=64||!hex_bearer(bearer))return fail(2,HTTP_ARGUMENT);
    for(unsigned i=0;i<64;i++)if(bearer[i]>='A'&&bearer[i]<='F')bearer[i]+=32;
    if(profile==0)memcpy(p->port64_bearer,bearer,65);else{memcpy(p->custom_bearer,bearer,65);strcpy(p->custom_origin,origin);}
    wipe_secret(bearer,sizeof(bearer));return (credentials_changed(c)||!c.persist_credentials)?good():fail(1,HTTP_WRITE);
}

uint16_t serialize_credentials(const BackendContext &c,uint8_t *out,uint16_t capacity) {
    if(c.preference>NETWORK_WLAN||!secure_state_valid(c.secure))return 0;
    CredentialWriter w(out,capacity);w.raw(reinterpret_cast<const uint8_t*>("P12C"),4);w.byte(2);w.byte(c.preference);w.byte(2);w.byte(0);
    for(unsigned n=0;n<2;n++){
        const AdapterProfile &p=c.profiles[n];w.byte(p.used?1:0);if(!p.used)continue;
        if(!valid_profile(p))return 0;
        if(n&&c.profiles[0].used&&!memcmp(p.mac,c.profiles[0].mac,6))return 0;
        w.raw(p.mac,6);w.byte(p.portal.token_replacement);w.text(p.portal.token_key,64);
        for(unsigned i=0;i<4;i++){w.text(p.portal.token_keys[i],64);w.text(p.portal.token_values[i],256);}
        w.text(p.port64_bearer,64);w.text(p.custom_bearer,64);w.text(p.custom_origin,96);
    }
    w.byte(c.secure.provisioned?1:0);w.raw(c.secure.seed,32);w.raw(c.secure.bootstrap_id,16);
    for(unsigned i=0;i<8;i++)w.byte(uint8_t(c.secure.epoch>>(8*i)));
    return w.ok?w.pos:0;
}
static bool decode_credentials(BackendContext *destination,const uint8_t *bytes,uint16_t length) {
    if((destination&&destination->transaction_active)||!bytes||length<10||length>6000)return false;
    AdapterProfile *profiles=static_cast<AdapterProfile*>(calloc(2,sizeof(AdapterProfile)));if(!profiles)return false;
    struct FreeProfiles{AdapterProfile *p;~FreeProfiles(){wipe_secret(p,2*sizeof(AdapterProfile));free(p);}}free_profiles={profiles};
    CredentialReader r(bytes,length);uint8_t magic[4];r.raw(magic,4);
    uint8_t schema=r.byte();if(memcmp(magic,"P12C",4)||(schema!=1&&schema!=2))return false;uint8_t mode=r.byte();if(mode>NETWORK_WLAN||r.byte()!=2||r.byte()!=0)return false;
    for(unsigned n=0;n<2;n++){
        uint8_t used=r.byte();if(used>1)return false;AdapterProfile &p=profiles[n];p.used=used;if(!used)continue;
        r.raw(p.mac,6);p.portal.token_replacement=r.byte();r.text(p.portal.token_key,64);
        for(unsigned i=0;i<4;i++){r.text(p.portal.token_keys[i],64);r.text(p.portal.token_values[i],256);}
        r.text(p.port64_bearer,64);r.text(p.custom_bearer,64);r.text(p.custom_origin,96);
        if(!r.ok||!valid_profile(p)||(n&&profiles[0].used&&!memcmp(p.mac,profiles[0].mac,6)))return false;
        for(unsigned i=0;i<4;i++)if(!strcmp(p.portal.token_key,p.portal.token_keys[i])){strcpy(p.portal.token,p.portal.token_values[i]);break;}
    }
    p14::SecureState secure={};
    struct WipeSecure{p14::SecureState &state;~WipeSecure(){wipe_secret(&state,sizeof(state));}}wipe_secure={secure};
    if(schema==2){
        uint8_t provisioned=r.byte();if(provisioned>1)return false;secure.provisioned=provisioned!=0;
        r.raw(secure.seed,32);r.raw(secure.bootstrap_id,16);
        for(unsigned i=0;i<8;i++)secure.epoch|=uint64_t(r.byte())<<(8*i);
        if(!secure_state_valid(secure))return false;
    }
    if(!r.ok||r.pos!=r.length)return false;
    if(destination){BackendContext &c=*destination;
        memcpy(c.profiles,profiles,2*sizeof(AdapterProfile));c.secure=secure;c.preference=mode;c.selected_profile=255;
        memset(static_cast<PortalCredentials*>(&c),0,sizeof(PortalCredentials));
        c.credentials_dirty=false;c.credentials_saved=true;publish_summary(c);}
    return true;
}
bool deserialize_credentials(BackendContext &c,const uint8_t *bytes,uint16_t length){return decode_credentials(&c,bytes,length);}
bool validate_credentials(const uint8_t *bytes,uint16_t length){return decode_credentials(0,bytes,length);}
bool credentials_changed(BackendContext &c) {
    AdapterProfile *profile=active_profile(c);
    if(profile)static_cast<PortalCredentials&>(c)=profile->portal;
    c.credentials_dirty=true;c.credentials_saved=false;publish_summary(c);
    if(!c.persist_credentials)return false;
    uint8_t *bytes=static_cast<uint8_t*>(malloc(6000));if(!bytes)return false;
    uint16_t n=serialize_credentials(c,bytes,6000);
    bool saved=n&&c.persist_credentials(c.persist_context,bytes,n);
    wipe_secret(bytes,6000);free(bytes);
    if(saved){c.credentials_dirty=false;c.credentials_saved=true;}publish_summary(c);return saved;
}

bool portal_response_authorized(const char *url) {
    if(!url)return false;
    Url *parsed=static_cast<Url*>(malloc(sizeof(Url)));if(!parsed)return false;
    bool valid=parse_url(reinterpret_cast<const uint8_t*>(url),strlen(url),*parsed);
    bool authorized=valid&&((!parsed->secure&&parsed->port==80&&(same(parsed->host,"x.wic64.net")||same(parsed->host,"t.wic64.net")))||
        (parsed->secure&&parsed->port==443&&same(parsed->host,"wic64.net")&&!strcmp(parsed->path,"/sid.php")));
    wipe_secret(parsed,sizeof(*parsed));free(parsed);return authorized;
}
bool adapt_legacy_prefanswer(uint8_t protocol,const char *url,uint16_t code,uint8_t *body,uint32_t &length) {
    if(protocol!='W'||code!=201||!portal_response_authorized(url))return true;
    if(length>MAX_RESPONSE||(!body&&length))return false;
    if(!length)return true;
    uint32_t begin=0;
    for(unsigned field=0;field<3;field++){const uint8_t *p=static_cast<const uint8_t*>(memchr(body+begin,1,length-begin));if(!p)break;begin=uint32_t(p-body)+1;}
    uint32_t end=begin;while(end<length&&body[end]!=1&&body[end])end++;
    if(end-begin>63)return false;
    length=end-begin;if(length)memmove(body,body+begin,length);return true;
}

BackendResult http_request(const uint8_t *url,uint32_t url_length,const uint8_t *post,uint32_t post_length,bool is_post,uint8_t *body,uint32_t capacity,uint32_t timeout_ms,const volatile bool *cancel,bool (*should_cancel)(void *),void *cancel_context,BackendContext *session,uint8_t protocol,const uint8_t *original_request,uint32_t original_request_length) {
    if((!url&&url_length)||!body||!capacity||capacity>MAX_RESPONSE||post_length>MAX_REQUEST||(post_length&&!post)||timeout_ms<50||timeout_ms>60000)return http_fail(2,HTTP_ARGUMENT);
    struct ResponseGuard{uint8_t *body;uint32_t capacity;bool complete;
        ~ResponseGuard(){if(!complete)wipe_secret(body,capacity);}
    } response_guard={body,capacity,false};
    Workspace *w=static_cast<Workspace*>(malloc(sizeof(Workspace)));if(!w)return http_fail(1,HTTP_SOCKET);
    struct FreeWork{Workspace *p;~FreeWork(){wipe_secret(p,sizeof(Workspace));free(p);}}free_work={w};
    if(!request_string(url,url_length,w->current,sizeof(w->current)))return http_fail(2,HTTP_URL);
    Deadline d(timeout_ms,cancel,should_cancel,cancel_context);w->bearer_suppressed=false;
    w->portal_authority=portal_response_authorized(w->current);
    for(unsigned redirects=0;redirects<=3;redirects++) {
        if(!d.remaining())return http_fail(4,d.cancelled()?HTTP_CANCELLED:HTTP_DEADLINE);
        if(!parse_url(reinterpret_cast<const uint8_t*>(w->current),strlen(w->current),w->url))return http_fail(2,HTTP_URL);
        if(!redirects){strcpy(w->initial_host,w->url.host);w->initial_port=w->url.port;w->initial_secure=w->url.secure;}
        else if(!same(w->initial_host,w->url.host)||w->initial_port!=w->url.port||w->initial_secure!=w->url.secure)w->bearer_suppressed=true;
#if defined(P18_LOG) && P18_LOG
        if(session){
            uint8_t log_command;uint32_t log_request;
            {TraceGuard guard;log_command=session->trace.command;log_request=session->trace.request_id;}
            p18log::http_detail(log_command,protocol,log_request,trace_now_ms(),reinterpret_cast<const uint8_t*>(w->current),strlen(w->current),0,is_post||request_bearer(session,*w)!=0,
                !redirects&&!is_post?original_request:0,!redirects&&!is_post?original_request_length:0);
        }
#endif
#if !P14_TLS
        if(w->url.secure)return http_fail(4,HTTP_UNSUPPORTED);
#else
        if(w->url.secure&&!session)return http_fail(4,HTTP_TLS_UNSEEDED);
#endif
        if(session)trace_phase(session->trace,TRACE_DNS);
        uint8_t ip[4];if(!resolve(w->url.host,ip,d))return http_fail(4,d.cancelled()?HTTP_CANCELLED:d.remaining()?HTTP_DNS:HTTP_DEADLINE);
        if(session)trace_phase(session->trace,TRACE_CONNECT);
        Socket connection(d);connection.fd=P8_SOCKET(AF_INET,SOCK_STREAM,0);if(connection.fd<0)return http_fail(3,HTTP_SOCKET);
        if(session&&!bind_selected_socket(*session,connection.fd))return http_fail(3,HTTP_CONNECT);
        timeval cleanup;cleanup.tv_sec=0;cleanup.tv_usec=200000;
        if(P8_SETSOCKOPT(connection.fd,SOL_SOCKET,SO_SNDTIMEO,&cleanup,sizeof(cleanup))<0||P8_FCNTL(connection.fd,F_SETFL,O_NONBLOCK)<0)return http_fail(3,HTTP_SOCKET);
        sockaddr_in address;memset(&address,0,sizeof(address));address.sin_family=AF_INET;address.sin_port=htons(w->url.port);memcpy(&address.sin_addr,ip,4);
#if !defined(P08_HTTP_HOST)
        address.sin_len=sizeof(address);
#endif
        if(P8_CONNECT(connection.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))<0) {
            if(errno!=EINPROGRESS&&errno!=EWOULDBLOCK&&errno!=EALREADY)return http_fail(3,HTTP_CONNECT);
            if(!ready(connection.fd,true,d))return http_fail(3,d.cancelled()?HTTP_CANCELLED:HTTP_DEADLINE);
            int error=0;socklen_t size=sizeof(error);if(P8_GETSOCKOPT(connection.fd,SOL_SOCKET,SO_ERROR,&error,&size)<0||error)return http_fail(3,HTTP_CONNECT);
        }
        if(w->url.secure){
            uint8_t numeric_ip[4];uint8_t error=connection.secure(w->url.host,numeric(w->url.host,numeric_ip),session);
            if(error)return http_fail(4,error);
        }
        if(session)trace_phase(session->trace,TRACE_HTTP_WRITE);
        const char *bearer=request_bearer(session,*w);
        // Advertise the WiC64 compatibility version first. Keep the native
        // provider/version separately, as VICE also does for revised requests.
        const char *agent=protocol=='W'?"ESP32HTTPClient":P18_HTTP_USER_AGENT;
        // Ultimate's small snprintf returns bytes written on truncation, not
        // the C99 required length. Send the bounded URL separately so a long
        // path can never silently truncate the request line.
        const char *method=is_post?"POST ":"GET ";
        if(!write_all(connection,reinterpret_cast<const uint8_t*>(method),strlen(method),d)||!write_all(connection,reinterpret_cast<const uint8_t*>(w->url.path),strlen(w->url.path),d))return http_fail(4,connection.failure(HTTP_WRITE));
        int n=snprintf(w->request,sizeof(w->request)," HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n",w->url.authority,agent);
        if(n<0||unsigned(n)>=sizeof(w->request)||!write_all(connection,reinterpret_cast<const uint8_t*>(w->request),n,d))return http_fail(4,connection.failure(HTTP_WRITE));
        if(bearer){
            static const char prefix[]="Authorization: Bearer ";
            if(!write_all(connection,reinterpret_cast<const uint8_t*>(prefix),sizeof(prefix)-1,d)||
               !write_all(connection,reinterpret_cast<const uint8_t*>(bearer),64,d)||
               !write_all(connection,reinterpret_cast<const uint8_t*>("\r\n"),2,d))return http_fail(4,connection.failure(HTTP_WRITE));
        }
        // Exact upstream 321009... multipart framing, including its first LF.
        static const char post_head[]="--WiC64-Binary-Data\nContent-Disposition: form-data; name=\"data\"\r\n\r\n";
        static const char post_tail[]="\r\n--WiC64-Binary-Data--\r\n";
        if(is_post){
            // MAX_REQUEST is 8192; this sum is at most 8284. The target
            // formatter supports %u but does not implement the %lu modifier.
            const unsigned wire_length=unsigned(post_length+sizeof(post_head)-1+sizeof(post_tail)-1);
            n=snprintf(w->request,sizeof(w->request),"Content-Type: multipart/form-data;boundary=\"WiC64-Binary-Data\"\r\nContent-Length: %u\r\n",wire_length);
            if(n<0||!write_all(connection,reinterpret_cast<const uint8_t*>(w->request),n,d))return http_fail(4,connection.failure(HTTP_WRITE));
        }
        if(!write_all(connection,reinterpret_cast<const uint8_t*>("\r\n"),2,d))return http_fail(4,connection.failure(HTTP_WRITE));
        if(is_post&&(!write_all(connection,reinterpret_cast<const uint8_t*>(post_head),sizeof(post_head)-1,d)||!write_all(connection,post,post_length,d)||!write_all(connection,reinterpret_cast<const uint8_t*>(post_tail),sizeof(post_tail)-1,d)))return http_fail(4,connection.failure(HTTP_WRITE));
        if(session)trace_phase(session->trace,TRACE_HTTP_HEADERS);
        Reader reader(connection,d);Headers response;
        if(!headers(reader,*w,response,capacity))return http_fail(4,connection.failure(HTTP_HEADERS));
#if defined(P18_LOG) && P18_LOG
        // Credential-bearing headers make protection sticky before a redirect,
        // body read or later response publication can expose application data.
        // Copy only public trace primitives while interrupts are excluded.
        if(session&&(w->key_seen||w->token_seen)){
            uint8_t log_command;uint32_t log_request_id;
            {TraceGuard guard;log_command=session->trace.command;log_request_id=session->trace.request_id;}
            p18log::http_detail(log_command,protocol,log_request_id,trace_now_ms(),reinterpret_cast<const uint8_t*>(w->current),strlen(w->current),0,true);
        }
#endif
        if(response.code>=300&&response.code<400)w->portal_authority=false;
        if(response.code==301||response.code==302||response.code==307||response.code==308) {
            if(is_post||bearer)return http_fail(4,HTTP_UNSUPPORTED,response.code);
            if(redirects==3)return http_fail(4,HTTP_REDIRECT_LIMIT,response.code);
            int next=redirect_url(*w);if(next<0)return http_fail(4,HTTP_TLS_DOWNGRADE,response.code);
            if(!next)return http_fail(4,HTTP_URL,response.code);continue;
        }
        if(response.code>=300&&response.code<400)return http_fail(4,HTTP_UNSUPPORTED,response.code);
        if(response.code>=400)return http_fail(5,HTTP_REMOTE_STATUS,response.code);
        // Unknown/chunked and credential-bearing responses stay below 64KiB
        // so their complete termination and credential commit precede success.
        // Retain the native E-protocol cache's exact 65536-byte fixed-length
        // noncredential response; larger queued transfers remain unsupported.
        if(session)trace_phase(session->trace,TRACE_HTTP_BODY);
        bool credential_response=w->portal_authority&&(w->key_seen||w->token_seen);
        if(response.have_length&&response.length>=65536&&(protocol!='E'||credential_response))return http_fail(2,HTTP_LENGTH,response.code);
        uint32_t body_capacity=capacity<65535?capacity:65535;
        uint32_t length=0;
        if(response.chunked){if(!chunked(reader,*w,body,body_capacity,length))return http_fail(4,connection.failure(HTTP_READ),response.code);}
        else if(response.have_length){length=response.length;if(!reader.body(body,length))return http_fail(4,connection.failure(HTTP_READ),response.code);}
        else if(response.code!=204&&response.code!=205){
            for(;;){
                uint8_t sentinel=0;uint32_t room=body_capacity-length;
                int got=reader.part(room?body+length:&sentinel,room?room:1);
                if(got<0)return http_fail(4,connection.failure(HTTP_READ),response.code);
                if(!got)break;
                if(!room)return http_fail(4,HTTP_LENGTH,response.code);
                length+=uint32_t(got);
            }
        }
        if(!d.remaining())return http_fail(4,d.cancelled()?HTTP_CANCELLED:HTTP_DEADLINE,response.code);
        const uint32_t received_length=length;
        if(w->portal_authority&&!adapt_legacy_prefanswer(protocol,w->current,response.code,body,length))return http_fail(4,HTTP_LENGTH,response.code);
        if(session&&w->portal_authority&&!commit_portal_headers(*session,*w))return http_fail(1,HTTP_HEADERS,response.code);
#if defined(P18_LOG) && P18_LOG
        if(session){
            uint8_t log_command;uint32_t log_request_id;
            {TraceGuard guard;log_command=session->trace.command;log_request_id=session->trace.request_id;}
            p18log::http_result(log_command,protocol,log_request_id,trace_now_ms(),reinterpret_cast<const uint8_t*>(w->current),strlen(w->current),response.code,received_length,
                is_post||bearer!=0||w->key_seen||w->token_seen);
        }
#else
        (void)received_length;
#endif
        BackendResult result=good(length);result.http_performed=true;result.http_status=response.code;response_guard.complete=true;return result;
    }return http_fail(4,HTTP_REDIRECT_LIMIT);
}

BackendResult http_speedtest(BackendContext &c,const uint8_t *url,uint32_t url_length,
    uint8_t seconds,uint32_t target,SpeedtestResult &out) {
    memset(&out,0,sizeof(out));out.content_length=0xffffffffU;
    if(!url||!url_length||url_length>512||seconds<3||seconds>20||target<262144U||target>16777216U)return http_fail(2,HTTP_ARGUMENT);
    // This diagnostic uses only its absolute URL. It deliberately does not
    // expand credentials, attach bearers, accept redirects, or update tokens.
    Workspace *w=static_cast<Workspace*>(malloc(sizeof(Workspace)));if(!w)return http_fail(1,HTTP_SOCKET);
    struct FreeSpeed{Workspace *p;~FreeSpeed(){wipe_secret(p,sizeof(Workspace));free(p);}}free_work={w};
    if(!request_string(url,url_length,w->current,sizeof(w->current))||!parse_url(reinterpret_cast<const uint8_t*>(w->current),strlen(w->current),w->url))return http_fail(2,HTTP_URL);
    if(!c.network.connected||!c.network.mac_valid)return http_fail(3,HTTP_CONNECT);
    uint32_t setup_limit=c.current_remote_timeout_ms;if(!setup_limit||setup_limit>60000)setup_limit=5000;
    // Leave the requested download phase inside the helper backend bound.
    uint32_t setup_cap=60000U-uint32_t(seconds)*1000U;if(setup_limit>setup_cap)setup_limit=setup_cap;
    Deadline d(setup_limit,&c.cancel_requested,c.should_cancel,c.cancel_context);
#if !P14_TLS
    if(w->url.secure)return http_fail(4,HTTP_UNSUPPORTED);
#endif
    trace_phase(c.trace,TRACE_DNS);
    uint8_t ip[4];if(!resolve(w->url.host,ip,d))return http_fail(4,d.cancelled()?HTTP_CANCELLED:d.remaining()?HTTP_DNS:HTTP_DEADLINE);
    trace_phase(c.trace,TRACE_CONNECT);
    Socket connection(d);connection.fd=P8_SOCKET(AF_INET,SOCK_STREAM,0);
    if(connection.fd<0)return http_fail(3,HTTP_SOCKET);
    if(!bind_selected_socket(c,connection.fd))return http_fail(3,HTTP_CONNECT);
    timeval cleanup={0,200000};
    if(P8_SETSOCKOPT(connection.fd,SOL_SOCKET,SO_SNDTIMEO,&cleanup,sizeof(cleanup))<0||P8_FCNTL(connection.fd,F_SETFL,O_NONBLOCK)<0)return http_fail(3,HTTP_SOCKET);
    sockaddr_in address={};address.sin_family=AF_INET;address.sin_port=htons(w->url.port);memcpy(&address.sin_addr,ip,4);
#if !defined(P08_HTTP_HOST)
    address.sin_len=sizeof(address);
#endif
    if(P8_CONNECT(connection.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))<0){
        if(errno!=EINPROGRESS&&errno!=EWOULDBLOCK&&errno!=EALREADY)return http_fail(3,HTTP_CONNECT);
        if(!ready(connection.fd,true,d))return http_fail(3,d.cancelled()?HTTP_CANCELLED:HTTP_DEADLINE);
        int error=0;socklen_t size=sizeof(error);if(P8_GETSOCKOPT(connection.fd,SOL_SOCKET,SO_ERROR,&error,&size)<0||error)return http_fail(3,HTTP_CONNECT);
    }
    // Speed has a bounded setup phase and a separately bounded measurement
    // phase. Use negotiated TLS operation windows for these explicit phases;
    // ordinary HTTP retains its single immutable complete-request deadline.
    if(w->url.secure){uint8_t numeric_ip[4];uint8_t error=connection.secure(w->url.host,numeric(w->url.host,numeric_ip),&c,true);if(error)return http_fail(4,error);out.flags|=0x10;}
    {uint8_t error=connection.operation(true);if(error)return http_fail(4,error);}
    trace_phase(c.trace,TRACE_HTTP_WRITE);
    if(!write_all(connection,reinterpret_cast<const uint8_t*>("GET "),4,d)||!write_all(connection,reinterpret_cast<const uint8_t*>(w->url.path),strlen(w->url.path),d))return http_fail(4,connection.failure(HTTP_WRITE));
    int n=snprintf(w->request,sizeof(w->request)," HTTP/1.1\r\nHost: %s\r\nUser-Agent: WiC64-Ultimate-Speedtest\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",w->url.authority);
    if(n<0||unsigned(n)>=sizeof(w->request)||!write_all(connection,reinterpret_cast<const uint8_t*>(w->request),n,d))return http_fail(4,connection.failure(HTTP_WRITE));
    trace_phase(c.trace,TRACE_HTTP_HEADERS);
    Reader reader(connection,d);Headers response;
    if(!headers(reader,*w,response,0xffffffffU))return http_fail(4,connection.failure(HTTP_HEADERS));
    out.http_status=response.code;
    if(response.code!=200)return http_fail(5,HTTP_REMOTE_STATUS,response.code);
    if(response.have_length){out.content_length=response.length;out.flags|=8;}
    // Fence setup while its original deadline still applies. Reader readahead
    // remains owned by this connection across the phase boundary. Do not renew
    // the TLS window for individual body chunks.
    {uint8_t error=connection.operation(false);if(error)return http_fail(4,error,response.code);}
    trace_phase(c.trace,TRACE_HTTP_BODY);
    out.setup_ms=now_ms()-d.start;
    d.start=now_ms();d.limit=uint32_t(seconds)*1000;
    {uint8_t error=connection.operation(true);if(error)return http_fail(4,error,response.code);}
    // The explicitly armed ESP measurement window can expire one scheduler
    // tick before the CPU clock observes its own deadline. That is the same
    // bounded measurement end, not a failed HTTP transfer. Setup deadlines
    // and ordinary HTTP do not use this partial-result classification.
    auto measurement_expired=[&](){
        if(d.cancelled())return false;
        uint32_t left=d.remaining();
        // The supplied ESP runs at100Hz. Accept its TLS timeout at most one
        // 10ms tick before CPU expiry; an earlier session/error timeout must
        // remain a failure even after the minimum byte count was received.
        return !d.cancelled()&&(!left||(left<=10U&&connection.failure(HTTP_READ)==HTTP_DEADLINE));
    };
    uint8_t scratch[512];uint32_t remain=response.have_length?response.length:0xffffffffU;
    uint32_t chunk=0;bool chunk_end=false,done=false;
    while(!done&&out.received_bytes<target){
        if(!d.remaining()){if(d.cancelled())return http_fail(4,HTTP_CANCELLED,response.code);out.flags|=2;break;}
        if(response.chunked&&chunk==0){
            if(chunk_end){if(reader.byte()!='\r'||reader.byte()!='\n'){if(measurement_expired()){out.flags|=2;break;}return http_fail(4,connection.failure(HTTP_READ),response.code);}chunk_end=false;}
            unsigned length=0;if(!reader.line(w->line,128,length)||!length){
                if(measurement_expired()){out.flags|=2;break;}return http_fail(4,connection.failure(HTTP_READ),response.code);
            }
            unsigned digits=0;chunk=0;
            for(unsigned i=0;i<length&&w->line[i]!=';';i++){
                unsigned char v=w->line[i];unsigned x=v>='0'&&v<='9'?v-'0':v>='a'&&v<='f'?v-'a'+10:v>='A'&&v<='F'?v-'A'+10:16;
                if(x>15||++digits>8||chunk>(0xffffffffU-x)/16)return http_fail(4,HTTP_HEADERS,response.code);chunk=chunk*16+x;
            }
            if(!digits)return http_fail(4,HTTP_HEADERS,response.code);
            if(!chunk){
                unsigned total=0;bool ended=false;
                for(unsigned lines=0;lines<32;lines++){
                    if(!reader.line(w->line,1025,length))return http_fail(4,connection.failure(HTTP_READ),response.code);
                    total+=length+2;if(total>1024)return http_fail(4,HTTP_HEADERS,response.code);
                    if(!length){ended=true;break;}if(!strchr(w->line,':'))return http_fail(4,HTTP_HEADERS,response.code);
                }
                if(!ended)return http_fail(4,HTTP_HEADERS,response.code);out.flags|=4;break;
            }
        }
        if(!response.chunked&&response.have_length&&!remain){out.flags|=4;break;}
        uint32_t take=target-out.received_bytes;if(take>sizeof(scratch))take=sizeof(scratch);
        if(response.chunked&&take>chunk)take=chunk;
        if(!response.chunked&&response.have_length&&take>remain)take=remain;
        int got=reader.part(scratch,take);
        if(got<0){
            if(measurement_expired()){out.flags|=2;break;}return http_fail(4,connection.failure(HTTP_READ),response.code);
        }
        if(!got){
            // A close-delimited body ends on EOF. Premature EOF inside a
            // declared body or chunk is malformed, never a speed result.
            if(response.chunked||(response.have_length&&remain))return http_fail(4,HTTP_READ,response.code);
            out.flags|=4;break;
        }
        out.received_bytes+=uint32_t(got);
        if(response.chunked){chunk-=uint32_t(got);if(!chunk)chunk_end=true;}
        else if(response.have_length)remain-=uint32_t(got);
    }
    if(out.received_bytes>=target)out.flags|=1;
    if(response.have_length&&!remain)out.flags|=4;
    out.elapsed_ms=now_ms()-d.start;if(!out.elapsed_ms)out.elapsed_ms=1;
    if(d.cancelled())return http_fail(4,HTTP_CANCELLED,response.code);
    if(out.received_bytes<16384U)return http_fail(4,HTTP_LENGTH,response.code);
    BackendResult result=good();result.http_performed=true;result.http_status=response.code;return result;
}

void reset_backend(BackendContext &c) {
    memset(&c,0,sizeof(c));c.selected_profile=255;c.preference=NETWORK_AUTO;
    strcpy(c.server,"http://x.wic64.net/prg/");
    if(!p15_load_public_server(c.server,sizeof(c.server)))strcpy(c.server,"http://x.wic64.net/prg/");
    reset_backend_session(c);
}
void reset_backend_session(BackendContext &c) {
    p12_reset_session(c);sync_profile(c);
    wipe_secret(c.post_url,sizeof(c.post_url));wipe_secret(c.post_url_template,sizeof(c.post_url_template));strcpy(c.last_status,"Success");
    c.next_remote_timeout_ms=c.current_remote_timeout_ms=5000;c.next_transfer_timeout=1;
    c.cancel_requested=false;c.should_cancel=0;c.cancel_context=0;c.transaction_active=false;
    memset(&c.network,0,sizeof(c.network));strcpy(c.network.ip,"0.0.0.0");publish_summary(c);
}
void refresh_network_info(BackendContext &c) {if(!c.transaction_active)select_network(c);}
static BackendResult execute_backend_dispatch(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity) {
    if(!response||!capacity||capacity>MAX_RESPONSE||length>MAX_REQUEST||(length&&!request))return fail(2,HTTP_ARGUMENT);
    BackendTransaction transaction(c);if(!transaction.entered)return fail(1,HTTP_ARGUMENT);BackendResult r=good();
    struct StatusGuard {BackendContext &c;char saved[40];bool keep;
        StatusGuard(BackendContext &context,bool preserve):c(context),keep(preserve){memcpy(saved,c.last_status,sizeof(saved));}
        ~StatusGuard(){if(keep)memcpy(c.last_status,saved,sizeof(saved));}
    } status_guard(c,protocol=='W');
    if(protocol!='W'&&protocol!='R'&&!(protocol=='E'&&(command==0x01||command==0x0f||command==0x28||command==0x2b)))return fail(2,HTTP_ARGUMENT);
    if(command==0x2a){if(length!=1)return fail(2,HTTP_ARGUMENT);char text[40];memcpy(text,c.last_status,sizeof(text));text[39]=0;
        for(unsigned i=0;text[i];i++){
            uint8_t value=uint8_t(text[i]);
            if(request[0]&&value>='A'&&value<='Z')value+=32;
            if(value>=0x5b&&value<=0x7e)value^=0x20;
            else if(value>='A'&&value<='Z')value|=0x80;
            text[i]=char(value);
        }return text_reply(text,response,capacity);}
    // U64 policy: a pending one-shot remote budget survives local metadata,
    // time, IP, RSSI and WiFi-configuration commands. Consume it only for a
    // remote operation (including legacy UDP aliases), even if that operation
    // subsequently fails validation. The original ESP dispatcher consumed it
    // at every request start; this provider intentionally keeps metadata safe.
    bool remote=command==0x01||command==0x0f||command==0x2b||command==0x3f||
        command==0x21||command==0x22||command==0x23||command==0x30||command==0x40||
        command==0x34||command==0x35||command==0x0a||command==0x0b||command==0x1e||command==0x1f||command==0x3e;
    uint32_t timeout=remote?c.next_remote_timeout_ms:5000;
    c.current_remote_timeout_ms=timeout;if(remote)c.next_remote_timeout_ms=5000;
    if(trace_command(command))trace_remote_budget(c.trace,timeout);
    if(c.preferences_required&&!c.preferences_ready&&
       (command==0x01||command==0x0f||command==0x2b||command==0x08||command==0x16||
        command==0x21||command==0x23||command==0x30||command==0x40||
        (command==0x42&&length>=2&&request[1]!=0))){
        status_text(c,"Preferences storage not ready");return fail(1,HTTP_WRITE);
    }
    if(p12_execute(c,command,protocol,request,length,response,capacity,r))return r;
    switch(command) {
    case 0x00:if(length)r=fail(2,HTTP_ARGUMENT);else r=text_reply(P18_WIRE_VERSION,response,capacity);break;
    case 0x26:if(length||capacity<4)r=fail(2,HTTP_ARGUMENT);else{response[0]=P18_WIC64_MAJOR;response[1]=P18_WIC64_MINOR;response[2]=P18_WIC64_PATCH;response[3]=P18_WIC64_REVISION;r=good(4);}break;
    case 0x42:r=auth_profiles(c,protocol,request,length,response,capacity);break;
    case 0xfe:if(length>capacity)r=fail(2,HTTP_LENGTH);else{if(length)memcpy(response,request,length);r=good(length);}break;
    case 0xfd:status_text(c,"Test error");r=fail(length?2:1,HTTP_ARGUMENT);break;
    case 0x06:if(length)r=fail(2,HTTP_ARGUMENT);else r=text_reply(c.network.ip,response,capacity);break;
    case 0x14:{char mac[19];if(length||!c.network.mac_valid){r=fail(1,HTTP_ARGUMENT);break;}snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",c.network.mac[0],c.network.mac[1],c.network.mac[2],c.network.mac[3],c.network.mac[4],c.network.mac[5]);r=text_reply(mac,response,capacity);break;}
    case 0x2c:if(length!=1)r=fail(2,HTTP_ARGUMENT);else r=c.network.connected?good():fail(3,HTTP_CONNECT);break;
    case 0x12:if(length)r=fail(2,HTTP_ARGUMENT);else r=text_reply(c.server,response,capacity);break;
    case 0x08:{
        char *server=static_cast<char*>(malloc(PUBLIC_SERVER_MAX+1));
        if(!server){r=fail(1,HTTP_SOCKET);break;}
        if(!request_string(request,length,server,PUBLIC_SERVER_MAX+1))r=fail(2,HTTP_ARGUMENT);
        else{
            if(!server[0])strcpy(server,"http://x.wic64.net/prg/");
            if(!p15_save_public_server(server))r=fail(1,HTTP_WRITE);
            else{wipe_secret(c.server,sizeof(c.server));strcpy(c.server,server);r=good();}
        }
        wipe_secret(server,PUBLIC_SERVER_MAX+1);free(server);break;
    }
    case 0x28:{
        // Match the target's replacement boundary: never retain a previous
        // secret-bearing URL after a shorter update or a rejected new preset.
        wipe_secret(c.post_url,sizeof(c.post_url));wipe_secret(c.post_url_template,sizeof(c.post_url_template));
        char *work=static_cast<char*>(malloc(2*(MAX_URL+1)));
        if(!work){r=fail(1,HTTP_SOCKET);break;}
        char *url=work,*normalized=work+MAX_URL+1;
        if(!url_text(request,length,false,normalized)||!expand_url(c,reinterpret_cast<uint8_t*>(normalized),strlen(normalized),url))r=fail(2,HTTP_URL);
        else{strcpy(c.post_url,url);strcpy(c.post_url_template,normalized);r=good();}
        wipe_secret(work,2*(MAX_URL+1));free(work);break;
    }
    case 0x32:if(!length||!request[0]||request[0]>60)r=fail(2,HTTP_ARGUMENT);else{c.next_remote_timeout_ms=uint32_t(request[0])*1000;r=good();}break;
    case 0x2d:r=fail(1,HTTP_UNSUPPORTED);break; // No accepted no-op: helper transfer deadline is fixed in P08.
    case 0x01:case 0x0f:case 0x2b:{char *url=static_cast<char*>(malloc(MAX_URL+1));if(!url){r=fail(1,HTTP_SOCKET);break;}
        bool valid=command!=0x2b?expand_url(c,request,length,url,command==0x0f):bool(c.post_url[0]);
        if(command==0x2b&&valid){
            const char *source=c.post_url_template[0]?c.post_url_template:c.post_url;
            valid=expand_url(c,reinterpret_cast<const uint8_t*>(source),strlen(source),url);
        }
        if(!valid)r=fail(2,HTTP_URL);else r=http_request(reinterpret_cast<const uint8_t*>(url),strlen(url),request,command==0x2b?length:0,command==0x2b,response,capacity,timeout,&c.cancel_requested,c.should_cancel,c.cancel_context,&c,protocol,
            command!=0x2b?request:0,command!=0x2b?length:0);
        if(!r.status&&protocol=='W'&&command!=0x2b&&r.length>2&&prg_url(url))r.flags|=LEGACY_PRG_MINUS2;
        wipe_secret(url,MAX_URL+1);free(url);break;}
    case 0x10:
#if !defined(P08_HTTP_HOST)
        if(length)r=fail(2,HTTP_ARGUMENT);else if(wifi.getLastAP()&&strcmp(wifi.getLastAP(),"-"))r=text_reply(wifi.getLastAP(),response,capacity);else r=fail(1,HTTP_UNSUPPORTED);
#else
        r=fail(1,HTTP_UNSUPPORTED);
#endif
        break;
    case 0x11:case 0x2f:r=fail(1,HTTP_UNSUPPORTED);break; // No invented RSSI/passphrase metadata.
    case 0x31:status_text(c,"WiC64 is emulated");r=fail(1,HTTP_UNSUPPORTED);break;
    default:r=fail(2,HTTP_UNSUPPORTED);break;
    }
    bool preserves_status=command==0x00||command==0x26||command==0xfe||command==0x06||command==0x14||command==0x12||command==0x10||command==0x42||command==0x08||command==0x28||command==0x32||command==0x01||command==0x0f||command==0x2b;
    if(!r.status&&preserves_status)status_guard.keep=true;
    if(!r.status)status_text(c,"Success");
    else if(command!=0xfd&&command!=0x31){
        if(r.error==HTTP_CANCELLED)status_text(c,"Cancelled");
        else if(r.error==HTTP_DEADLINE)status_text(c,"Request timed out");
        else if(r.error==HTTP_TLS_UNSEEDED)status_text(c,"TLS seed unavailable");
        else if(r.error==HTTP_TLS_TIME)status_text(c,"TLS clock unavailable");
        else if(r.error==HTTP_TLS_CERTIFICATE)status_text(c,"TLS certificate rejected");
        else if(r.error==HTTP_TLS_HANDSHAKE)status_text(c,"TLS handshake failed");
        else if(r.error==HTTP_TLS_RECORD)status_text(c,"TLS record rejected");
        else if(r.error==HTTP_TLS_DOWNGRADE)status_text(c,"TLS downgrade refused");
        else if(r.http_status){char text[40];snprintf(text,sizeof(text),"HTTP %u",r.http_status);status_text(c,text);}
        else if(r.status==3)status_text(c,!c.network.connected?"Network not connected":
            r.error==HTTP_SOCKET?"Socket unavailable":"Network connection failed");
        else status_text(c,r.error==HTTP_UNSUPPORTED?"Command or format unsupported":"Request failed");
    }
    if(protocol!='E'&&r.length>65535){r.status=2;r.error=HTTP_LENGTH;r.flags=0;r.length=0;status_text(c,"Response requires E protocol");}
    if(protocol=='W'&&r.status){
        // small_printf uses uppercase digits even for %x. Keep the legacy
        // text identical to the host backend without relying on that quirk.
        char undefined[]="Undefined command id 0x00";
        static const char lower_hex[]="0123456789abcdef";
        undefined[sizeof(undefined)-3]=lower_hex[command>>4];
        undefined[sizeof(undefined)-2]=lower_hex[command&15];
        const char *legacy=(command==1||command==0x0f||command==0x2b||command==0x28)?"!0":command==0xfd?"Test error":undefined;
        BackendResult msg=text_reply(legacy,response,capacity,false);r.length=msg.length;r.flags=0;
    }
    return r;
}
BackendResult execute_backend(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity) {
    trace_enter_backend(c.trace,command,protocol);
    BackendResult result=execute_backend_dispatch(c,command,protocol,request,length,response,capacity);
    if(trace_command(command))trace_finish(c.trace,result.status,result.error,result.http_status,result.length);
    return result;
}
} // namespace p08
