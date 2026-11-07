#include "p15_network.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#if defined(P08_HTTP_HOST)
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#define NET_SOCKET socket
#define NET_SENDTO sendto
#define NET_RECVFROM recvfrom
#define NET_CLOSE close
#define NET_SELECT select
#define NET_FCNTL fcntl
#else
extern "C" {
#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
}
#define NET_SOCKET lwip_socket
#define NET_SENDTO lwip_sendto
#define NET_RECVFROM lwip_recvfrom
#define NET_CLOSE lwip_close
#define NET_SELECT lwip_select
#define NET_FCNTL lwip_fcntl
#endif

namespace p08 {
namespace {
struct Datagram {
    int fd; uint8_t mac[6]; char ip[16]; void *adapter; bool wireless;
    Datagram():fd(-1),adapter(0),wireless(false){memset(mac,0,sizeof(mac));memset(ip,0,sizeof(ip));}
} datagram;
uint16_t ping_identifier=0x5764;
uint32_t now_ms(){
#ifdef P08_HTTP_HOST
    timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return uint32_t(uint64_t(t.tv_sec)*1000+t.tv_nsec/1000000);
#else
    return uint32_t(uint64_t(xTaskGetTickCount())*1000/configTICK_RATE_HZ);
#endif
}
struct Budget {
    BackendContext &c;uint32_t start,limit;
    Budget(BackendContext &ctx,uint32_t ms=0):c(ctx),start(now_ms()),limit(ms?ms:ctx.current_remote_timeout_ms){if(!limit||limit>65535)limit=5000;}
    bool cancelled()const{return c.cancel_requested||(c.should_cancel&&c.should_cancel(c.cancel_context));}
    uint32_t remaining()const{uint32_t elapsed=now_ms()-start;return cancelled()||elapsed>=limit?0:limit-elapsed;}
};
BackendResult result(uint8_t status=0,uint8_t error=0,uint32_t length=0){BackendResult r={status,error,0,false,length,0};return r;}
void message(BackendContext &c,const char *text){unsigned n=0;while(text[n]&&n<sizeof(c.last_status)-1){c.last_status[n]=text[n];n++;}c.last_status[n]=0;}
bool finish(BackendContext &c,uint8_t protocol,uint8_t *response,uint32_t cap,BackendResult &r,const char *text,bool explicit_success=false,const char *legacy_success=0,const char *legacy_error=0){
    if(protocol!='W'&&(r.status||explicit_success))message(c,text);
    if(protocol=='W'&&(r.status||legacy_success)){
        const char *body=r.status?(legacy_error?legacy_error:text):legacy_success;
        uint32_t n=strlen(body);if(n<=cap){memcpy(response,body,n);r.length=n;}else r.length=0;
    }return true;
}
bool finish_udp(BackendContext &c,uint8_t protocol,uint8_t *response,uint32_t cap,BackendResult &r,const char *text,bool explicit_success=false){
    return finish(c,protocol,response,cap,r,text,explicit_success,explicit_success?"0":0,r.status==4?"!E":"!0");
}
bool again(){return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR;}
bool wait_read(int fd,const Budget &budget,uint32_t at_most){
    uint32_t started=now_ms();
    while(budget.remaining()&&uint32_t(now_ms()-started)<at_most){
        uint32_t ms=at_most-uint32_t(now_ms()-started);if(ms>budget.remaining())ms=budget.remaining();if(ms>50)ms=50;
        fd_set set;FD_ZERO(&set);FD_SET(fd,&set);timeval tv={0,int(ms*1000)};
        int n=NET_SELECT(fd+1,&set,0,0,&tv);if(n>0)return !budget.cancelled();if(n<0&&errno!=EINTR)return false;
    }return false;
}
void address(sockaddr_in &out,const uint8_t ip[4],uint16_t port){memset(&out,0,sizeof(out));out.sin_family=AF_INET;out.sin_port=htons(port);memcpy(&out.sin_addr,ip,4);
#ifndef P08_HTTP_HOST
    out.sin_len=sizeof(out);
#endif
}
bool host_text(const uint8_t *p,uint32_t n,char out[254]){
    if(!p||!n||n>253)return false;
    for(uint32_t i=0;i<n;i++){uint8_t c=p[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_'))return false;out[i]=char(c);}out[n]=0;return true;
}
bool same_adapter(const NetworkInfo &n){return !memcmp(datagram.mac,n.mac,6)&&!memcmp(datagram.ip,n.ip,16)&&datagram.adapter==n.adapter_handle&&datagram.wireless==n.wireless;}
void u16(uint8_t *p,uint32_t v){p[0]=uint8_t(v);p[1]=uint8_t(v>>8);}
void u32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=uint8_t(v>>(8*i));}
uint32_t read32(const uint8_t *p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
uint16_t checksum(const uint8_t *p,unsigned n){uint32_t sum=0;while(n>1){sum+=(uint16_t(p[0])<<8)|p[1];p+=2;n-=2;}if(n)sum+=uint16_t(*p)<<8;while(sum>>16)sum=(sum&0xffff)+(sum>>16);return uint16_t(~sum);}
bool ping(BackendContext &c,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out){
    char host[254];if(length<2||request[0]!=1||!host_text(request+1,length-1,host)||capacity<25){out=result(2,HTTP_ARGUMENT);return true;}
    Budget budget(c,8000);uint8_t ip[4];
    uint32_t dns_limit=budget.remaining();if(dns_limit>2000)dns_limit=2000;
    if(!resolve_backend_ipv4(c,host,ip,dns_limit)){out=result(4,budget.cancelled()?HTTP_CANCELLED:HTTP_DNS);return true;}
    int fd=NET_SOCKET(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(fd<0){out=result(4,HTTP_SOCKET);return true;}
    if(!bind_selected_socket(c,fd)||NET_FCNTL(fd,F_SETFL,O_NONBLOCK)<0){NET_CLOSE(fd);out=result(4,HTTP_SOCKET);return true;}
    memset(response,0,25);response[0]=1;memcpy(response+1,ip,4);for(unsigned i=0;i<4;i++)u16(response+7+3*i,65535);
    u16(response+19,65535);u16(response+21,65535);u16(response+23,65535);
    sockaddr_in target;address(target,ip,0);uint16_t identifier=++ping_identifier;uint32_t nonce=now_ms();uint32_t sum=0,minimum=65535,maximum=0;
    bool failed=false;
    for(unsigned i=0;i<4;i++){
        if(!budget.remaining()){failed=true;break;}
        uint8_t packet[24]={8,0,0,0,uint8_t(identifier>>8),uint8_t(identifier),0,uint8_t(i)};
        u32(packet+8,nonce);u32(packet+12,uint32_t(identifier));memcpy(packet+16,"U64PING1",8);
        uint16_t cs=checksum(packet,sizeof(packet));packet[2]=uint8_t(cs>>8);packet[3]=uint8_t(cs);
        uint32_t sent_at=now_ms();int n=NET_SENDTO(fd,packet,sizeof(packet),0,reinterpret_cast<sockaddr*>(&target),sizeof(target));
        if(n!=int(sizeof(packet))){failed=true;break;}response[5]++;
        // Each probe gets at most 1.5 seconds; DNS+four probes fit the8s session.
        while(budget.remaining()&&uint32_t(now_ms()-sent_at)<1500){
            uint32_t left=1500-uint32_t(now_ms()-sent_at);if(!wait_read(fd,budget,left))break;
            uint8_t incoming[128];sockaddr_in from;socklen_t size=sizeof(from);
            n=NET_RECVFROM(fd,incoming,sizeof(incoming),MSG_DONTWAIT,reinterpret_cast<sockaddr*>(&from),&size);
            if(n<0){if(again())continue;failed=true;break;}
            uint8_t ttl=0;if(size<sizeof(sockaddr_in)||from.sin_family!=AF_INET||memcmp(&from.sin_addr,ip,4)||!p15_ping_reply(incoming,uint32_t(n),ip,packet,ttl))continue;
            uint32_t rtt=now_ms()-sent_at;if(rtt>65534)rtt=65534;u16(response+7+3*i,rtt);response[9+3*i]=ttl;response[6]++;
            sum+=rtt;if(rtt<minimum)minimum=rtt;if(rtt>maximum)maximum=rtt;break;
        }
        if(failed)break;
    }
    NET_CLOSE(fd);
    if(budget.cancelled()){out=result(4,HTTP_CANCELLED);return true;}
    if(failed){out=result(4,budget.remaining()?HTTP_READ:HTTP_DEADLINE);return true;}
    if(response[6]){u16(response+19,minimum);u16(response+21,sum/response[6]);u16(response+23,maximum);}
    out=result(0,0,25);return true;
}
}

bool p15_ping_reply(const uint8_t *packet,uint32_t length,const uint8_t target[4],const uint8_t expected[24],uint8_t &ttl){
    if(!packet||!target||!expected||length<44||(packet[0]>>4)!=4)return false;
    unsigned ihl=(packet[0]&15)*4;unsigned total=(unsigned(packet[2])<<8)|packet[3];
    if(ihl<20||ihl>60||total!=ihl+24||length<total||packet[9]!=IPPROTO_ICMP||memcmp(packet+12,target,4)||((packet[6]&0x3f)||packet[7]))return false;
    const uint8_t *icmp=packet+ihl;
    if(icmp[0]||icmp[1]||checksum(icmp,24)||memcmp(icmp+4,expected+4,20))return false;
    ttl=packet[8];return true;
}

void p15_network_reset(){if(datagram.fd>=0)NET_CLOSE(datagram.fd);datagram.fd=-1;memset(datagram.mac,0,6);memset(datagram.ip,0,16);datagram.adapter=0;datagram.wireless=false;}

bool p15_execute_network(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out){
    if(command==0x0a||command==0x1e)command=0x35;
    if(command==0x0b||command==0x1f)command=0x34;
    if(command==0x0e)command=0x33;
    if(command!=0x33&&command!=0x34&&command!=0x35&&command!=0x3e&&command!=0x3f)return false;
    out=result(2,HTTP_ARGUMENT);
    if(!response||!capacity||length>MAX_REQUEST||(length&&!request))return true;
    if(protocol!='R'&&protocol!='W')return finish(c,protocol,response,capacity,out,"Command requires W or R protocol");
    if(!c.network.connected||!c.network.mac_valid){p15_network_reset();out=result(3,HTTP_CONNECT);return finish(c,protocol,response,capacity,out,"Network not connected",false,0,command<0x36?"!0":0);}
    if(datagram.fd>=0&&!same_adapter(c.network))p15_network_reset();
    if(command==0x3e){ping(c,request,length,response,capacity,out);return finish(c,protocol,response,capacity,out,out.status?"ICMP probe failed":"Success");}
    if(command==0x3f){
        if(length<7||request[0]!=1||request[1]<3||request[1]>20||length-6>512||capacity<28)return finish(c,protocol,response,capacity,out,"Invalid speedtest request");
        uint32_t target=read32(request+2);if(target<262144||target>16777216)return finish(c,protocol,response,capacity,out,"Invalid speedtest target");
        SpeedtestResult measured={};out=http_speedtest(c,request+6,length-6,request[1],target,measured);
        if(out.status)return finish(c,protocol,response,capacity,out,"Speedtest failed");
        memset(response,0,28);response[0]=1;response[1]=measured.flags;
        uint32_t elapsed=measured.elapsed_ms?measured.elapsed_ms:1;
        uint64_t bits=uint64_t(measured.received_bytes)*8000/elapsed;
        uint32_t bps=bits>0xffffffffULL?0xffffffffU:uint32_t(bits);
        uint64_t display=(uint64_t(bps)+5000)/10000; // Rounded Mbit/s in hundredths.
        if(display>65535){display=65535;response[1]|=32;}
        uint64_t received_kib=(uint64_t(measured.received_bytes)+512)/1024;
        if(received_kib>65535)received_kib=65535;
        u32(response+2,measured.received_bytes);u32(response+6,measured.elapsed_ms);u32(response+10,bps);u32(response+14,measured.setup_ms);u32(response+18,measured.content_length);u16(response+22,measured.http_status);u16(response+24,uint32_t(display));u16(response+26,uint32_t(received_kib));
        out.length=28;return finish(c,protocol,response,capacity,out,"Success");
    }
    if(command==0x33){
        if(!length)return finish_udp(c,protocol,response,capacity,out,"UDP port requires at least one byte");
        uint16_t port=uint16_t(request[0])|(length>=2?uint16_t(request[1])<<8:0);
        if(!port)return finish_udp(c,protocol,response,capacity,out,"UDP port must be nonzero");
        p15_network_reset();int fd=NET_SOCKET(AF_INET,SOCK_DGRAM,0);
        if(fd<0||!bind_selected_socket_port(c,fd,port)||NET_FCNTL(fd,F_SETFL,O_NONBLOCK)<0){if(fd>=0)NET_CLOSE(fd);out=result(4,HTTP_SOCKET);return finish_udp(c,protocol,response,capacity,out,"UDP bind failed");}
        datagram.fd=fd;memcpy(datagram.mac,c.network.mac,6);memcpy(datagram.ip,c.network.ip,16);datagram.adapter=c.network.adapter_handle;datagram.wireless=c.network.wireless;out=result();return finish_udp(c,protocol,response,capacity,out,"Success",true);
    }
    if(datagram.fd<0){out=result(2,HTTP_ARGUMENT);return finish_udp(c,protocol,response,capacity,out,"UDP port not configured");}
    Budget budget(c);
    if(command==0x34){
        if(length<4)return finish_udp(c,protocol,response,capacity,out,"Invalid UDP packet");
        uint32_t n=request[0];char host[254];if(n+3>length||!host_text(request+1,n,host)||length-n-3>1460)return finish_udp(c,protocol,response,capacity,out,"Invalid UDP packet");
        uint16_t port=uint16_t(request[n+1])|(uint16_t(request[n+2])<<8);if(!port)return finish_udp(c,protocol,response,capacity,out,"UDP port must be nonzero");
        uint8_t ip[4];if(!resolve_backend_ipv4(c,host,ip,budget.remaining())){out=result(4,budget.cancelled()?HTTP_CANCELLED:HTTP_DNS);return finish_udp(c,protocol,response,capacity,out,"UDP DNS failed");}
        sockaddr_in target;address(target,ip,port);uint32_t payload=length-n-3;
        int sent=budget.remaining()?NET_SENDTO(datagram.fd,request+n+3,payload,0,reinterpret_cast<sockaddr*>(&target),sizeof(target)):-1;
        out=sent==int(payload)?result():result(4,budget.cancelled()?HTTP_CANCELLED:HTTP_WRITE);return finish_udp(c,protocol,response,capacity,out,out.status?"UDP send failed":"Success",!out.status);
    }
    uint32_t timeout=length>=2?uint32_t(request[0])|(uint32_t(request[1])<<8):0;
    Budget receive_budget(c,timeout?timeout:1);
    if(receive_budget.cancelled()){out=result(4,HTTP_CANCELLED);return finish_udp(c,protocol,response,capacity,out,"Cancelled");}
    uint8_t packet[1461];sockaddr_in from;memset(&from,0,sizeof(from));socklen_t size=sizeof(from);
    int n=-1;unsigned dropped=0;
    for(;;){
        size=sizeof(from);n=NET_RECVFROM(datagram.fd,packet,sizeof(packet),MSG_DONTWAIT,reinterpret_cast<sockaddr*>(&from),&size);
        // Port64's receive worker drops oversized datagrams without exposing
        // a truncated packet or turning a subsequent GET into an error.
        // Bound the drain so a continuous flood cannot monopolize the worker.
        if(n>1460){
            if(++dropped<32&&receive_budget.remaining())continue;
            n=-1;errno=EAGAIN;break;
        }
        if(n>=0||!again()||!timeout||!receive_budget.remaining())break;
        if(!wait_read(datagram.fd,receive_budget,receive_budget.remaining()))break;
    }
    if(receive_budget.cancelled()){out=result(4,HTTP_CANCELLED);return finish_udp(c,protocol,response,capacity,out,"Cancelled");}
    if(n<0){if(again()){out=result();return finish_udp(c,protocol,response,capacity,out,"Success");}out=result(4,HTTP_READ);return finish_udp(c,protocol,response,capacity,out,"UDP receive failed");}
    if(size<sizeof(sockaddr_in)||from.sin_family!=AF_INET||n>1460||uint32_t(n)+6>capacity){out=result(4,HTTP_LENGTH);return finish_udp(c,protocol,response,capacity,out,"UDP packet too large");}
    memcpy(response,&from.sin_addr,4);u16(response+4,ntohs(from.sin_port));if(n)memcpy(response+6,packet,n);out=result(0,0,uint32_t(n)+6);return finish_udp(c,protocol,response,capacity,out,"Success");
}
}
