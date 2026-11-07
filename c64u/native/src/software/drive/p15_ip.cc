#include "p15_ip.h"
#include <string.h>
#if !defined(P08_HTTP_HOST)
#include "FreeRTOS.h"
#include "task.h"
#include "network_interface.h"
#include "p08_service.h"
#include "c64.h"
#include "c64_subsys.h"
#endif
namespace p08 {
namespace {
#if !defined(P08_HTTP_HOST)
struct Guard {Guard(){taskENTER_CRITICAL();}~Guard(){taskEXIT_CRITICAL();}};
#else
struct Guard {Guard(){}~Guard(){}};
#endif
struct Deferred {
    P15IpOps ops;bool installed;uint8_t session[8];uint32_t request,generation;
    NetworkInfo target;uint8_t preference;P15IpSettings desired;P15IpSnapshot expected;
    P15IpStatus status;
} deferred={};
void text(BackendContext &c,const char *s){unsigned n=0;while(s[n]&&n<39){c.last_status[n]=s[n];n++;}c.last_status[n]=0;}
bool equal(const uint8_t *s){return s&&!memcmp(s,deferred.session,8);}
bool nonzero(const uint8_t *s){uint8_t v=0;if(s)for(unsigned i=0;i<8;i++)v|=s[i];return v!=0;}
bool mac_valid(const NetworkInfo &n){uint8_t any=0;for(unsigned i=0;i<6;i++)any|=n.mac[i];return n.mac_valid&&any&&!(n.mac[0]&1);}
unsigned bounded(const char *s){unsigned n=0;while(n<16&&s[n])n++;return n;}
void format(const uint8_t ip[4],char out[16]){
    unsigned n=0;for(unsigned i=0;i<4;i++){unsigned v=ip[i];if(v>=100)out[n++]='0'+v/100;if(v>=10)out[n++]='0'+(v/10)%10;out[n++]='0'+v%10;if(i<3)out[n++]='.';}out[n]=0;
}
bool parse(const uint8_t *s,unsigned length,char out[16]){
    uint8_t ip[4]={};unsigned at=0;
    for(unsigned field=0;field<4;field++){
        unsigned value=0,digits=0;
        while(at<length&&s[at]>='0'&&s[at]<='9'){
            if(++digits>3)return false;value=value*10+s[at++]-'0';if(value>255)return false;
        }
        if(!digits)return false;ip[field]=value;
        if(field<3){if(at>=length||s[at++]!='.')return false;}
    }
    if(at!=length)return false;format(ip,out);return true;
}
bool parse_static(const uint8_t *s,uint32_t length,P15IpSettings &out){
    memset(&out,0,sizeof(out));strcpy(out.address[4],"0.0.0.0");
    if(!s||!length||length>81)return false;if(s[length-1]==0)length--;
    unsigned begin=0,field=0;
    for(unsigned at=0;at<=length;at++){
        if(at<length&&s[at]!=1){if(!s[at])return false;continue;}
        if(field>=5)return false;unsigned n=at-begin;
        if(field==4&&!n)strcpy(out.address[field],"0.0.0.0");
        else if(!n||n>15||!parse(s+begin,n,out.address[field]))return false;
        field++;begin=at+1;
    }
    return field==4||field==5;
}
bool snapshot_valid(const P15IpSnapshot &s){
    for(unsigned i=0;i<5;i++){unsigned n=bounded(s.active[i]);char work[16];if(!n||n==16||!parse(reinterpret_cast<const uint8_t *>(s.active[i]),n,work)||strcmp(work,s.active[i]))return false;
        if(bounded(s.configured[i])==16)return false;}
    return true;
}
#if !defined(P08_HTTP_HOST)
TaskHandle_t worker=0;
NetworkInterface *find_native(const NetworkInfo &target){
    for(int i=0;i<NetworkInterface::getNumberOfInterfaces();i++){
        NetworkInterface *n=NetworkInterface::getInterface(i);if(n!=target.adapter_handle||!n)continue;
        uint8_t mac[6]={};LOCK_TCPIP_CORE();n->getMacAddr(mac);bool wireless=n->is_wireless();UNLOCK_TCPIP_CORE();
        return wireless==target.wireless&&!memcmp(mac,target.mac,6)?n:0;
    }return 0;
}
bool native_snapshot(void *,const NetworkInfo &target,P15IpSnapshot &out){
    NetworkInterface *n=find_native(target);if(!n)return false;uint8_t ip[20]={};memset(&out,0,sizeof(out));
    if(!n->p15_snapshot_ip(out.dhcp,ip,out.configured))return false;
    for(unsigned i=0;i<5;i++)format(ip+4*i,out.active[i]);return true;
}
bool native_selected(void *,const NetworkInfo &target,uint8_t preference){
    if(!find_native(target)||preference>NETWORK_WLAN)return false;
    if(preference==NETWORK_LAN&&target.wireless)return false;
    if(preference==NETWORK_WLAN&&!target.wireless)return false;
    if(preference!=NETWORK_AUTO)return true;
    bool target_up=false,other_online=false,wired_online=false;
    LOCK_TCPIP_CORE();
    for(int i=0;i<NetworkInterface::getNumberOfInterfaces();i++){
        NetworkInterface *n=NetworkInterface::getInterface(i);if(!n)continue;uint8_t ip[12]={},mac[6]={};n->getIpAddr(ip);n->getMacAddr(mac);
        NetworkInfo candidate={};candidate.mac_valid=true;memcpy(candidate.mac,mac,6);
        bool online=n->is_link_up()&&(ip[0]||ip[1]||ip[2]||ip[3])&&mac_valid(candidate);
        if(n==target.adapter_handle)target_up=online;else other_online|=online;
        wired_online|=online&&!n->is_wireless();
    }
    UNLOCK_TCPIP_CORE();
    return target_up?(!target.wireless||!wired_online):!other_online;
}
bool native_apply(void *,const NetworkInfo &target,const P15IpSettings &desired,const P15IpSnapshot &expected){
    if(!c64_subsys||!c64_subsys->p08_try_lock())return false;
    bool ok=false;
    if(!native_menu_held()){
        NetworkInterface *n=find_native(target);
        if(n)ok=n->p15_apply_ip(desired.dhcp,desired.address,expected.configured,expected.dhcp);
    }
    c64_subsys->unlock();return ok;
}
void run(void *){for(;;){p15_ip_tick();vTaskDelay(pdMS_TO_TICKS(10)?pdMS_TO_TICKS(10):1);}}
void install(){if(deferred.installed)return;P15IpOps ops={0,native_snapshot,native_selected,native_apply};deferred.ops=ops;
    if(!worker&&xTaskCreate(run,"WiC64 IP",2048,0,PRIO_POLL,&worker)!=pdPASS){worker=0;return;}deferred.installed=true;}
#else
void install(){}
#endif
bool answer(BackendContext &c,uint8_t protocol,uint8_t *out,uint32_t capacity,BackendResult &r,uint8_t status,uint8_t error,const char *message){
    r={status,error,0,false,0,0};if(protocol!='W'&&status)text(c,message);
    if(protocol=='W'&&status){unsigned n=strlen(message);if(n<=capacity){memcpy(out,message,n);r.length=n;}else r.error=HTTP_LENGTH;}
    return true;
}
}
void p15_ip_set_ops(const P15IpOps &ops){Guard g;deferred.ops=ops;deferred.installed=true;}
void p15_ip_reset(const uint8_t session[8]){install();Guard g;deferred.generation++;memcpy(deferred.session,session,8);deferred.request=0;
    if(deferred.status.state==1||deferred.status.state==2){deferred.status.state=6;deferred.status.persisted=deferred.status.applied=false;}
    else if(deferred.status.state!=3)deferred.status={0,0,false,false};}
void p15_ip_request_context(const uint8_t session[8],uint32_t request){Guard g;
    if(deferred.status.state==1&&(!equal(session)||request!=deferred.status.request))deferred.status.state=6;
    deferred.request=equal(session)?request:0;
}
void p15_ip_response_consumed(const uint8_t session[8],uint32_t request){Guard g;if(deferred.status.state==1&&equal(session)&&request==deferred.status.request)deferred.status.state=2;}
void p15_ip_status(P15IpStatus &out){Guard g;out=deferred.status;}
void p15_ip_tick(){
    Deferred job;
    {Guard g;if(deferred.status.state!=2)return;job=deferred;}
    bool selected=job.ops.selected&&job.ops.selected(job.ops.context,job.target,job.preference);
    {Guard g;if(job.generation!=deferred.generation||deferred.status.state!=2||job.status.request!=deferred.status.request)return;
        if(!selected){deferred.status.state=5;return;}
        // The ACK-authorized persistent commit starts here. A reset before
        // this gate cancels it; once entered, finish the bounded persistence
        // transaction so that applied state agrees with verified flash.
        deferred.status.state=3;
    }
    bool ok=job.ops.apply&&job.ops.apply(job.ops.context,job.target,job.desired,job.expected);
    Guard g;
    // A reset during an entered commit does not make the physical write
    // reversible. Retain its real outcome instead of falsely reporting cancel.
    if(deferred.status.state==3){deferred.status.state=ok?4:5;deferred.status.persisted=deferred.status.applied=ok;}
}
bool p15_execute_ip(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out){
    if(command<0x3a||command>0x3c)return false;install();
    if(!response||!capacity||length>MAX_REQUEST||(length&&!request))return answer(c,protocol,response,0,out,2,HTTP_ARGUMENT,"Invalid IP command buffers");
    if(protocol!='R'&&protocol!='W')return answer(c,protocol,response,capacity,out,2,HTTP_UNSUPPORTED,"IP command requires W or R");
    if((command==0x3a||command==0x3b)&&length)return answer(c,protocol,response,capacity,out,2,HTTP_ARGUMENT,"IP command expects no payload");
    P15IpSettings desired={};if(command==0x3c&&!parse_static(request,length,desired))return answer(c,protocol,response,capacity,out,2,HTTP_ARGUMENT,"Invalid static IPv4 fields");
    if(!mac_valid(c.network))return answer(c,protocol,response,capacity,out,1,HTTP_UNSUPPORTED,"Selected network adapter unavailable");
    P15IpOps ops;{Guard g;ops=deferred.ops;}
    P15IpSnapshot snapshot={};
    if(!deferred.installed||!ops.snapshot||!ops.snapshot(ops.context,c.network,snapshot)||!snapshot_valid(snapshot))return answer(c,protocol,response,capacity,out,1,HTTP_UNSUPPORTED,"Native IP settings unavailable");
    if(command==0x3a){
        unsigned n=snapshot.dhcp?5:7;for(unsigned i=0;i<5;i++)n+=strlen(snapshot.active[i])+1;n++;
        if(n>capacity)return answer(c,protocol,response,capacity,out,1,HTTP_LENGTH,"IP response buffer too small");
        unsigned used=0;const char *mode=snapshot.dhcp?"DHCP":"STATIC";unsigned size=strlen(mode)+1;memcpy(response,mode,size);used+=size;
        for(unsigned i=0;i<5;i++){size=strlen(snapshot.active[i])+1;memcpy(response+used,snapshot.active[i],size);used+=size;}
        response[used++]=0xff;out={0,0,0,false,used,0};return true;
    }
    if(command==0x3b){desired.dhcp=true;memcpy(desired.address,snapshot.configured,sizeof(desired.address));}
    Guard g;
    if(!nonzero(deferred.session)||!deferred.request)return answer(c,protocol,response,capacity,out,2,HTTP_ARGUMENT,"IP request not session bound");
    if(deferred.status.state==1||deferred.status.state==2||deferred.status.state==3)return answer(c,protocol,response,capacity,out,4,HTTP_READ,"IP configuration job busy");
    if(!ops.apply||!ops.selected)return answer(c,protocol,response,capacity,out,1,HTTP_UNSUPPORTED,"Native IP writer unavailable");
    deferred.target=c.network;deferred.preference=c.preference;deferred.desired=desired;deferred.expected=snapshot;
    deferred.status={1,deferred.request,false,false};
    return answer(c,protocol,response,capacity,out,0,0,"IP configuration queued");
}
}
