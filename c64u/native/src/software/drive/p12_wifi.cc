#include "p12_wifi.h"
#include <string.h>
#if !defined(P08_HTTP_HOST)
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "wifi.h"
#include "network_interface.h"
#if C64U_ESP_WIFI_CONFIG
#include "p21_preferences.h"
#include "p21_store_wire.h"
#endif
#endif
namespace p08 {
namespace {
void wipe(void *p,unsigned n){volatile uint8_t *q=static_cast<volatile uint8_t *>(p);while(n--)*q++=0;}
enum Job { NONE, SCAN_QUEUED, SCAN_RPC, CONNECT_STAGED, CONNECT_QUEUED, CONNECT_RPC, CONNECT_WAIT, SIGNAL_QUEUED, SIGNAL_RPC, FORGET_STAGED, FORGET_QUEUED, FORGET_RPC };
struct Bridge {
    WifiNativeOps ops; bool installed; uint8_t session[8]; uint32_t generation,request;
    Job job; uint16_t ticket,next_ticket; uint32_t deadline,job_deadline,association_before;
    WifiAP cache[10]; uint8_t cache_count; bool cache_valid;
    uint8_t ssid[32],ssid_length,password[64],password_length,candidate_password_length,auth;
    bool configured_known,passphrase_known; uint32_t known_association;
    uint8_t configured_ssid[32],configured_length,stored_password_length;
    uint8_t state; bool scan_finished,connection_intent; uint8_t scan_status; char error[40];
    uint8_t signal_ssid[32],signal_length,signal_status; int8_t signal_rssi;
    uint32_t signal_association,signal_time; bool signal_valid,signal_finished;
    uint8_t forget_state; uint32_t forget_association;
} bridge={};
#if !defined(P08_HTTP_HOST)
struct Guard {Guard(){taskENTER_CRITICAL();}~Guard(){taskEXIT_CRITICAL();}};
#else
struct Guard {Guard(){}~Guard(){}};
#endif
void error(const char *s){unsigned n=0;while(s[n]&&n<39){bridge.error[n]=s[n];n++;}bridge.error[n]=0;}
bool same_session(const uint8_t *s){return s&&!memcmp(s,bridge.session,8);}
bool nonzero(const uint8_t *s){uint8_t v=0;if(s)for(unsigned i=0;i<8;i++)v|=s[i];return v!=0;}
bool expired(uint32_t now,uint32_t deadline){return int32_t(now-deadline)>=0;}
uint32_t now(){return bridge.ops.milliseconds?bridge.ops.milliseconds(bridge.ops.context):0;}
bool native_snapshot(WifiNativeSnapshot &s){memset(&s,0,sizeof(s));return bridge.installed&&bridge.ops.snapshot&&bridge.ops.snapshot(bridge.ops.context,s);}
bool configuration_ready(){
#if C64U_ESP_WIFI_CONFIG
    return bridge.installed&&bridge.ops.configuration_ready&&bridge.ops.configuration_ready(bridge.ops.context);
#else
    return true;
#endif
}
void finish(uint8_t state,const char *message){bridge.state=state;bridge.job=NONE;wipe(bridge.password,sizeof(bridge.password));bridge.password_length=0;error(message);}
bool next_ticket(uint16_t &t){if(bridge.next_ticket==0xffff){error("WiFi RPC sequence exhausted");return false;}t=++bridge.next_ticket;return true;}

#if !defined(P08_HTTP_HOST)
QueueHandle_t replies=0;
TaskHandle_t worker=0;
volatile uint16_t expected_sequence=0;
volatile uint8_t expected_command=0;
volatile uint32_t association_generation=0;
bool native_ready(void*,WifiNativeSnapshot &out){
    memset(&out,0,sizeof(out));WifiState_t state=wifi.getState();
    out.available=state!=eWifi_Off&&state!=eWifi_Disabled&&state!=eWifi_NotDetected&&state!=eWifi_Download;
    out.linked=state==eWifi_Connected;out.association_generation=association_generation;
    const char *ssid=wifi.getLastAP();
    if(out.linked&&ssid){while(out.ssid_length<32&&ssid[out.ssid_length]){out.ssid[out.ssid_length]=uint8_t(ssid[out.ssid_length]);out.ssid_length++;}}
    strcpy(out.ip,"0.0.0.0");
    for(int n=0;n<NetworkInterface::getNumberOfInterfaces();n++){
        NetworkInterface *iface=NetworkInterface::getInterface(n);if(!iface||!iface->is_wireless())continue;
        uint8_t ip[12]={};iface->getIpAddr(ip);out.ip_ready=out.linked&&iface->is_link_up()&&(ip[0]||ip[1]||ip[2]||ip[3]);
        if(out.ip_ready){iface->getIpAddrString(out.ip,sizeof(out.ip));break;}
    }return true;
}
uint32_t native_ms(void*){return uint32_t(uint64_t(xTaskGetTickCount())*1000/configTICK_RATE_HZ);}
void native_delay(void*,uint32_t ms){TickType_t ticks=pdMS_TO_TICKS(ms);vTaskDelay(ticks?ticks:1);}
void native_cancel(void*){
    {Guard g;expected_sequence=0;expected_command=0;}
    command_buf_t *reply=0;while(replies&&xQueueReceive(replies,&reply,0)==pdTRUE){wipe(reply->data,sizeof(reply->data));esp32.uart->FreeBuffer(reply);}
}
bool submit(uint16_t ticket,uint8_t command,const uint8_t *ssid,uint8_t sl,const uint8_t *password,uint8_t pl,uint8_t auth){
#if P05_RAM_DIAGNOSTIC && !C64U_ESP_WIFI_CONFIG
    // WiC64 Alpha may query the existing Stock connection and scan. These
    // controller commands persist AP credentials in ESP NVS, so reject them
    // before allocating or transmitting any RPC buffer.
    if(command==CMD_WIFI_CONNECT||command==CMD_CLEAR_APS)return false;
#endif
    if((command==CMD_WIFI_CONNECT||command==CMD_CLEAR_APS)&&!configuration_ready())return false;
    if(!esp32.uart||!replies)return false;
    command_buf_t *buffer=0;if(esp32.uart->GetBuffer(&buffer,0)!=pdTRUE)return false;
    memset(buffer->data,0,command==CMD_WIFI_CONNECT?sizeof(rpc_wifi_connect_req):sizeof(rpc_identify_req));
    rpc_header_t *h=reinterpret_cast<rpc_header_t *>(buffer->data);h->command=command;h->thread=0xfe;h->sequence=ticket;
    buffer->size=sizeof(rpc_identify_req);
    if(command==CMD_WIFI_CONNECT){rpc_wifi_connect_req *p=reinterpret_cast<rpc_wifi_connect_req *>(buffer->data);p->auth_mode=auth;memcpy(p->ssid,ssid,sl);memcpy(p->password,password,pl);buffer->size=sizeof(*p);}
    {Guard g;
        // A reset or replacement can invalidate a queued job while a buffer
        // is being prepared. The nonblocking enqueue is its commit point.
        if(ticket!=bridge.ticket||(bridge.job!=SCAN_QUEUED&&bridge.job!=SIGNAL_QUEUED&&bridge.job!=CONNECT_QUEUED&&bridge.job!=FORGET_QUEUED)){
            wipe(buffer->data,buffer->size);esp32.uart->FreeBuffer(buffer);return false;
        }
        expected_sequence=ticket;expected_command=command;
        if(esp32.uart->TransmitPacketNonBlocking(buffer)!=pdTRUE){expected_sequence=0;expected_command=0;return false;}
    }
    return true;
}
bool native_scan(void*,uint16_t t){return submit(t,CMD_WIFI_SCAN,0,0,0,0,0);}
bool native_forget(void*,uint16_t t){return submit(t,CMD_CLEAR_APS,0,0,0,0,0);}
bool native_configuration_ready(void*){
#if C64U_ESP_WIFI_CONFIG
    return p21prefs::wifi_config_ready();
#else
    return true;
#endif
}
// Kept separately named so the final ELF can audit the intentional WiFi
// configuration RPC independently from firmware/OTA/flash writer paths.
bool p12_wifi_native_submit_connect(void*,uint16_t t,const uint8_t *s,uint8_t sl,const uint8_t *p,uint8_t pl,uint8_t auth){return submit(t,CMD_WIFI_CONNECT,s,sl,p,pl,auth);}
int native_poll(void*,uint16_t ticket,WifiAP *aps,uint8_t &count){
    command_buf_t *buffer=0;if(!replies||xQueueReceive(replies,&buffer,0)!=pdTRUE)return 0;
    rpc_header_t *header=reinterpret_cast<rpc_header_t *>(buffer->data);int outcome=-1;
    if(buffer->size>=sizeof(rpc_espcmd_resp)&&header->sequence==ticket){
        rpc_espcmd_resp *r=reinterpret_cast<rpc_espcmd_resp *>(buffer->data);
#if C64U_ESP_WIFI_CONFIG
        if(header->command==CMD_WIFI_CONNECT&&r->esp_err==P21_WIFI_SAVE_FAILED)outcome=-2;
#endif
        if(r->esp_err==0){outcome=1;
            if(header->command==CMD_WIFI_SCAN){
                const unsigned start=sizeof(rpc_header_t)+sizeof(int)+2;
                if(buffer->size<start){outcome=-1;}
                else {rpc_scan_resp *scan=reinterpret_cast<rpc_scan_resp *>(buffer->data);unsigned available=(buffer->size-start)/sizeof(ultimate_ap_record_t);
                    if(scan->rec.num_records>24||scan->rec.num_records>available)outcome=-1;
                    else {
                        uint8_t target[32]={},target_length=0;bool signal=false;
                        {Guard g;signal=bridge.job==SIGNAL_RPC;target_length=bridge.signal_length;memcpy(target,bridge.signal_ssid,32);}
                        count=0;
                        for(unsigned i=0;i<scan->rec.num_records;i++){
                            unsigned length=0;while(length<32&&scan->rec.aps[i].ssid[length])length++;
                            // A signal query searches all returned APs (up to24),
                            // including those beyond the public ten-entry list.
                            // Keep two matches so a shared SSID is ambiguous.
                            if(signal&&(length!=target_length||memcmp(scan->rec.aps[i].ssid,target,length)))continue;
                            if(count>=(signal?2:10))continue;
                            WifiAP &ap=aps[count++];memset(&ap,0,sizeof(ap));ap.length=length;
                            memcpy(ap.ssid,scan->rec.aps[i].ssid,length);ap.auth=scan->rec.aps[i].authmode;ap.rssi=scan->rec.aps[i].rssi;
                        }
                    }
                }
            }
        }
    }
    wipe(buffer->data,sizeof(buffer->data));esp32.uart->FreeBuffer(buffer);return outcome;
}
void worker_main(void*){for(;;){p12_wifi_tick();native_delay(0,10);}}
void install_native(){
    if(bridge.installed)return;
    if(!replies)replies=xQueueCreate(2,sizeof(command_buf_t *));
    WifiNativeOps ops={0,native_ms,native_delay,native_ready,native_scan,p12_wifi_native_submit_connect,native_poll,native_cancel,native_forget,native_configuration_ready};
    bridge.ops=ops;bridge.installed=replies!=0;
    if(bridge.installed&&!worker&&xTaskCreate(worker_main,"WiC64 WiFi",3072,0,PRIO_POLL,&worker)!=pdPASS){bridge.installed=false;worker=0;}
}
#else
void install_native(){}
#endif
}

void p12_wifi_set_ops(const WifiNativeOps &ops){Guard g;bridge.ops=ops;bridge.installed=true;}
void p12_wifi_reset(const uint8_t session[8]){
    install_native();if(bridge.ops.cancel)bridge.ops.cancel(bridge.ops.context);
    Guard g;bridge.generation++;memcpy(bridge.session,session,8);bridge.job=NONE;bridge.request=0;
    bridge.cache_count=0;bridge.cache_valid=false;bridge.scan_finished=false;
    bridge.connection_intent=false;bridge.signal_valid=false;bridge.signal_finished=false;
    if(bridge.forget_state==1)bridge.forget_state=3;
    wipe(bridge.password,sizeof(bridge.password));bridge.password_length=0;
    // Known nonsecret configuration metadata survives a service restart in
    // the same management firmware; a cold boot cannot invent NVS contents.
    bridge.state=0;error("");
}
void p12_wifi_tick(){
    WifiNativeOps ops;Job job;uint32_t generation,deadline;uint16_t ticket;
    uint8_t ssid[32],password[64],sl=0,pl=0,auth=0;
    {Guard g;ops=bridge.ops;job=bridge.job;generation=bridge.generation;deadline=bridge.deadline;ticket=bridge.ticket;
        if(job==CONNECT_QUEUED){memcpy(ssid,bridge.ssid,sizeof(ssid));memcpy(password,bridge.password,sizeof(password));sl=bridge.ssid_length;pl=bridge.password_length;auth=bridge.auth;}}
    if(!bridge.installed||job==NONE||job==CONNECT_STAGED||job==FORGET_STAGED)return;
    if(job==SCAN_QUEUED||job==SIGNAL_QUEUED||job==CONNECT_QUEUED||job==FORGET_QUEUED){
        if((job==CONNECT_QUEUED||job==FORGET_QUEUED)&&!configuration_ready()){
            wipe(password,sizeof(password));
            Guard g;if(generation!=bridge.generation||bridge.job!=job)return;
            if(job==FORGET_QUEUED)bridge.forget_state=3;
            finish(8,"ESP WiFi setup requires app update");return;
        }
        // No mutation may start after its consumed-response deadline. A busy
        // scheduler must not turn a timed-out request into a later write.
        if(expired(now(),deadline)){
            wipe(password,sizeof(password));
            Guard g;if(generation!=bridge.generation||bridge.job!=job)return;
            if(job==SCAN_QUEUED){bridge.scan_finished=true;bridge.scan_status=4;}
            if(job==SIGNAL_QUEUED){bridge.signal_finished=true;bridge.signal_status=4;}
            if(job==FORGET_QUEUED)bridge.forget_state=3;
            finish((job==SCAN_QUEUED||job==SIGNAL_QUEUED)?bridge.state:8,"WiFi RPC deadline");return;
        }
        WifiNativeSnapshot snap={};native_snapshot(snap);
        {Guard g;if(generation!=bridge.generation||bridge.job!=job){wipe(password,sizeof(password));return;}}
        bool sent=(job==SCAN_QUEUED||job==SIGNAL_QUEUED)?ops.scan&&ops.scan(ops.context,ticket):
            job==FORGET_QUEUED?ops.forget&&ops.forget(ops.context,ticket):ops.connect&&(ops.connect)(ops.context,ticket,ssid,sl,password,pl,auth);
        wipe(password,sizeof(password));
        Guard g;if(generation!=bridge.generation||bridge.job!=job){if(sent&&ops.cancel)ops.cancel(ops.context);return;}
        if(!sent){
            if(job==SCAN_QUEUED){bridge.scan_finished=true;bridge.scan_status=1;}
            if(job==SIGNAL_QUEUED){bridge.signal_finished=true;bridge.signal_status=1;}
            if(job==FORGET_QUEUED)bridge.forget_state=3;
            finish((job==SCAN_QUEUED||job==SIGNAL_QUEUED)?bridge.state:8,"WiFi RPC unavailable");return;
        }
        if(job==CONNECT_QUEUED){
            // The owned UART buffer now carries the sole transient copy.
            wipe(bridge.password,sizeof(bridge.password));bridge.password_length=0;
        }
        if(job==FORGET_QUEUED){
            // CLEAR_APS may erase credentials before a disconnect error is
            // returned. Invalidate our metadata after enqueue, not just onOK.
            bridge.configured_known=false;bridge.passphrase_known=false;
            bridge.configured_length=bridge.stored_password_length=0;bridge.signal_valid=false;
            wipe(bridge.configured_ssid,sizeof(bridge.configured_ssid));
        }
        bridge.association_before=snap.association_generation;
        bridge.job=job==SCAN_QUEUED?SCAN_RPC:job==SIGNAL_QUEUED?SIGNAL_RPC:job==FORGET_QUEUED?FORGET_RPC:CONNECT_RPC;return;
    }
    if(job==SCAN_RPC||job==SIGNAL_RPC||job==CONNECT_RPC||job==FORGET_RPC){
        WifiAP result[10]={};uint8_t count=0;
        // A final reply arriving after the advertised budget is uncertain,
        // even when the controller may already have completed its write.
        int polled=expired(now(),deadline)?0:ops.poll?ops.poll(ops.context,ticket,result,count):-1;
        if(!polled&&!expired(now(),deadline))return;
        if(!polled&&ops.cancel)ops.cancel(ops.context);
        WifiNativeSnapshot snap={};if(job==SIGNAL_RPC)native_snapshot(snap);
        Guard g;if(generation!=bridge.generation||bridge.job!=job)return;
        if(job==FORGET_RPC){bridge.forget_state=polled>0?2:3;
            bridge.configured_known=polled>0;bridge.forget_association=bridge.association_before;
            finish(polled>0?0:8,polled>0?"WiFi settings cleared":"WiFi clear failed or timed out");return;}
        if(job==SIGNAL_RPC){
            unsigned matches=0;int8_t sample=0;bool valid=count<=10;
            for(unsigned i=0;i<count&&i<10;i++){
                valid=valid&&result[i].length<=32;
                if(result[i].length==bridge.signal_length&&!memcmp(result[i].ssid,bridge.signal_ssid,bridge.signal_length)){
                    matches++;sample=result[i].rssi;
                }
            }
            bool linked=snap.available&&snap.linked&&snap.association_generation==bridge.signal_association&&
                snap.ssid_length==bridge.signal_length&&!memcmp(snap.ssid,bridge.signal_ssid,bridge.signal_length);
            bridge.signal_valid=polled>0&&valid&&linked&&matches==1&&sample<0&&sample>=-127;
            bridge.signal_status=bridge.signal_valid?0:polled<=0?4:!linked?3:1;
            bridge.signal_finished=true;if(bridge.signal_valid){bridge.signal_rssi=sample;bridge.signal_time=now();}
            finish(bridge.state,bridge.signal_valid?"Success":matches>1?"WiFi SSID signal ambiguous":"WiFi signal sample unavailable");return;
        }
        if(job==SCAN_RPC){bool valid=count<=10;for(unsigned i=0;i<count&&i<10;i++)valid=valid&&result[i].length<=32;
            bridge.scan_finished=true;bridge.scan_status=polled>0&&valid?(count?0:4):4;
            if(polled>0&&valid){memcpy(bridge.cache,result,sizeof(result));bridge.cache_count=count;bridge.cache_valid=true;}
            finish(bridge.state,polled>0?(count?"Success":"No networks found"):"WiFi scan failed or timed out");return;}
        if(polled<=0){finish(8,polled==-2?"WiFi connected; AP settings not saved":"WiFi connect RPC failed");return;}
        bridge.job=CONNECT_WAIT;bridge.state=1;
        bridge.deadline=C64U_ESP_WIFI_CONFIG?bridge.job_deadline:now()+30000;
        wipe(bridge.password,sizeof(bridge.password));bridge.password_length=0;return;
    }
    if(job==CONNECT_WAIT){
        WifiNativeSnapshot snap={};native_snapshot(snap);Guard g;if(generation!=bridge.generation||bridge.job!=job)return;
        if(expired(now(),deadline)){finish(8,"WiFi association or IP timeout");return;}
        if(snap.linked&&snap.ip_ready&&snap.association_generation!=bridge.association_before&&
           snap.ssid_length==bridge.ssid_length&&!memcmp(snap.ssid,bridge.ssid,bridge.ssid_length)){
            bridge.configured_known=true;bridge.passphrase_known=true;bridge.configured_length=bridge.ssid_length;
            bridge.known_association=snap.association_generation;
            bridge.stored_password_length=bridge.candidate_password_length;
            memcpy(bridge.configured_ssid,bridge.ssid,bridge.ssid_length);finish(3,"Success");
        }else bridge.state=snap.linked&&snap.association_generation!=bridge.association_before?2:1;
    }
}
uint8_t p12_wifi_scan(WifiAP out[10],uint8_t &count,uint32_t timeout,bool (*cancel)(void *),void *context){
    WifiNativeSnapshot native={};if(!native_snapshot(native)||!native.available){error("WiFi module unavailable");return 1;}
    uint32_t generation,stop;
    {Guard g;if(bridge.job!=NONE){error("WiFi job busy");return 4;}
        if(!next_ticket(bridge.ticket))return 1;bridge.cache_valid=false;bridge.cache_count=0;bridge.scan_finished=false;
        bridge.deadline=now()+(timeout>15000?15000:timeout);stop=bridge.deadline;bridge.job=SCAN_QUEUED;generation=bridge.generation;}
    for(;;){
#if defined(P08_HTTP_HOST)
        p12_wifi_tick();
#endif
        {Guard g;if(generation!=bridge.generation)return 4;if(bridge.scan_finished){count=bridge.cache_count;if(!bridge.scan_status)memcpy(out,bridge.cache,sizeof(bridge.cache));return bridge.scan_status;}}
        if(expired(now(),stop)){
            if(bridge.ops.cancel)bridge.ops.cancel(bridge.ops.context);
            Guard g;if(generation==bridge.generation){bridge.job=NONE;bridge.scan_finished=true;bridge.scan_status=4;error("WiFi scan deadline");}return 4;
        }
        if(cancel&&cancel(context)){if(bridge.ops.cancel)bridge.ops.cancel(bridge.ops.context);Guard g;if(generation==bridge.generation){bridge.job=NONE;error("WiFi scan cancelled");}return 4;}
        if(bridge.ops.delay)bridge.ops.delay(bridge.ops.context,10);else return 1;
    }
}
uint8_t p15_wifi_rssi(int8_t &dbm,uint32_t timeout,bool (*cancel)(void *),void *context){
    WifiNativeSnapshot native={};
    if(!native_snapshot(native)||!native.available){error("WiFi module unavailable");return 1;}
    if(!native.linked){error("WiFi not connected");return 3;}
    if(!native.ssid_length||native.ssid_length>32){error("WiFi SSID unavailable");return 1;}
    if(cancel&&cancel(context)){error("WiFi signal cancelled");return 4;}
    uint32_t generation,stop;uint16_t ticket;
    {Guard g;
        if(bridge.job!=NONE){error("WiFi job busy");return 4;}
        if(bridge.forget_state==2&&bridge.forget_association==native.association_generation){error("WiFi settings cleared");return 3;}
        if(bridge.signal_valid&&uint32_t(now()-bridge.signal_time)<=5000&&
           bridge.signal_association==native.association_generation&&bridge.signal_length==native.ssid_length&&
           !memcmp(bridge.signal_ssid,native.ssid,native.ssid_length)){
            dbm=bridge.signal_rssi;error("Success");return 0;
        }
        if(!next_ticket(bridge.ticket))return 1;
        bridge.signal_valid=false;bridge.signal_finished=false;bridge.signal_status=1;
        memcpy(bridge.signal_ssid,native.ssid,native.ssid_length);bridge.signal_length=native.ssid_length;
        bridge.signal_association=native.association_generation;
        bridge.deadline=now()+(timeout>15000?15000:timeout);stop=bridge.deadline;
        bridge.job=SIGNAL_QUEUED;generation=bridge.generation;ticket=bridge.ticket;
    }
    for(;;){
#if defined(P08_HTTP_HOST)
        p12_wifi_tick();
#endif
        {Guard g;
            if(generation!=bridge.generation){error("WiFi signal session changed");return 4;}
            if(bridge.signal_finished){if(!bridge.signal_status)dbm=bridge.signal_rssi;return bridge.signal_status;}
        }
        bool cancelled=cancel&&cancel(context);
        if(cancelled||expired(now(),stop)||!bridge.ops.delay){
            if(bridge.ops.cancel)bridge.ops.cancel(bridge.ops.context);
            Guard g;
            if(generation==bridge.generation&&ticket==bridge.ticket&&(bridge.job==SIGNAL_QUEUED||bridge.job==SIGNAL_RPC)){
                bridge.job=NONE;bridge.signal_valid=false;bridge.signal_finished=true;bridge.signal_status=4;
                error(cancelled?"WiFi signal cancelled":"WiFi signal deadline");
            }
            return 4;
        }
        bridge.ops.delay(bridge.ops.context,10);
    }
}
uint8_t p15_wifi_stage_forget(const uint8_t session[8],uint32_t request){
#if P05_RAM_DIAGNOSTIC && !C64U_ESP_WIFI_CONFIG
    Guard g;error("WiFi settings read-only in RAM Alpha");return 1;
#else
    if(!configuration_ready()){error("ESP WiFi setup requires app update");return 1;}
    WifiNativeSnapshot native={};if(!native_snapshot(native)||!native.available){error("WiFi module unavailable");return 1;}
    Guard g;
    if(!same_session(session)||!nonzero(session)||!request){error("WiFi request not session bound");return 2;}
    if(bridge.job!=NONE){error("WiFi job busy");return 4;}
    if(!bridge.ops.forget){error("WiFi clear RPC unavailable");return 1;}
    if(!next_ticket(bridge.ticket))return 1;
    bridge.request=request;bridge.job=FORGET_STAGED;bridge.forget_state=1;bridge.state=1;
    bridge.connection_intent=true;error("WiFi clear queued");return 0;
#endif
}
uint8_t p12_wifi_stage(const uint8_t session[8],uint32_t request,const uint8_t *ssid,uint8_t sl,const uint8_t *password,uint8_t pl,int index){
#if P05_RAM_DIAGNOSTIC && !C64U_ESP_WIFI_CONFIG
    Guard g;error("WiFi settings read-only in RAM Alpha");return 1;
#else
    if(!configuration_ready()){error("ESP WiFi setup requires app update");return 1;}
    WifiNativeSnapshot native={};if(!native_snapshot(native)||!native.available){error("WiFi module unavailable");return 1;}
    Guard g;if(!same_session(session)||!nonzero(session)||!request){error("WiFi request not session bound");return 2;}
    if(bridge.job!=NONE){error("WiFi job busy");return 4;}
    if((index<0&&(!ssid||!sl||sl>32))||pl>64||(pl&&!password)){error("Invalid WiFi credentials");return 2;}
    uint8_t auth=pl?3:0;
    if(index>=0){if(!bridge.cache_valid||index>=bridge.cache_count){error("Invalid WiFi scan index");return 2;}ssid=bridge.cache[index].ssid;sl=bridge.cache[index].length;auth=bridge.cache[index].auth;}
    else for(unsigned i=0;i<bridge.cache_count;i++)if(bridge.cache_valid&&sl==bridge.cache[i].length&&!memcmp(ssid,bridge.cache[i].ssid,sl)){auth=bridge.cache[i].auth;break;}
    if(!ssid||!sl||sl>32){error("Invalid WiFi credentials");return 2;}
    // The installed Ultimate controller persists these fixed RPC arrays as
    // C strings. Full-width fields are not proven terminated in that firmware.
    // Do not silently truncate a user's network or key to make them fit.
    if(sl>31){error("Native WiFi SSID maximum is 31 bytes");return 2;}
    if(pl>63){error("Native WiFi key maximum is 63 bytes");return 2;}
    if(auth>7){error("Native WiFi security unsupported");return 2;}
    if(!next_ticket(bridge.ticket))return 1;
    memcpy(bridge.ssid,ssid,sl);bridge.ssid_length=sl;if(pl)memcpy(bridge.password,password,pl);bridge.password_length=pl;
    bridge.signal_valid=false;bridge.forget_state=0;bridge.candidate_password_length=pl;bridge.auth=auth;bridge.request=request;bridge.job=CONNECT_STAGED;bridge.state=1;bridge.connection_intent=true;error("wifi config queued");return 0;
#endif
}
void p12_wifi_response_consumed(const uint8_t session[8],uint32_t request){Guard g;
    if(same_session(session)&&request==bridge.request&&(bridge.job==CONNECT_STAGED||bridge.job==FORGET_STAGED)){
        // The C64U controller's private connect reply follows association and
        // verified AP storage. Other firmware keeps the original short RPC.
        bridge.job_deadline=now()+18000;
        bridge.deadline=now()+((C64U_ESP_WIFI_CONFIG&&bridge.job==CONNECT_STAGED)?12000:10000);
        bridge.job=bridge.job==CONNECT_STAGED?CONNECT_QUEUED:FORGET_QUEUED;
    }
}
void p12_wifi_request_context(const uint8_t session[8],uint32_t request){
    Guard g;if((bridge.job==CONNECT_STAGED||bridge.job==FORGET_STAGED)&&(!same_session(session)||request!=bridge.request)){
        if(bridge.job==FORGET_STAGED)bridge.forget_state=3;
        // Consumed proof for the previous response must be delivered first.
        // A superseding request without it abandons, rather than replays, the
        // staged native action. Keep failed intent so LAN cannot mask it.
        finish(8,"WiFi response abandoned");
    }
}
void p12_wifi_snapshot(WifiBridgeSnapshot &out){
    WifiNativeSnapshot native={};native_snapshot(native);Guard g;memset(&out,0,sizeof(out));out.available=native.available;
    out.configured_known=bridge.configured_known||native.ssid_length;out.configured=bridge.configured_length||native.ssid_length;
    out.passphrase_length_known=bridge.passphrase_known&&native.association_generation==bridge.known_association&&
        native.ssid_length==bridge.configured_length&&!memcmp(native.ssid,bridge.configured_ssid,native.ssid_length);
    out.passphrase_length=bridge.stored_password_length;
    const bool forgot=bridge.forget_state==2&&native.association_generation==bridge.forget_association;
    if(forgot){out.configured_known=true;out.configured=false;out.passphrase_length_known=false;native.ssid_length=0;native.linked=false;native.ip_ready=false;}
    out.job_pending=bridge.job==CONNECT_STAGED||bridge.job==CONNECT_QUEUED||bridge.job==CONNECT_RPC||bridge.job==CONNECT_WAIT||bridge.job==FORGET_STAGED||bridge.job==FORGET_QUEUED||bridge.job==FORGET_RPC;
    out.forget_state=bridge.forget_state;
    out.rssi_age_ms=uint32_t(now()-bridge.signal_time);
    out.rssi_known=bridge.signal_valid&&native.linked&&native.association_generation==bridge.signal_association&&
        native.ssid_length==bridge.signal_length&&!memcmp(native.ssid,bridge.signal_ssid,bridge.signal_length)&&out.rssi_age_ms<=5000;
    if(out.rssi_known){out.rssi=bridge.signal_rssi;out.rssi_source=1;}
    else out.rssi_age_ms=0;
    out.connection_intent=bridge.connection_intent;
    out.state=out.job_pending?bridge.state:bridge.state==8?8:native.linked?(native.ip_ready?3:2):out.configured?1:0;
    if(native.ssid_length){out.ssid_length=native.ssid_length;memcpy(out.ssid,native.ssid,native.ssid_length);}
    else if(bridge.configured_known){out.ssid_length=bridge.configured_length;memcpy(out.ssid,bridge.configured_ssid,bridge.configured_length);}
    memcpy(out.ip,native.ip,sizeof(out.ip));out.ip[15]=0;
}
uint8_t p12_wifi_wait_connected(uint8_t seconds,bool (*cancel)(void *),void *context){
    if(seconds>60){error("WiFi wait exceeds 60 seconds");return 2;}
    uint32_t deadline=now()+uint32_t(seconds)*1000;
    for(;;){
#if defined(P08_HTTP_HOST)
        p12_wifi_tick();
#endif
        WifiBridgeSnapshot s={};p12_wifi_snapshot(s);
        if(!s.available){error("WiFi module unavailable");return 1;}
        if(s.state==3){error("Success");return 0;}
        if(s.state==8)return 3; // Preserve the actual setup/storage failure.
        if(!s.job_pending&&!s.configured){error(s.configured_known?"WiFi not configured":"WiFi not connected");return s.configured_known?2:3;}
        if(expired(now(),deadline)){error(s.state==2?"No IP address assigned":"WiFi not connected");return 3;}
        if(cancel&&cancel(context)){error("WiFi wait cancelled");return 4;}
        if(bridge.ops.delay)bridge.ops.delay(bridge.ops.context,20);else return 1;
    }
}
const char *p12_wifi_last_error(){return bridge.error;}
void p15_wifi_note_forget_started(){
    if(bridge.ops.cancel)bridge.ops.cancel(bridge.ops.context);
    Guard g;bridge.generation++;bridge.job=NONE;bridge.request=0;
    bridge.scan_finished=false;bridge.cache_valid=false;bridge.cache_count=0;
    bridge.signal_valid=false;bridge.signal_finished=false;
    bridge.configured_known=false;bridge.passphrase_known=false;
    bridge.configured_length=bridge.stored_password_length=0;
    wipe(bridge.configured_ssid,sizeof(bridge.configured_ssid));
    wipe(bridge.password,sizeof(bridge.password));bridge.password_length=0;
    bridge.connection_intent=true;bridge.forget_state=1;bridge.state=1;
    error("Native WiFi clear pending");
}
void p15_wifi_note_forget_finished(bool confirmed){
    WifiNativeSnapshot native={};native_snapshot(native);
    Guard g;bridge.configured_known=confirmed;bridge.passphrase_known=false;
    bridge.configured_length=bridge.stored_password_length=0;bridge.signal_valid=false;
    bridge.forget_state=confirmed?2:3;bridge.forget_association=native.association_generation;
    finish(confirmed?0:8,confirmed?"WiFi settings cleared":"WiFi clear result uncertain");
}
void p12_wifi_note_connected(){
#if !defined(P08_HTTP_HOST)
    Guard g;association_generation++;
#endif
}
void p12_wifi_note_disconnected(){
#if !defined(P08_HTTP_HOST)
    Guard g;association_generation++;
#endif
}
bool p12_wifi_rpc_receive_isr(void *context,void *raw,void *wake){
#if !defined(P08_HTTP_HOST)
    command_buf_t *buffer=static_cast<command_buf_t *>(raw);if(buffer->size<sizeof(rpc_header_t))return false;
    rpc_header_t *header=reinterpret_cast<rpc_header_t *>(buffer->data);if(header->thread!=0xfe)return false;
    BaseType_t *w=static_cast<BaseType_t *>(wake);
    if(replies&&expected_sequence&&header->sequence==expected_sequence&&header->command==expected_command&&xQueueSendFromISR(replies,&buffer,w)==pdTRUE){expected_sequence=0;expected_command=0;return true;}
    wipe(buffer->data,sizeof(buffer->data));cmd_buffer_free_isr(static_cast<command_buf_context_t *>(context),buffer,w);return true;
#else
    (void)context;(void)raw;(void)wake;return false;
#endif
}
}
