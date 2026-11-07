#include "p12_commands.h"
#include "p18_version.h"
#include "p12_wifi.h"
#include "p12_tcp.h"
#include "p08_http.h"
#include "p15_network.h"
#include "p15_commands_extra.h"
#include "p15_ip.h"
#include <string.h>
#include <stdio.h>
namespace p08 {
namespace {
uint8_t current_session[8]={};uint32_t current_request=0;
P12CommandStatus command_status={};
void wipe(void *p,unsigned n){volatile uint8_t *q=static_cast<volatile uint8_t *>(p);while(n--)*q++=0;}
void message(BackendContext &c,const char *s){unsigned n=0;while(s[n]&&n<39){c.last_status[n]=s[n];n++;}c.last_status[n]=0;}
BackendResult result(uint8_t status=0,uint8_t error=0,uint32_t length=0){BackendResult r={status,error,0,false,length,0};return r;}
bool bytes(uint8_t *out,uint32_t cap,const void *value,uint32_t n,BackendResult &r){if(n>cap){r=result(1,HTTP_LENGTH);return false;}if(n)memcpy(out,value,n);r.length=n;return true;}
bool finish(BackendContext &c,uint8_t protocol,uint8_t *out,uint32_t cap,BackendResult &r,const char *text,const char *legacy_success=0,bool record_success=true,const char *legacy_error=0){
    // The ESP Command::status() writes the shared $2A text only for R/E.
    // Commands that merely return data do not replace a previous status.
    if(protocol!='W'&&(r.status||record_success))message(c,text);
    if(protocol=='W'&&(r.status||legacy_success)){
        const char *body=r.status?(legacy_error?legacy_error:text):legacy_success;
        bytes(out,cap,body,strlen(body),r);
    }
    return true;
}
bool cancelled(void *p){BackendContext *c=static_cast<BackendContext *>(p);return c->cancel_requested||(c->should_cancel&&c->should_cancel(c->cancel_context));}
int nibble(uint8_t x){if(x>='0'&&x<='9')return x-'0';if(x>='a'&&x<='f')return x-'a'+10;if(x>='A'&&x<='F')return x-'A'+10;return -1;}
bool parse_connect(uint8_t command,const uint8_t *in,uint32_t n,uint8_t ssid[32],uint8_t &sl,uint8_t password[64],uint8_t &pl,int &index){
    sl=pl=0;index=-1;if(!in||!n)return false;
    if(in[n-1]==0)n--; // A transport terminator is optional, never required.
    uint32_t cut=0;while(cut<n&&in[cut]!=1){if(!in[cut])return false;cut++;}
    if(!cut||cut==n)return false;
    if(command==0x0d){if(cut!=1||in[0]<'0'||in[0]>'9')return false;index=in[0]-'0';}
    else {if(cut>32)return false;sl=uint8_t(cut);memcpy(ssid,in,sl);}
    uint32_t end=cut+1;while(end<n&&in[end]!=1){if(!in[end])return false;end++;}
    // Both the historic trailing 01/01 and CC's unterminated final field are
    // accepted. Unexpected further data is rejected before any native action.
    for(uint32_t tail=end;tail<n;tail++)if(in[tail]!=1)return false;
    for(uint32_t i=cut+1;i<end;i++){
        uint8_t value=in[i];if(value=='~'){if(i+2>=end)return false;int hi=nibble(in[++i]),lo=nibble(in[++i]);if(hi<0||lo<0)return false;value=uint8_t((hi<<4)|lo);}
        if(!value||pl==64)return false;password[pl++]=value;
    }
    // WPA accepts a 64-digit hexadecimal PSK; a normal passphrase is <=63.
    if(pl==64)for(unsigned i=0;i<64;i++)if(nibble(password[i])<0)return false;
    return true;
}
void bitmap(uint8_t *out,uint8_t id){out[32+(id>>3)]|=uint8_t(1U<<(id&7));}
void build_info(uint8_t out[64]){
    memset(out,0,64);memcpy(out,"W64I",4);out[4]=1;out[5]=0;out[6]=64;memcpy(out+8,"U64 ",4);
    // Public WiC64 compatibility is the retained 2.4.4-1 candidate contract.
    // Keep the independent U64 build tuple for client validation/diagnostics.
    out[12]=P18_WIC64_MAJOR;out[13]=P18_WIC64_MINOR;out[14]=P18_WIC64_PATCH;out[15]=P18_WIC64_REVISION;
    out[16]=P18_U64_BUILD_MAJOR;out[17]=P18_U64_BUILD_MINOR;out[18]=P18_U64_BUILD_PATCH;out[19]=P18_U64_BUILD_REVISION;
    // Capability meanings apply under the U64 provider identifier. P14 adds
    // verified HTTPS and bearer sending; firmware updates remain simulation.
    for(unsigned i=0;i<8;i++)out[24+i]=uint8_t(U64_CAPABILITIES>>(8*i));
    static const uint8_t supported[]={0x00,0x01,0x02,0x06,0x08,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x14,0x15,0x16,0x17,0x1e,0x1f,0x21,0x22,0x23,0x26,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,
        0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0xfc,0xfd,0xfe};
    for(unsigned i=0;i<sizeof(supported);i++)bitmap(out,supported[i]);
    // $27 simulation is deliberately absent from the functional map: it does
    // not implement a firmware update. WPS and web-admin43 require unavailable
    // module/management APIs and are excluded; deprecated handlers stay excluded.
}
bool dummy_url(const uint8_t *p,uint32_t n){if(!p||!n||n>MAX_URL)return false;if(p[n-1]==0)n--;if(n<8)return false;
    bool http=!memcmp(p,"http://",7),https=n>=9&&!memcmp(p,"https://",8);
    if(!http&&!https)return false;
    for(uint32_t i=0;i<n;i++)if(p[i]<0x21||p[i]>0x7e)return false;return true;}
}
void p12_reset_commands(const uint8_t session[8]){memcpy(current_session,session,8);current_request=0;p12_wifi_reset(session);p12_tcp_reset();p15_network_reset();p15_ip_reset(session);command_status.reboot_simulation_pending=false;}
void p12_request_context(const uint8_t session[8],uint32_t request){p12_wifi_request_context(session,request);memcpy(current_session,session,8);current_request=request;p15_ip_request_context(session,request);}
void p12_response_consumed(const uint8_t session[8],uint32_t request){p12_wifi_response_consumed(session,request);p15_ip_response_consumed(session,request);}
void p12_reset_session(BackendContext &){p12_wifi_reset(current_session);p12_tcp_reset();p15_network_reset();p15_ip_reset(current_session);}
void p12_command_status(P12CommandStatus &out){out=command_status;}
bool p12_execute(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out){
    if(p15_execute_network(c,command,protocol,request,length,response,capacity,out))return true;
    if(p15_execute_extra(c,command,protocol,request,length,response,capacity,out))return true;
    if(p15_execute_ip(c,command,protocol,request,length,response,capacity,out))return true;
    bool wifi_command=command==0x02||command==0x0c||command==0x0d||command==0x10||command==0x11||command==0x2c||command==0x2f||command==0x3d||command==0x39;
    bool own=wifi_command||command==0x27||command==0x29||command==0x2d||command==0x41||command==0x36||command==0x37||command==0x38||command==0x43;
    bool tcp_command=command==0x21||command==0x22||command==0x23||command==0x2e||command==0x30||command==0x40;
    if(!own&&!tcp_command)return false;
    out=result();
    if(!response||!capacity||length>MAX_REQUEST||(length&&!request)){out=result(2,HTTP_ARGUMENT);return true;}
    if(protocol!='R'&&protocol!='W'){out=result(2,HTTP_UNSUPPORTED);message(c,"Command requires W or R protocol");return true;}
    if(tcp_command){
        if(!p12_execute_tcp(c,command,request,length,response,capacity,out))return false;
        const bool explicit_success=command==0x21||command==0x23||command==0x2e||command==0x40;
        const char *legacy_error=out.error==HTTP_TLS_TIME?"!T":out.status==4?"!E":"!0";
        return finish(c,protocol,response,capacity,out,out.status?"TCP request failed":"Success",explicit_success?"0":0,explicit_success,legacy_error);
    }
    if(command==0x02||command==0x0d){
        uint8_t ssid[32]={},password[64]={},sl=0,pl=0;int index=-1;
        bool valid=parse_connect(command,request,length,ssid,sl,password,pl,index);
        uint8_t status=valid?p12_wifi_stage(current_session,current_request,ssid,sl,password,pl,index):2;
        wipe(password,sizeof(password));wipe(ssid,sizeof(ssid));out=result(status,status?HTTP_ARGUMENT:0);
        return finish(c,protocol,response,capacity,out,valid?(status?p12_wifi_last_error():"wifi config queued"):"Invalid WiFi credential fields",status?0:"wifi config changed");
    }
    if(command==0x0c){
        if(length){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Scan expects no payload");}
        WifiAP aps[10]={};uint8_t count=0;uint8_t status=p12_wifi_scan(aps,count,15000,cancelled,&c);
        if(status){out=result(status,HTTP_READ);return finish(c,protocol,response,capacity,out,p12_wifi_last_error());}
        uint32_t used=0;uint8_t separator=protocol=='W'?1:0;
        for(unsigned i=0;i<count;i++){
            char signal[8];int n=snprintf(signal,sizeof(signal),"%d",int(aps[i].rssi));
            uint32_t needed=2+aps[i].length+1+unsigned(n)+1;
            if(n<0||used+needed+(protocol=='R'?1:0)>capacity){out=result(1,HTTP_LENGTH);return finish(c,protocol,response,capacity,out,"Scan response buffer too small");}
            response[used++]='0'+i;response[used++]=separator;memcpy(response+used,aps[i].ssid,aps[i].length);used+=aps[i].length;response[used++]=separator;
            memcpy(response+used,signal,n);used+=n;response[used++]=separator;
        }
        if(protocol=='R')response[used++]=0xff;out.length=used;return finish(c,protocol,response,capacity,out,"Success",0,false);
    }
    if(command==0x2c){
        if(length!=1){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"WiFi wait requires one byte");}
        if(request[0]>60){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Network wait exceeds 60 seconds");}
        WifiBridgeSnapshot s={};p12_wifi_snapshot(s);
        // A configuration job must prove its own WLAN result even if Ethernet
        // remains online. Ordinary application readiness uses its selected NIC.
        if(!s.connection_intent&&!c.network.wireless){out=result(c.network.connected?0:3,c.network.connected?0:HTTP_CONNECT);return finish(c,protocol,response,capacity,out,c.network.connected?"Success":"Network not connected");}
        uint8_t status=p12_wifi_wait_connected(request[0],cancelled,&c);out=result(status,status?HTTP_CONNECT:0);
        return finish(c,protocol,response,capacity,out,status?p12_wifi_last_error():"WiFi connected",status?0:"WiFi connected");
    }
    if(command==0x39){
        if(length){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Forget WiFi expects no payload");}
        if(capacity<4){out=result(1,HTTP_LENGTH);return finish(c,protocol,response,capacity,out,"Forget response requires four bytes");}
        uint8_t status=p15_wifi_stage_forget(current_session,current_request);
        out=result(status,status?HTTP_ARGUMENT:0);
        if(!status){const uint8_t core[4]={0,0,0,0xff};bytes(response,capacity,core,4,out);}
        // Native WPS is idle; $FF explicitly denotes an unknown ESP driver
        // state. This ACK queues forgetting; it never claims completed erasure.
        return finish(c,protocol,response,capacity,out,status?p12_wifi_last_error():"WiFi forget queued",0,false);
    }
    if(command==0x10||command==0x11||command==0x2f||command==0x3d){
        if(length){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Command expects no payload");}
        WifiBridgeSnapshot s={};p12_wifi_snapshot(s);
        if(!s.available){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"WiFi module unavailable");}
        if(command==0x3d){
            // A cold host cannot inspect the controller's saved NVS settings.
            // Unknown is not proof of an empty WiFi configuration. A scan
            // result alone also establishes no connection-attempt history.
            if(!s.configured_known&&!s.connection_intent&&!s.job_pending&&s.state!=2&&s.state!=3){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"Stored WiFi state unavailable");}
            uint8_t pair[2]={s.state,s.reason};bytes(response,capacity,pair,2,out);return finish(c,protocol,response,capacity,out,"Success",0,false);
        }
        if(command==0x11){
            if(!c.network.wireless){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"Selected adapter is not WLAN");}
            int8_t dbm=0;uint8_t status=p15_wifi_rssi(dbm,15000,cancelled,&c);
            out=result(status,status?HTTP_READ:0);
            if(status)return finish(c,protocol,response,capacity,out,p12_wifi_last_error());
            char signal[12];int n=snprintf(signal,sizeof(signal),"%ddbm",int(dbm));
            if(n<0||unsigned(n)>=sizeof(signal)||!bytes(response,capacity,signal,unsigned(n)+1,out))out=result(1,HTTP_LENGTH);
            return finish(c,protocol,response,capacity,out,out.status?"RSSI response too large":"Success",0,false);
        }
        if(command==0x2f){
            if(protocol!='R'){out=result(2,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"Configured requires R protocol");}
            if(!s.configured_known||!s.passphrase_length_known){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"Stored WiFi metadata unavailable");}
            if(!s.configured){out=result(1,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"WiFi not configured");}
            bytes(response,capacity,&s.passphrase_length,1,out);return finish(c,protocol,response,capacity,out,"Success",0,false);
        }
        if(!s.ssid_length){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"WiFi SSID unavailable");}
        if(uint32_t(s.ssid_length)+1>capacity){out=result(1,HTTP_LENGTH);return finish(c,protocol,response,capacity,out,"SSID response too large");}
        memcpy(response,s.ssid,s.ssid_length);response[s.ssid_length]=0;out.length=s.ssid_length+1;return finish(c,protocol,response,capacity,out,"Success",0,false);
    }
    if(command==0x27){
        if(!dummy_url(request,length)){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Invalid simulation URL");}
        command_status.simulated_updates++;command_status.reboot_simulation_pending=true;
        return finish(c,protocol,response,capacity,out,"SIMULATED_NO_FLASH",protocol=='W'?"SIMULATED_NO_FLASH":0);
    }
    if(command==0x2d){
        if(!length||!request[0]){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Transfer timeout requires 1..255");}
        // The helper arms this value only after this successful reply is sent.
        return finish(c,protocol,response,capacity,out,"Success",0,false);
    }
    if(command==0x29){out=result(length?2:1,length?HTTP_ARGUMENT:HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"Reboot requires helper handshake");}
    if(command==0x36||command==0x37||command==0x38){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"WPS unavailable on native WLAN");}
    if(command==0x43){out=result(1,HTTP_UNSUPPORTED);return finish(c,protocol,response,capacity,out,"Native API uses its own login");}
    if(command==0x41){
        if(length!=1||request[0]!=1){out=result(2,HTTP_ARGUMENT);return finish(c,protocol,response,capacity,out,"Unsupported build-info schema",0,false,"!0");}
        uint8_t info[64];build_info(info);bytes(response,capacity,info,sizeof(info),out);return finish(c,protocol,response,capacity,out,out.status?"Response buffer too small":"Success",0,false,"!0");
    }
    return false;
}
}
