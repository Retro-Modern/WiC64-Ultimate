#include "p15_commands_extra.h"
#include <string.h>
#include <stdio.h>
#if C64U_ESP_PERSIST
#include "p21_preferences.h"
#endif
#if defined(P08_HTTP_HOST)
#include <time.h>
#else
extern "C" {
#include "FreeRTOS.h"
#include "task.h"
}
#include "p14_platform.h"
#include "config.h"
#include "init_function.h"
#endif

namespace p08 {
namespace {
// WiC64's fixed-offset table, independently of the native menu's POSIX zone.
const int32_t offsets[32]={0,0,3600,7200,7200,10800,12600,14400,
    18000,19800,21600,25200,28800,32400,34200,36000,39600,43200,
    -39600,-36000,-32400,-28800,-25200,-25200,-21600,-18000,-18000,
    -14400,-12600,-10800,-10800,-3600};
#if defined(P08_HTTP_HOST)
P15ExtraTestOps test_ops={};
bool utc(uint64_t &out){return test_ops.utc&&test_ops.utc(test_ops.context,out);}
uint8_t timezone_index(){
#if C64U_ESP_PERSIST
 return p21prefs::timezone();
#else
 return test_ops.timezone?test_ops.timezone(test_ops.context):0;
#endif
}
bool save_timezone(uint8_t i){
#if C64U_ESP_PERSIST
 return p21prefs::save_timezone(i);
#else
 return test_ops.save_timezone&&test_ops.save_timezone(test_ops.context,i);
#endif
}
uint32_t milliseconds(){if(test_ops.milliseconds)return test_ops.milliseconds(test_ops.context);timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return uint32_t(uint64_t(t.tv_sec)*1000+t.tv_nsec/1000000);}
void delay(uint32_t ms){if(test_ops.delay)test_ops.delay(test_ops.context,ms);else{timespec t={0,long(ms*1000000)};nanosleep(&t,0);}}
#else
enum { PUBLIC_SETTINGS_ID=0x57313550, TIMEZONE_ITEM=0x10,
       SERVER_FIRST_ITEM=0x11, SERVER_SECOND_ITEM=0x12 };
t_cfg_definition definitions[]={
    {TIMEZONE_ITEM,CFG_TYPE_VALUE,"WiC64 timezone index","%d",0,0,31,0},
    {SERVER_FIRST_ITEM,CFG_TYPE_STRING,"WiC64 server prefix 1","%s",0,0,PUBLIC_SERVER_PART,(long)""},
    {SERVER_SECOND_ITEM,CFG_TYPE_STRING,"WiC64 server prefix 2","%s",0,0,PUBLIC_SERVER_PART,(long)""},
    {CFG_TYPE_END,CFG_TYPE_END,"","",0,0,0,0}
};
class PublicPreferences:public ConfigurableObject {
public:
    void init(){if(register_store(PUBLIC_SETTINGS_ID,"WiC64 compatibility settings",definitions)){cfg->hide();cfg->set_effectuated();}}
} preferences;
InitFunction init_preferences("WiC64 nonsecret settings",[](void *,void *){preferences.init();},0,0,105);
bool utc(uint64_t &out){return p14::utc_now(out)==p14::OK;}
uint8_t timezone_index(){
#if C64U_ESP_PERSIST
 return p21prefs::timezone();
#endif
 int value=preferences.cfg?preferences.cfg->get_value(TIMEZONE_ITEM):0;return value>=0&&value<32?uint8_t(value):0;}
bool save_timezone(uint8_t i){
#if C64U_ESP_PERSIST
    return p21prefs::save_timezone(i);
#endif
    if(!preferences.cfg||!preferences.cfg->get_page())return false;
    const int prior=preferences.cfg->get_value(TIMEZONE_ITEM);
    preferences.cfg->set_value(TIMEZONE_ITEM,i);
    bool saved=preferences.cfg->get_page()->p15_write_verified();
    if(!saved)preferences.cfg->set_value(TIMEZONE_ITEM,prior);
    else{preferences.cfg->set_need_flash_write(false);preferences.cfg->set_effectuated();}
    return saved;
}
uint32_t milliseconds(){return uint32_t(xTaskGetTickCount())*(1000U/configTICK_RATE_HZ);}
void delay(uint32_t ms){TickType_t ticks=pdMS_TO_TICKS(ms);vTaskDelay(ticks?ticks:1);}
#endif
bool cancelled(BackendContext &c){return c.cancel_requested||(c.should_cancel&&c.should_cancel(c.cancel_context));}
BackendResult result(uint8_t s=0,uint8_t e=0,uint32_t n=0){BackendResult r={s,e,0,false,n,0};return r;}
void status(BackendContext &c,const char *s){unsigned n=0;while(s[n]&&n<sizeof(c.last_status)-1){c.last_status[n]=s[n];n++;}c.last_status[n]=0;}
bool fail(BackendContext &c,BackendResult &r,uint8_t s,uint8_t e,const char *text){r=result(s,e);status(c,text);return true;}
bool text(BackendContext &c,BackendResult &r,uint8_t *out,uint32_t cap,const char *s){uint32_t n=uint32_t(strlen(s))+1;if(n>cap)return fail(c,r,1,HTTP_LENGTH,"Response buffer too small");memcpy(out,s,n);r=result(0,0,n);return true;}
const char *deprecated(uint8_t command){
    switch(command){
    case 0x03:case 0x04:case 0x05:case 0x18:return "Firmware updates are now handled by the new update command $27. The old update program(s) may still appear to be working, but will actually no longer install any updates.";
    case 0x07:return "Firmware is now versioned semantically, use command $00 to get a version string to display to the user, or use command $26 to get the version as individual bytes (<major> <minor> <patch> <devel>)";
    case 0x09:return "We see no reason to log to the esp console from the c64. If you *really* need this, please drop us a line.";
    case 0x13:return "The command for getting the external IP has never worked correctly, nor has it been used in any programs we are aware of.";
    case 0x19:case 0x1a:return "The commands for getting or setting ESP preferences from the c64 have been removed because they are inherently unsafe. Third parties should not be able to write arbitrary data to the ESP flash memory.";
    case 0x20:return "This command was called \"set tcp port\" but has apparently never had any effect in the legacy firmware, apart from setting a global variable that was never used.";
    case 0x24:return "The previous implementation of HTTP POST was broken and the payload structure was unnecessarily complex. Please use the new commands WIC64_HTTP_POST_SET_URL and WIC64_HTTP_POST_DATAinstead.";
    case 0x25:return "This command was called \"big loader\" and was intended as aHTTP GET request implementation for transfer sizes above 64kb. It has never worked properly and has never been officially documented. General support for payloads larger than 64kb has been added with the extended command protocol.";
    case 0x63:return "The factory reset command has been deprecated. If this turns outto be required at all, it will be implemented from the web interface instead.";
    default:return 0;
    }
}
// Gregorian conversion of a bounded Unix day count; no libc time(), TZ,
// localtime(), RTC writes or mutable TLS clock state is involved.
bool format_time(uint64_t seconds,int32_t offset,char out[20]){
    if(seconds>4102444799ULL)return false;
    int64_t local=int64_t(seconds)+offset;
    if(local<0||local>4102444799LL)return false;
    unsigned day=unsigned(local/86400),within=unsigned(local%86400),year=1970;
    while(true){bool leap=year%4==0&&(year%100!=0||year%400==0);unsigned n=leap?366:365;if(day<n)break;day-=n;year++;}
    const unsigned month_days[]={31,28,31,30,31,30,31,31,30,31,30,31};unsigned month=0;
    while(month<11){unsigned n=month_days[month];if(month==1&&year%4==0&&(year%100!=0||year%400==0))n++;if(day<n)break;day-=n;month++;}
    int n=snprintf(out,20,"%02u:%02u:%02u %02u-%02u-%04u",within/3600,(within/60)%60,within%60,day+1,month+1,year);
    return n==19;
}
}
bool p15_load_public_server(char *out,uint32_t capacity){
    if(!out||capacity<PUBLIC_SERVER_MAX+1)return false;
#if C64U_ESP_PERSIST
    return p21prefs::load_server(out,capacity);
#endif
#if defined(P08_HTTP_HOST)
    return test_ops.load_server&&test_ops.load_server(test_ops.context,out,capacity);
#else
    if(!preferences.cfg)return false;
    const char *first=preferences.cfg->get_string(SERVER_FIRST_ITEM);
    const char *second=preferences.cfg->get_string(SERVER_SECOND_ITEM);
    unsigned a=0,b=0;
    while(a<=PUBLIC_SERVER_PART&&first[a])a++;
    while(b<=PUBLIC_SERVER_PART&&second[b])b++;
    if(!a||a>PUBLIC_SERVER_PART||b>PUBLIC_SERVER_PART||(b&&a!=PUBLIC_SERVER_PART))return false;
    for(unsigned i=0;i<a;i++)if(uint8_t(first[i])<0x20||uint8_t(first[i])>0x7e)return false;
    for(unsigned i=0;i<b;i++)if(uint8_t(second[i])<0x20||uint8_t(second[i])>0x7e)return false;
    memcpy(out,first,a);memcpy(out+a,second,b);out[a+b]=0;return true;
#endif
}
bool p15_save_public_server(const char *server){
    if(!server)return false;
    unsigned n=0;while(n<=PUBLIC_SERVER_MAX&&server[n]){
        if(uint8_t(server[n])<0x20||uint8_t(server[n])>0x7e)return false;n++;
    }
    if(!n||n>PUBLIC_SERVER_MAX)return false;
#if C64U_ESP_PERSIST
    return p21prefs::save_server(server);
#endif
#if defined(P08_HTTP_HOST)
    return test_ops.save_server&&test_ops.save_server(test_ops.context,server);
#else
    if(!preferences.cfg||!preferences.cfg->get_page())return false;
    // Header4 + timezone7 + two string records(3+240) + terminator1 =498.
    // Each length fits the native one-byte field; no secret journal changes.
    char first[PUBLIC_SERVER_PART+1]={},old_first[PUBLIC_SERVER_PART+1],old_second[PUBLIC_SERVER_PART+1];
    strcpy(old_first,preferences.cfg->get_string(SERVER_FIRST_ITEM));
    strcpy(old_second,preferences.cfg->get_string(SERVER_SECOND_ITEM));
    const unsigned a=n>PUBLIC_SERVER_PART?PUBLIC_SERVER_PART:n;
    memcpy(first,server,a);
    preferences.cfg->set_string(SERVER_FIRST_ITEM,first);
    preferences.cfg->set_string(SERVER_SECOND_ITEM,n>a?server+a:"");
    bool saved=preferences.cfg->get_page()->p15_write_verified();
    if(!saved){
        // A failed readback may follow a complete physical commit. Keep RAM
        // on the old value and report failure; do not claim durable rollback.
        preferences.cfg->set_string(SERVER_FIRST_ITEM,old_first);
        preferences.cfg->set_string(SERVER_SECOND_ITEM,old_second);
    }else{preferences.cfg->set_need_flash_write(false);preferences.cfg->set_effectuated();}
    return saved;
#endif
}
#if defined(P08_HTTP_HOST)
void p15_extra_test_ops(const P15ExtraTestOps &ops){test_ops=ops;}
#endif
static bool execute_extra(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out){
    const char *reason=deprecated(command);
    if(command!=0x15&&command!=0x16&&command!=0x17&&command!=0xfc&&!reason)return false;
    out=result();
    if(!response||!capacity||length>MAX_REQUEST||(length&&!request))return fail(c,out,2,HTTP_ARGUMENT,"Invalid command arguments");
    if(protocol!='R'&&protocol!='W')return fail(c,out,2,HTTP_UNSUPPORTED,"Command requires W or R protocol");
    if(reason){
        char prefix[]="Command $00 has been deprecated since firmware version 2.0.0:\r\n";
        static const char hex[]="0123456789abcdef";prefix[9]=hex[command>>4];prefix[10]=hex[command&15];
        const uint32_t a=sizeof(prefix)-1,b=uint32_t(strlen(reason))+1;
        if(a+b>capacity)return fail(c,out,1,HTTP_LENGTH,"Response buffer too small");
        memcpy(response,prefix,a);memcpy(response+a,reason,b);out=result(0,0,a+b);return true;
    }
    if(command==0xfc){
        uint8_t seconds=length?request[0]:1;
        if(seconds>60)return fail(c,out,2,HTTP_ARGUMENT,"Diagnostic wait exceeds 60 seconds");
        uint32_t began=milliseconds(),limit=uint32_t(seconds)*1000;
        while(uint32_t(milliseconds()-began)<limit){
            if(cancelled(c))return fail(c,out,4,HTTP_CANCELLED,"Cancelled");
            uint32_t left=limit-uint32_t(milliseconds()-began);delay(left<20?left:20);
        }
        if(cancelled(c))return fail(c,out,4,HTTP_CANCELLED,"Cancelled");return true;
    }
    if(command==0x16){
        if(length<2)return fail(c,out,2,HTTP_ARGUMENT,"Invalid timezone index");
        unsigned digit[2]={request[0],request[1]};
        // Parser::timezoneIndex accepts either two ASCII digits or two raw
        // digits, consumes the first two bytes and ignores a trailing payload.
        if(digit[0]>='0'&&digit[0]<='9'&&digit[1]>='0'&&digit[1]<='9'){
            digit[0]-='0';digit[1]-='0';
        }else if(digit[0]>9||digit[1]>9)return fail(c,out,2,HTTP_ARGUMENT,"Invalid timezone index");
        unsigned index=digit[1]*10+digit[0];if(index>=32)return fail(c,out,2,HTTP_ARGUMENT,"Invalid timezone index");
        if(cancelled(c))return fail(c,out,4,HTTP_CANCELLED,"Cancelled");
        if(!save_timezone(uint8_t(index)))return fail(c,out,1,HTTP_WRITE,"Timezone storage unavailable");
        return true;
    }
    if(length)return fail(c,out,2,HTTP_ARGUMENT,"Command expects no payload");
    uint8_t index=timezone_index();if(index>=32)return fail(c,out,1,HTTP_ARGUMENT,"Invalid stored timezone");
    if(command==0x17){char value[8];snprintf(value,sizeof(value),"%d",int(offsets[index]));return text(c,out,response,capacity,value);}
    uint64_t now=0;char value[20];if(!utc(now)||!format_time(now,offsets[index],value))return fail(c,out,1,HTTP_TLS_TIME,"Clock unavailable");
    return text(c,out,response,capacity,value);
}
bool p15_execute_extra(BackendContext &c,uint8_t command,uint8_t protocol,const uint8_t *request,uint32_t length,uint8_t *response,uint32_t capacity,BackendResult &out){
    char previous_status[sizeof(c.last_status)];memcpy(previous_status,c.last_status,sizeof(previous_status));
    bool owned=execute_extra(c,command,protocol,request,length,response,capacity,out);
    // Legacy W has no status byte: its error body follows the existing native
    // command convention, exact ASCII without an added terminator.
    if(owned&&protocol=='W'&&out.status&&response&&capacity){
        const char *body=command==0x16&&out.status==2?"!0":c.last_status;
        uint32_t n=uint32_t(strlen(body));
        if(n<=capacity){memcpy(response,body,n);out.length=n;}
    }
    if(protocol=='W')memcpy(c.last_status,previous_status,sizeof(previous_status));
    return owned;
}

}
