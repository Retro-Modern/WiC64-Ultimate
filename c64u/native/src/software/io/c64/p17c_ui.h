#ifndef P17C_WIC64_UI_H
#define P17C_WIC64_UI_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "p08_http.h"
#include "p18_version.h"
#if defined(P18_TLS) && P18_TLS
#include "p18_tls.h"
#endif

namespace p17c {
// UIPopup adds two border columns and four rows and does not clamp to the
// screen. These bounds leave the complete popup inside a 40 x 25 C64 screen.
enum { LINE_COLUMNS=36, PANEL_ROWS=20, PANEL_BYTES=768 };

struct StatusView {
    const char *state,*drives,*https,*https_error,*flash,*flash_error,*last_error,*setup_result,*math_cache;
    bool menu_paused,program_pending,rssi_known;
    int rssi;
    uint32_t rssi_age_ms,requests;
    p08::BackendSummary network;
};

inline const char *connection_name(uint8_t mode)
{
    return mode==p08::NETWORK_LAN?"LAN":mode==p08::NETWORK_WLAN?"WLAN":"Auto";
}

inline const char *network_action_label(const p08::BackendSummary &network)
{
    return network.preference==p08::NETWORK_LAN?"Connection: LAN":
        network.preference==p08::NETWORK_WLAN?"Connection: WLAN":"Connection: Auto";
}

inline uint8_t network_toggle_target(const p08::BackendSummary &network)
{
    // Cycle the saved preference: Auto -> LAN -> WLAN -> Auto.
    return network.preference==p08::NETWORK_AUTO?p08::NETWORK_LAN:
        network.preference==p08::NETWORK_LAN?p08::NETWORK_WLAN:p08::NETWORK_AUTO;
}

class Panel {
    char *buffer;
    size_t capacity,used;
    unsigned rows;
    bool complete;
    void emit(const char *text,size_t count)
    {
        if(rows>=PANEL_ROWS||used+LINE_COLUMNS+(rows?1:0)+1>capacity){complete=false;return;}
        if(rows)buffer[used++]='\n';
        for(size_t i=0;i<count;i++){
            const unsigned char ch=static_cast<unsigned char>(text[i]);
            buffer[used++]=ch>=32&&ch<=126?char(ch):'?';
        }
        // UIPopup centers each line separately. Padding fixes the content
        // width so field labels stay aligned instead of shifting every row.
        for(size_t i=count;i<LINE_COLUMNS;i++)buffer[used++]=' ';
        buffer[used]=0;rows++;
    }
public:
    Panel(char *output,size_t size):buffer(output),capacity(size),used(0),rows(0),complete(size!=0)
    {
        if(capacity)buffer[0]=0;
    }
    void line(const char *text)
    {
        if(!text||!*text)return;
        const char *read=text;
        while(*read){
            size_t length=strlen(read),count=length;
            if(count>LINE_COLUMNS){
                count=LINE_COLUMNS;
                // Prefer a word boundary, but split long diagnostic codes as
                // needed rather than allowing them to overwrite the border.
                size_t split=count;
                while(split&&read[split]!=' ')split--;
                size_t next=split;
                while(next<length&&read[next]==' ')next++;
                // A short label must not consume a whole row, and selecting
                // a word boundary must not add rows to the hard-wrap budget.
                // In particular, "Error: " + 79 characters fits three rows.
                const size_t minimum_rows=(length+LINE_COLUMNS-1)/LINE_COLUMNS;
                const size_t remaining_rows=(length-next+LINE_COLUMNS-1)/LINE_COLUMNS;
                if(split>=LINE_COLUMNS/2&&1+remaining_rows<=minimum_rows)count=split;
            }
            emit(read,count);read+=count;
            while(*read==' ')read++;
        }
    }
    void field(const char *label,const char *value)
    {
        char text[128];
        snprintf(text,sizeof(text),"%s: %s",label,value?value:"Unavailable");
        line(text);
    }
    void number(const char *label,uint32_t value,const char *unit="")
    {
        char text[80];
        snprintf(text,sizeof(text),"%s: %u%s",label,unsigned(value),unit);
        line(text);
    }
    bool ok()const{return complete;}
};

inline bool format_status(char *text,size_t capacity,const StatusView &view)
{
    Panel panel(text,capacity);char value[80];
    panel.line(P18_STATUS_TITLE);
    panel.field("State",view.state);
    panel.field("C64",view.program_pending?"Starting program":view.menu_paused?"Paused in menu":"Running");
    panel.field("Connection",connection_name(view.network.preference));
    if(view.network.mac_valid)
        snprintf(value,sizeof(value),"%s (%s)",connection_name(view.network.selected),view.network.connected?"connected":"offline");
    else if(view.network.preference==p08::NETWORK_AUTO)strcpy(value,"No adapter available");
    else snprintf(value,sizeof(value),"%s adapter unavailable",connection_name(view.network.preference));
    panel.field("Using",value);
    if(view.network.mac_valid){
        snprintf(value,sizeof(value),"%u.%u.%u.%u",unsigned(view.network.ipv4[0]),unsigned(view.network.ipv4[1]),unsigned(view.network.ipv4[2]),unsigned(view.network.ipv4[3]));
        panel.field("IP",value);
        snprintf(value,sizeof(value),"%02X:%02X:%02X:%02X:%02X:%02X",view.network.mac[0],view.network.mac[1],view.network.mac[2],view.network.mac[3],view.network.mac[4],view.network.mac[5]);
        panel.field("MAC",value);
    }
    if(view.network.mac_valid&&view.network.selected==p08::NETWORK_WLAN){
        if(view.rssi_known){
            snprintf(value,sizeof(value),"%d dBm (scan sample)",view.rssi);
            panel.field("WLAN signal",value);
            panel.number("Sample age",view.rssi_age_ms," ms");
        }else panel.field("WLAN signal","Not measured");
    }
    panel.field("Drives",view.drives);
    panel.field("HTTPS",view.https);
#if defined(P18_TLS) && P18_TLS
    panel.field("TLS engine",p18::engine_name());
#endif
    if(view.https_error&&*view.https_error&&strcmp(view.https_error,"OK"))panel.field("HTTPS error",view.https_error);
    if(view.setup_result)panel.field("Last setup",view.setup_result);
    panel.field("Flash",view.flash);
    if(view.flash_error&&*view.flash_error)panel.field("Flash error",view.flash_error);
    panel.number("Requests",view.requests);
    panel.field("Error",view.last_error&&*view.last_error?"See WiC64 Diagnostics":"None");
    return panel.ok();
}

inline bool format_diagnostics(char *text,size_t capacity,const StatusView &view,const p08::RequestTrace &trace)
{
    Panel panel(text,capacity);char value[80];
    panel.line(P18_DIAGNOSTIC_TITLE);
    panel.field("State",view.state);
    if(view.last_error&&*view.last_error)panel.field("Error",view.last_error);
    if(!trace.sequence){panel.line("No network operation recorded");return panel.ok();}
    snprintf(value,sizeof(value),"$%02X / %c",unsigned(trace.command),
        (trace.protocol=='W'||trace.protocol=='R'||trace.protocol=='E')?trace.protocol:'?');
    panel.field("Last operation",value);
    panel.field("Phase",p08::trace_phase_name(trace.phase));
    panel.field("Delivery",p08::trace_lifecycle_name(trace.lifecycle));
    panel.number("Budget",trace.remote_budget_ms," ms");
    panel.number("Backend",trace.lifecycle==p08::TRACE_EXECUTING?trace.elapsed_tick_ms:trace.backend_elapsed_tick_ms," ms");
    panel.number("Total",trace.elapsed_tick_ms," ms");
    panel.field("TLS call",trace.tls_call_active?"Active":trace.tls_call_interrupted?"Interrupted":"Last completed");
    panel.number("TLS duration",trace.tls_call_active||trace.tls_call_interrupted?trace.tls_inflight_tick_ms:trace.tls_last_call_tick_ms," ms");
    panel.number("TLS maximum",trace.tls_max_call_tick_ms," ms");
    panel.number("TLS calls",trace.tls_connect_calls);
    snprintf(value,sizeof(value),"%u/%u B",unsigned(trace.tls_sent_bytes),unsigned(trace.tls_received_bytes));
    panel.field("TLS tx/rx",value);
    snprintf(value,sizeof(value),"%u/%u",unsigned(trace.tls_io_tick_ms),unsigned(trace.tls_io_max_tick_ms));
    panel.field("I/O ms/max",value);
    snprintf(value,sizeof(value),"%u/%u",unsigned(trace.status),unsigned(trace.error));
    panel.field("Result",value);
    panel.number("HTTP status",trace.http_status);
    panel.line("Clock: RTOS ticks in milliseconds");
    return panel.ok();
}

inline const char *crypto_short_name(unsigned kind)
{
    switch(kind){
    case p08::TRACE_CRYPTO_ECC_KEYGEN:return "ECCgen";
    case p08::TRACE_CRYPTO_ECC_VERIFY:return "ECCsig";
    case p08::TRACE_CRYPTO_ECC_SHARED:return "ECDH";
    case p08::TRACE_CRYPTO_RSA_PKCS1:return "RSAv15";
    case p08::TRACE_CRYPTO_RSA_PSS:return "RSA-PSS";
    default:return "None";
    }
}

inline void crypto_call_text(char *text,size_t capacity,unsigned kind,unsigned bits,uint32_t elapsed)
{
    if(kind==p08::TRACE_CRYPTO_NONE||kind>=p08::TRACE_CRYPTO_KIND_COUNT)
        snprintf(text,capacity,"None");
    else snprintf(text,capacity,"%s/%u %u ms",crypto_short_name(kind),bits,unsigned(elapsed));
}

inline bool format_tls_details(char *text,size_t capacity,const StatusView &view,const p08::RequestTrace &trace)
{
    Panel panel(text,capacity);char value[80];
    panel.line(P18_TLS_DETAILS_TITLE);
    if(!trace.sequence){
        if(view.math_cache)panel.field("Code cache",view.math_cache);
        panel.line("No network operation recorded");return panel.ok();
    }
    snprintf(value,sizeof(value),"$%02X %s",unsigned(trace.command),p08::trace_phase_name(trace.phase));
    panel.field("Op",value);
    panel.field("Delivery",p08::trace_lifecycle_name(trace.lifecycle));
    panel.number("Budget",trace.remote_budget_ms," ms");
    crypto_call_text(value,sizeof(value),trace.crypto_call_active||trace.crypto_call_interrupted?trace.crypto_active_kind:p08::TRACE_CRYPTO_NONE,
        trace.crypto_active_bits,trace.crypto_inflight_tick_ms);
    if(!trace.crypto_call_active&&!trace.crypto_call_interrupted&&view.math_cache)
        panel.field("Code cache",view.math_cache);
    else panel.field(trace.crypto_call_interrupted?"Stopped":"Active",value);
    crypto_call_text(value,sizeof(value),trace.crypto_last_kind,trace.crypto_last_bits,trace.crypto_last_call_tick_ms);
    panel.field("Last",value);
    crypto_call_text(value,sizeof(value),trace.crypto_max_kind,trace.crypto_max_bits,trace.crypto_max_call_tick_ms);
    panel.field("Peak",value);
    panel.line("Rows: total ms / max ms / calls");
    for(unsigned kind=1;kind<p08::TRACE_CRYPTO_KIND_COUNT;kind++){
        const p08::CryptoTraceBin &bin=trace.crypto[kind-1];
        snprintf(value,sizeof(value),"%s (peak %u bits)",p08::trace_crypto_kind_name(kind),unsigned(bin.max_bits));
        panel.line(value);
        snprintf(value,sizeof(value),"%u/%u/%u",unsigned(bin.total_tick_ms),unsigned(bin.max_tick_ms),unsigned(bin.calls));
        panel.line(value);
    }
    snprintf(value,sizeof(value),"%u/%u; HTTP %u",unsigned(trace.status),unsigned(trace.error),unsigned(trace.http_status));
    panel.field("Result",value);
    panel.line("Elapsed includes task switches");
    return panel.ok();
}
}
#endif
