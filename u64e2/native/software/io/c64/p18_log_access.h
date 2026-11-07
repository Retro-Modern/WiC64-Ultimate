#ifndef P18_WIC64_LOG_ACCESS_H
#define P18_WIC64_LOG_ACCESS_H
#include "p17c_ui.h"
#include "p18_log_stream.h"
#if !defined(P18_LOG_ACCESS_HOST_TEST)
#include "p08_service.h"
#include "network_config.h"
#include "userinterface.h"
#endif
namespace p18logaccess {
inline const char *level_name(unsigned value)
{
    return value==0?"Off":value==1?"Error":value==2?"Info":"Debug";
}
inline bool format(char *text,size_t capacity,const p08::BackendSummary &network,
                   bool config_known,bool http_enabled,unsigned level,
                   bool previews,const char *notice)
{
    p17c::Panel panel(text,capacity);char value[64];
    panel.line("WiC64 Log settings");
    panel.field("Capture",level_name(level));
    panel.field("Hex/ASCII",previews?"On (up to 128B)":"Off (default)");
    if(notice&&*notice)panel.line(notice);
    panel.field("Adapter",network.mac_valid?p17c::connection_name(network.selected):"Unavailable");
    if(network.mac_valid&&network.connected){
        snprintf(value,sizeof(value),"%u.%u.%u.%u",unsigned(network.ipv4[0]),unsigned(network.ipv4[1]),unsigned(network.ipv4[2]),unsigned(network.ipv4[3]));
        panel.field("Current IP",value);
    }else panel.field("Current IP","No connected adapter");
    panel.field("Web setting",!config_known?"Unavailable":http_enabled?"Enabled":"Disabled");
    panel.line("Browser: HTTP port 80");
    panel.line("/v1/machine:wic64_log_view");
    snprintf(value,sizeof(value),"PuTTY: Raw port %u",unsigned(p18log::STREAM_PORT));
    panel.line(value);
    panel.line("Use the current IP shown above.");
    panel.line("Use Ultimate network password.");
    panel.line("Enable Web in Network settings.");
    panel.line(previews&&level<2?"Use Info/Debug for packet data.":"Data: Hex/ASCII for new requests.");
    panel.line("Data may contain private content.");
    return panel.ok();
}
#if !defined(P18_LOG_ACCESS_HOST_TEST)
inline int settings(UserInterface *ui,unsigned level,bool previews,const char *notice)
{
    if(!ui||!ui->host||!ui->host->exists())return 0;
    p08::BackendSummary network={};
    if(p08::service)p08::service->get_network_summary(network);
    bool known=networkConfig.cfg!=0;
    bool http_enabled=known&&networkConfig.cfg->get_value(CFG_NETWORK_HTTP_SERVICE)!=0;
    char text[p17c::PANEL_BYTES];
    if(!format(text,sizeof(text),network,known,http_enabled,level,previews,notice))return 0;
    // Close is the safe default for Return/Space; Escape also closes.
    const char *names[]={" Close "," Level "," Data "," Clear "};
    const char keys[]={char(KEY_ESCAPE),'l','d','c'};
    return ui->popup(text,4,names,keys);
}
#endif
}
#endif
