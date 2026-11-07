/* Bounded sanitized classic WiC64 log API. Included by p12_routes.inc. */
#include "p18_log.h"
#include "p18_log_web.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
namespace {
struct P18LogPage {
    p18log::Snapshot *value;
    P18LogPage():value(static_cast<p18log::Snapshot *>(malloc(sizeof(p18log::Snapshot)))){}
    ~P18LogPage(){free(value);}
private:
    P18LogPage(const P18LogPage &);
    P18LogPage &operator=(const P18LogPage &);
};
enum {P18_LOG_TEXT_LIMIT=65536};
bool p18_log_decimal(const char *text,uint32_t maximum,uint32_t &out)
{
    if(!text||!*text)return false;
    uint32_t value=0;
    for(const char *p=text;*p;++p){
        if(*p<'0'||*p>'9')return false;unsigned digit=unsigned(*p-'0');
        if(value>maximum/10||(value==maximum/10&&digit>maximum%10))return false;
        value=value*10+digit;
    }
    out=value;return true;
}
// The pinned native JSON_String renderer writes its value verbatim between
// quotes. Escape formatter strings here once; clients receive the exact ASCII.
bool p18_log_json_escape(const char *line,unsigned length,char *out,unsigned capacity)
{
    unsigned used=0;
    for(unsigned i=0;i<length;++i){
        unsigned char ch=static_cast<unsigned char>(line[i]);
        if(ch<0x20||ch>0x7e)return false;
        if(ch=='"'||ch=='\\'){if(used+1>=capacity)return false;out[used++]='\\';}
        if(used+1>=capacity)return false;out[used++]=char(ch);
    }
    if(used>=capacity)return false;out[used]=0;return true;
}
void p18_log_no_cache(ResponseWrapper *response)
{
    // The existing JSON wrapper has already written its final blank line.
    // Its fixed header is <160 bytes; the native HTTP buffer is 1024 bytes.
    static const char headers[]="Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n";
    unsigned size=unsigned(response->resp->_index);
    if(size>=2&&size-2+sizeof(headers)<=HTTP_BUFFER_SIZE){
        memcpy(response->resp->_buf+size-2,headers,sizeof(headers));
        response->resp->_index=int(size-2+sizeof(headers)-1);
    }
}
void p18_log_json_response(ResponseWrapper *response,int code)
{response->json_response(code);p18_log_no_cache(response);}
void p18_log_error(ResponseWrapper *response,int code,const char *message)
{response->error("%s",message);p18_log_json_response(response,code);}
void p18_log_stream_response(ResponseWrapper *response,StreamRamFile *stream,const char *type,bool download=false,bool html=false)
{
    // All header values are fixed internal constants, never request values.
    StreamTextLog header(HTTP_BUFFER_SIZE,reinterpret_cast<char *>(response->resp->_buf));
    header.format("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: %s\r\n",type);
    header.format("Content-Length: %d\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n",stream->getLength());
    if(download)header.format("Content-Disposition: attachment; filename=\"wic64-log.txt\"\r\n");
    if(html)header.format("Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n");
    header.format("\r\n");response->resp->_index=header.getLength();
    response->resp->BodyContext=stream;response->resp->BodyCB=&ResponseWrapper::stream_body;
    response->attachment=0; // HTTP BodyCB now owns the bounded body.
}
JSON_Object *p18_log_meta(ResponseWrapper *response,const p18log::Snapshot &s)
{
    JSON_Object *out=JSON::Obj();response->json->add("wic64_log",out);
    out->add("contract","U64-WIC64-LOG-2")->add("schema",2)->add("generation",int(s.generation))
        ->add("next_after",int(s.next_after))->add("oldest_seq",int(s.oldest_seq))->add("newest_seq",int(s.newest_seq))
        ->add("dropped",int(s.dropped))->add("overwritten",int(s.overwritten))->add("level",int(s.level))
        ->add("reset",s.reset)->add("more",s.more)->add("available",s.available)->add("previews_enabled",s.previews_enabled)->add("capacity",int(p18log::CAPACITY))
        ->add("page_size",int(p18log::PAGE_SIZE))->add("line_capacity",int(p18log::LINE_CAPACITY))
        ->add("max_record_lines",int(p18log::MAX_RECORD_LINES));
    return out;
}
}
API_DOC(GET,machine,wic64_log,
    TAG("WiC64") SUMMARY("Read a bounded page of classic sanitized WiC64 log records")
    PATH("/v1/machine:wic64_log","wic64Log","")
    PARAM("generation","integer","Cursor generation; zero starts from oldest retained entry.","0","1")
    PARAM("after","integer","Read entries after this sequence in the matching generation.","0","0")
    PARAM("limit","integer(1..8)","Maximum records.","8","8")
    RESPONSE("200","application/json","","Sanitized classic lines, semantic colors and cursor metadata; packet samples are bounded and protected values are redacted.","")
)
API_CALL(GET,machine,wic64_log,NULL,ARRAY({{"generation",P_OPTIONAL},{"after",P_OPTIONAL},{"limit",P_OPTIONAL}}))
{
    uint32_t generation=0,after=0,limit=p18log::PAGE_SIZE;
    if((args["generation"]&&!p18_log_decimal(args["generation"],0x7fffffffU,generation))||
       (args["after"]&&!p18_log_decimal(args["after"],0x7fffffffU,after))||
       (args["limit"]&&!p18_log_decimal(args["limit"],p18log::PAGE_SIZE,limit))||!limit||(!generation&&after)){
        p18_log_error(resp,HTTP_BAD_REQUEST,"Invalid log cursor or limit.");return;
    }
    P18LogPage storage;
    if(!storage.value){p18_log_error(resp,HTTP_SERVICE_UNAVAILABLE,"Log page allocation failed; retry.");return;}
    p18log::Snapshot &snapshot=*storage.value;
    if(!p18log::snapshot(generation,after,uint8_t(limit),snapshot)){
        p18_log_error(resp,HTTP_LOCKED,"Log is busy; retry this read.");return;
    }
    JSON_List *events=JSON::List();p18_log_meta(resp,snapshot)->add("entries",events);
    for(unsigned i=0;i<snapshot.count;++i){
        const p18log::Entry &e=snapshot.entries[i];
        JSON_Object *entry=JSON::Obj();events->add(entry);
        JSON_List *lines=JSON::List();entry->add("lines",lines);
        for(unsigned row=0;row<p18log::MAX_RECORD_LINES;++row){
            char line[p18log::LINE_CAPACITY];unsigned size=p18log::format_record(e,row,line,sizeof(line));
            if(size>=sizeof(line)){p18_log_error(resp,HTTP_INTERNAL_SERVER_ERROR,"Log formatting failed.");return;}
            if(!size)break;
            char escaped[p18log::LINE_CAPACITY*2];
            if(!p18_log_json_escape(line,size,escaped,sizeof(escaped))){p18_log_error(resp,HTTP_INTERNAL_SERVER_ERROR,"Log formatting failed.");return;}
            lines->add(escaped);
        }
        entry->add("seq",int(e.seq))->add("tick_ms",int(e.tick_ms))->add("request_id",int(e.request_id))
            ->add("command",int(e.command))->add("protocol",int(e.protocol))->add("event",int(e.event))->add("phase",int(e.phase))
            ->add("lifecycle",int(e.lifecycle))->add("status",int(e.status))->add("error",int(e.error))->add("level",int(e.level))
            ->add("http_status",int(e.http_status))->add("length",int(e.length))->add("elapsed_ms",int(e.elapsed_ms))
            ->add("tls_tx",int(e.tls_tx))->add("tls_rx",int(e.tls_rx))->add("engine_error",int(e.engine_error))
            ->add("color",int(p18log::record_color(e)));
    }
    p18_log_json_response(resp,HTTP_OK);
}
API_DOC(GET,machine,wic64_log_text,
    TAG("WiC64") SUMMARY("Download the bounded retained classic sanitized WiC64 log")
    PATH("/v1/machine:wic64_log_text","wic64LogText","")
    RESPONSE("200","text/plain","","Bounded text download; no C64 pause or log mutation.","")
)
API_CALL(GET,machine,wic64_log_text,NULL,ARRAY({}))
{
    P18LogPage storage;
    if(!storage.value){p18_log_error(resp,HTTP_SERVICE_UNAVAILABLE,"Log page allocation failed; retry.");return;}
    p18log::Snapshot &page=*storage.value;uint32_t generation=0,after=0,ceiling=0;unsigned total=0;bool capped=false;
    StreamRamFile *text=resp->add_attachment();
    text->format("WiC64: log - classic diagnostics; protected values redacted\n");
    for(unsigned chunk=0;chunk<p18log::CAPACITY/p18log::PAGE_SIZE;++chunk){
        if(!p18log::snapshot(generation,after,p18log::PAGE_SIZE,page)){
            p18_log_error(resp,HTTP_LOCKED,"Log is busy; retry this download.");return;
        }
        if(!chunk){generation=page.generation;ceiling=page.newest_seq;
            text->format("WiC64: generation=%u dropped=%u overwritten=%u\n",generation,page.dropped,page.overwritten);
        }else if(page.generation!=generation||page.reset){
            p18_log_error(resp,HTTP_CONFLICT,"Log changed during download; retry.");return;
        }
        for(unsigned i=0;i<page.count&&total<p18log::CAPACITY;++i){
            if(page.entries[i].seq>ceiling)break;
            for(unsigned row=0;row<p18log::MAX_RECORD_LINES;++row){
                char line[p18log::LINE_CAPACITY];unsigned length=p18log::format_record(page.entries[i],row,line,sizeof(line));
                if(length>=sizeof(line)){p18_log_error(resp,HTTP_INTERNAL_SERVER_ERROR,"Log formatting failed.");return;}
                if(!length)break;
                // Reserve room for a truthful cap marker within the 64 KiB export.
                if(unsigned(text->getLength())+length+1>P18_LOG_TEXT_LIMIT-128){capped=true;break;}
                text->write(reinterpret_cast<uint8_t *>(line),int(length));text->format("\n");
            }
            ++total;after=page.entries[i].seq;if(capped)break;
        }
        if(capped||after>=ceiling||!ceiling)break;
        if(!page.count||chunk+1==p18log::CAPACITY/p18log::PAGE_SIZE){
            p18_log_error(resp,HTTP_CONFLICT,"Log changed during download; retry.");return;
        }
    }
    if(capped)text->format("WiC64: ... (text export capped at 65536 bytes; remaining retained log lines omitted)\n");
    p18_log_stream_response(resp,text,"text/plain; charset=utf-8",true);
}
API_DOC(PUT,machine,wic64_log_control,
    TAG("WiC64") SUMMARY("Explicitly set log level, application data previews or clear the RAM log")
    PATH("/v1/machine:wic64_log_control","wic64LogControl","")
    PARAM("level","string","off, error, info or debug.","","info")
    PARAM("clear","integer(0..1)","Clear retained entries only when one.","0","1")
    PARAM("previews","integer(0..1)","Explicit application data previews; default off. Protected values remain redacted.","0","0")
    RESPONSE("200","application/json","","Atomic control; entries stay in RAM. The ESP storage profile persists level and preview preferences.","")
)
API_CALL(PUT,machine,wic64_log_control,NULL,ARRAY({{"level",P_OPTIONAL},{"clear",P_OPTIONAL},{"previews",P_OPTIONAL}}))
{
    const char *level=args["level"],*clear=args["clear"],*previews=args["previews"];uint32_t erase=0,preview_value=0;
    int selected=level&&!strcmp(level,"off")?0:level&&!strcmp(level,"error")?1:
        level&&!strcmp(level,"info")?2:level&&!strcmp(level,"debug")?3:-1;
    if((!level&&!clear&&!previews)||(level&&selected<0)||(clear&&!p18_log_decimal(clear,1,erase))||
       (previews&&!p18_log_decimal(previews,1,preview_value))){
        p18_log_error(resp,HTTP_BAD_REQUEST,"Invalid log level, clear or preview value.");return;
    }
    if(!p18log::control(level!=0,p18log::Level(selected<0?0:selected),erase!=0,previews!=0,preview_value!=0)){
        p18_log_error(resp,HTTP_LOCKED,"Log is busy; control was not applied.");return;
    }
    resp->json->add("wic64_log",JSON::Obj()->add("level",int(p18log::level()))->add("cleared",erase!=0)->add("previews_enabled",p18log::previews_enabled()));
    p18_log_json_response(resp,HTTP_OK);
}
API_DOC(GET,machine,wic64_log_view,
    TAG("WiC64") SUMMARY("Open the static WiC64 log viewer")
    PATH("/v1/machine:wic64_log_view","wic64LogView","")
    RESPONSE("200","text/html","","Public static shell; every data/control request requires the normal network password.","")
)
API_CALL(GET,machine,wic64_log_view,NULL,ARRAY({}))
{
    StreamRamFile *page=resp->add_attachment();
    page->write(reinterpret_cast<uint8_t *>(const_cast<char *>(p18_log_web)),sizeof(p18_log_web)-1);
    p18_log_stream_response(resp,page,"text/html; charset=utf-8",false,true);
}
