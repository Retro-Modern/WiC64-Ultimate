/* Explicit application-service lifecycle; session ownership is external. */
#include "p08_service.h"
namespace {
void p08_hex(const uint8_t *bytes,unsigned length,char *out)
{
    static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<length;i++){out[2*i]=digits[bytes[i]>>4];out[2*i+1]=digits[bytes[i]&15];}out[2*length]=0;
}
bool p08_session_arg(const char *text,uint8_t session[8])
{
    if(!text || strlen(text)!=16)return false;
    for(unsigned i=0;i<8;i++) {
        uint8_t a=chartohex(text[2*i]),b=chartohex(text[2*i+1]);
        if(a>15 || b>15)return false;session[i]=(a<<4)|b;
    }
    return p08::nonzero(session,8);
}
JSON_Object *p08_json(ResponseWrapper *resp)
{
    JSON_Object *out=JSON::Obj();out->add("contract","P08-SERVICE-1")->add("schema",1);
    resp->json->add("p08",out);return out;
}
void p08_error(ResponseWrapper *resp,p08::Result result)
{
    JSON_Object *out=p08_json(resp);out->add("published",false)->add("acknowledged",false)->add("result",p08::result_name(result));
    resp->error("P08 %s",p08::result_name(result));
    int code=result==p08::BUSY?HTTP_LOCKED:result==p08::BAD_PARAMETER?HTTP_BAD_REQUEST:result==p08::NO_DRIVE?HTTP_SERVICE_UNAVAILABLE:HTTP_CONFLICT;
    resp->json_response(code);
}
void p08_mutation(ResponseWrapper *resp,const char *text,bool start)
{
    uint8_t session[8];
    if(!p08_session_arg(text,session)){p08_error(resp,p08::BAD_PARAMETER);return;}
    if(!p08::service){p08_error(resp,p08::NO_DRIVE);return;}
    p08::Result result=start?p08::service->request_start(session):p08::service->request_stop(session);
    if(result!=p08::OK){p08_error(resp,result);return;}
    char nonce[17];p08_hex(session,8,nonce);
    p08_json(resp)->add("published",true)->add("acknowledged",false)->add("result","QUEUED")
        ->add("state",start?"STARTING":"STOPPING")->add("session_hex",nonce);
    resp->json_response(HTTP_OK);
}
}
API_DOC(GET,machine,p08_status,
    TAG("WiC64") SUMMARY("Read P08 WiC64 application service state")
    DESCRIPTION("Returns the service lifecycle, immutable session, counters and last stable drive/firmware mailbox snapshots. The initial response uses bounded RWSEQ/Ultimax CIA snapshots. Refills continue that receive grant without fresh PA2 sampling. No C64 RAM header is required. Only present in P08_SERVICE builds.")
    PATH("/v1/machine:p08_status","p08Status","")
    RESPONSE("200","application/json","","P08-SERVICE-1 state and evidence.","")
    RESPONSE_ERROR("423","Service state lock busy","")
)
API_CALL(GET,machine,p08_status,NULL,ARRAY({ }))
{
    if(!p08::service){p08_error(resp,p08::NO_DRIVE);return;}
    p08::Status s={};if(!p08::service->get_status(s)){p08_error(resp,p08::BUSY);return;}
    char nonce[17],d[129],h[129];p08_hex(s.session,8,nonce);p08_hex(s.mailbox.d,64,d);p08_hex(s.mailbox.h,64,h);
    JSON_Object *out=p08_json(resp);
    out->add("state",p08::state_name(s.state))->add("session_hex",nonce)
       ->add("helper_sha256",s.helper_sha256)->add("sample_method","RWSEQ_ULTIMAX_IO")
       ->add("probe_armed",s.probe_armed)->add("application_mode",true)->add("idle_timeout_ms",0)
       ->add("stream_method","FULL_RESPONSE_CACHE_DRIVE_WINDOWS")->add("request_capacity",8192)->add("response_capacity",65536)
       ->add("refill_sample_method","INITIAL_RECEIVE_GRANT_NO_NEW_SAMPLE")
       ->add("last_error",s.last_error)->add("drive_mailbox_hex",d)->add("firmware_mailbox_hex",h)
       ->add("pending_request_id",int(p08::u32(s.mailbox.d+20)))
       ->add("last_stop_ms",int(s.last_stop_ms))
       ->add("heap_free_bytes",int(xPortGetFreeHeapSize()))->add("heap_min_free_bytes",int(xPortGetMinimumEverFreeHeapSize()));
    out->add("helper_diagnostics",JSON::Obj()->add("guard_mask",int(s.helper_guard_mask))
       ->add("previous_sequence",int(s.helper_previous_sequence))->add("previous_request",int(s.helper_previous_request))
       ->add("previous_drive_request",int(s.helper_previous_drive_request))->add("work_request",int(s.helper_work_request))
       ->add("endpoint_resets",int(s.endpoint_resets)));
    out->add("counters",JSON::Obj()->add("requests",int(s.requests))->add("responses",int(s.responses))
       ->add("pa2_samples",int(s.pa2_samples))->add("http_requests",int(s.http_requests))
       ->add("http_success",int(s.http_success))->add("http_errors",int(s.http_errors))->add("http_last_status",int(s.http_last_status)));
    out->add("stream",JSON::Obj()->add("request_bytes",int(s.request_bytes))->add("response_bytes",int(s.response_bytes))
       ->add("rx_chunks",int(s.rx_chunks))->add("tx_chunks",int(s.tx_chunks))->add("tx_refills",int(s.tx_refills))
       ->add("last_tx_offset",int(s.last_tx_offset))->add("tx_consumed_bytes",int(s.tx_consumed_bytes))
       ->add("request_cache_length",int(s.request_cache_length))->add("response_cache_length",int(s.response_cache_length))
       ->add("peak_response_bytes",int(s.peak_response_bytes)));
    out->add("restore",JSON::Obj()->add("status",p08::restore_name(s.restore))->add("rom_verified",s.rom_verified)
       ->add("metadata_verified",s.metadata_verified)->add("settings_verified",s.settings_verified)
       ->add("settings_verification","CONFIG_READBACK_AND_DERIVED_REGISTER_WRITES"));
    resp->json_response(HTTP_OK);
}
API_DOC(POST,machine,p08_start,
    TAG("WiC64") SUMMARY("Queue an integrated P08 session")
    DESCRIPTION("Queues a fresh nonzero session. The service journals and temporarily replaces empty 1541 Drive A; Drive B may already have media and is never mutated. It enables the parallel cable and normal speed in RAM, and validates its embedded helper boot. HTTP 200 is queue acknowledgement only; poll p08_status for ACTIVE. Never blindly retry a lost mutation response.")
    PATH("/v1/machine:p08_start","p08Start","")
    PARAM("session","string","Exactly 16 hexadecimal digits; eight nonzero-as-a-group bytes.","","0102030405060708")
    RESPONSE("200","application/json","","Queued STARTING; helper readiness is reported by GET.","")
    RESPONSE_ERROR("409","State/session precondition failed","") RESPONSE_ERROR("423","Service lock busy before mutation","")
)
API_CALL(POST,machine,p08_start,NULL,ARRAY({ {"session",P_REQUIRED} }))
{p08_mutation(resp,args["session"],true);}
API_DOC(POST,machine,p08_stop,
    TAG("WiC64") SUMMARY("Queue restoration of the owned P08 session")
    DESCRIPTION("Stops new requests for the matching session. After any bounded HTTP call returns, the service restores its exact 32-KiB Drive-A ROM backup and original metadata/power/settings. Poll GET for RESTORED and separate verification flags. The RAM firmware remains loaded until powercycle. Foreign global settings changes are not overwritten.")
    PATH("/v1/machine:p08_stop","p08Stop","")
    PARAM("session","string","The currently owned eight-byte session as 16 hex digits.","","0102030405060708")
    RESPONSE("200","application/json","","Queued STOPPING; restoration is reported by GET.","")
    RESPONSE_ERROR("409","State/session precondition failed","") RESPONSE_ERROR("423","Service lock busy before mutation","")
)
API_CALL(POST,machine,p08_stop,NULL,ARRAY({ {"session",P_REQUIRED} }))
{p08_mutation(resp,args["session"],false);}

#include "p12_routes.inc"
