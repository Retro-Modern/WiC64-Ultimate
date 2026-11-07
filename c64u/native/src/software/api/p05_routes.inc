/* Included by route_machine.cc only in explicitly enabled diagnostic builds. */
#include "c1541.h"
#include "u64_machine.h"

namespace {
volatile bool p05_operation_active = false;
class P05Operation {
    bool owned;
public:
    P05Operation() {
        portENTER_CRITICAL();
        owned = !p05_operation_active;
        if (owned) p05_operation_active = true;
        portEXIT_CRITICAL();
    }
    ~P05Operation() {
        if (owned) {
            portENTER_CRITICAL();
            p05_operation_active = false;
            portEXIT_CRITICAL();
        }
    }
    bool acquired() const { return owned; }
};

void p05_hex(const uint8_t *source, unsigned count, char *destination)
{
    const char *hex = "0123456789abcdef";
    for (unsigned n = 0; n < count; ++n) {
        destination[n*2] = hex[source[n] >> 4];
        destination[n*2+1] = hex[source[n] & 15];
    }
    destination[count*2] = 0;
}

JSON_Object *p05_response(ResponseWrapper *resp)
{
    JSON_Object *out = JSON::Obj();
    out->add("contract", "P05-MAILBOX-1")->add("schema", 1)->add("enabled", true)
       ->add("heap_free_bytes", int(xPortGetFreeHeapSize()))
       ->add("heap_min_free_bytes", int(xPortGetMinimumEverFreeHeapSize()));
    resp->json->add("p05", out);
    return out;
}

void p05_drive_json(JSON_Object *out, p05::Result result, const p05::Snapshot &s)
{
    JSON_Object *drive = JSON::Obj();
    drive->add("valid", result == p05::OK)->add("read_status", p05::result_name(result));
    if (result == p05::OK) {
        char session[17], raw[129];
        p05_hex(s.drive+8, 8, session);
        uint8_t both[64];
        memcpy(both, s.drive, 32); memcpy(both+32, s.host, 32);
        p05_hex(both, 64, raw);
        drive->add("state", int(s.drive[5]))->add("sequence", int(s.drive[6]))
             ->add("last_error", int(s.drive[7]))->add("session_hex", session)
             ->add("request_id", int(p05::u32(s.drive+16)))
             ->add("ack_id", int(p05::u32(s.drive+20)))
             ->add("pra", int(s.drive[24]))->add("ddra", int(s.drive[25]))
             ->add("ddrb", int(s.drive[26]))->add("outcome", int(s.drive[27]))
             ->add("accepted_count", int(p05::u16(s.drive+28)))
             ->add("rejected_count", int(s.drive[30]))->add("raw_hex", raw);
    }
    out->add("drive", drive);
}

int p05_http(p05::Result result)
{
    if (result == p05::BUSY) return HTTP_LOCKED;
    if (result == p05::NO_DRIVE || result == p05::LOW_MEMORY) return HTTP_SERVICE_UNAVAILABLE;
    if (result == p05::BAD_PARAMETER) return HTTP_BAD_REQUEST;
    if (result == p05::STOP_TIMEOUT || result == p05::TIMER_FAILURE) return HTTP_GATEWAY_TIMEOUT;
    return HTTP_CONFLICT;
}

void p05_failure(ResponseWrapper *resp, JSON_Object *out, p05::Result result)
{
    out->add("published", false)->add("result", p05::result_name(result));
    resp->error("P05 %s", p05::result_name(result));
    resp->json_response(p05_http(result));
}

bool p05_session(const char *text, uint8_t session[8])
{
    if (!text || strlen(text) != 16) return false;
    for (unsigned n = 0; n < 8; ++n) {
        uint8_t a = chartohex(text[2*n]), b = chartohex(text[2*n+1]);
        if (a > 15 || b > 15) return false;
        session[n] = (a << 4) | b;
    }
    return p05::nonzero(session, 8);
}
}

API_DOC(GET, machine, p05_status,
    TAG("Diagnostics")
    SUMMARY("Read experimental P05 capability and fixed Drive A mailbox")
    DESCRIPTION("Only present in a P05_MAILBOX_DIAGNOSTIC build. Reads the fixed "
                "64-byte P05 mailbox; never accepts an arbitrary address. A valid "
                "capability is returned even when no P05 ROM is running. No writes.")
    PATH("/v1/machine:p05_status", "p05Status", "")
    RESPONSE("200", "application/json", "", "Capability and optional mailbox snapshot.", "")
)
API_CALL(GET, machine, p05_status, NULL, ARRAY({ }))
{
    p05::Snapshot snapshot = {};
    p05::Result result = c1541_A ? c1541_A->p05_snapshot(snapshot) : p05::NO_DRIVE;
    JSON_Object *out = p05_response(resp);
    p05_drive_json(out, result, snapshot);
    resp->json_response(HTTP_OK);
}

API_DOC(POST, machine, p05_probe,
    TAG("Diagnostics")
    SUMMARY("Publish one controlled P05 attach or PA2 sample")
    DESCRIPTION("Only present in an explicit diagnostic build. Requires the matching "
                "P05 drive ROM and, for sample, the matching C64 test program in its "
                "holding phase. Session is sixteen hexadecimal digits in RAM byte "
                "order. HTTP 200 confirms publication, not drive acknowledgement or "
                "test success. Read p05_status for the matching acknowledgement. "
                "Never retry a lost mutating response without first reading status.")
    PATH("/v1/machine:p05_probe", "p05Probe", "")
    PARAM("action", "string", "attach or sample", "", "sample")
    PARAM("session", "string", "Sixteen hexadecimal digits; nonzero", "", "0102030405060708")
    PARAM("request", "string", "Sample number 1..4; omitted or 0 for attach", "", "1")
    RESPONSE("200", "application/json", "", "Command published; drive acknowledgement pending.", "")
    RESPONSE_ERROR("409", "P05 STALE", "")
    RESPONSE_ERROR("423", "P05 BUSY", "")
    RESPONSE_ERROR("504", "P05 STOP_TIMEOUT", "")
)
API_CALL(POST, machine, p05_probe, NULL,
         ARRAY({ {"action", P_REQUIRED}, {"session", P_REQUIRED}, {"request", P_OPTIONAL} }))
{
    JSON_Object *out = p05_response(resp);
    uint8_t session[8];
    const char *action = args["action"], *number = args["request"];
    bool attach = action && !strcmp(action, "attach");
    bool sample = action && !strcmp(action, "sample");
    uint32_t request = 0;
    if ((!attach && !sample) || !p05_session(args["session"], session) ||
        (attach && number && strcmp(number, "0")) ||
        (sample && (!number || strlen(number) != 1 || number[0] < '1' || number[0] > '4'))) {
        p05_failure(resp, out, p05::BAD_PARAMETER); return;
    }
    if (sample) request = number[0] - '0';
    if (xPortGetFreeHeapSize() < 256U * 1024U) {
        p05_failure(resp, out, p05::LOW_MEMORY); return;
    }
    P05Operation operation;
    if (!operation.acquired()) { p05_failure(resp, out, p05::BUSY); return; }
    if (!c1541_A) { p05_failure(resp, out, p05::NO_DRIVE); return; }
    p05::Snapshot before = {};
    p05::Result result = c1541_A->p05_snapshot(before);
    if (result != p05::OK) { p05_failure(resp, out, result); return; }
    uint8_t command[32];
    if (!p05::prepare(before, attach, session, request, command)) {
        p05_failure(resp, out, p05::STALE); return;
    }
    p05::Measurement measurement = {};
    if (sample) {
        if (!c64_subsys || !c64_subsys->p05_try_lock()) {
            p05_failure(resp, out, p05::BUSY); return;
        }
        U64Machine *machine = static_cast<U64Machine *>(C64::getMachine());
        result = machine->p05_measure(session, request, measurement);
        c64_subsys->unlock();
        if (result != p05::OK) { p05_failure(resp, out, result); return; }
        command[16] = measurement.pra;
        command[17] = measurement.ddra;
        command[18] = measurement.ddrb;
        command[19] = p05::outcome(measurement.pra, measurement.ddra, measurement.ddrb);
    }
    result = c1541_A->p05_publish(before, command, sample ? &measurement : NULL);
    if (result != p05::OK) { p05_failure(resp, out, result); return; }
    char session_hex[17], command_hex[65];
    p05_hex(session, 8, session_hex); p05_hex(command, 32, command_hex);
    out->add("published", true)->add("acknowledged", false)->add("result", "PUBLISHED")
       ->add("action", action)->add("session_hex", session_hex)->add("request_id", int(request))
       ->add("command_hex", command_hex);
    if (sample) {
        out->add("measurement", JSON::Obj()->add("pra", int(measurement.pra))
           ->add("ddra", int(measurement.ddra))->add("ddrb", int(measurement.ddrb))
           ->add("outcome", int(command[19]))->add("stop_ms", int(measurement.stop_ms)));
    }
    resp->json_response(HTTP_OK);
}
