#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "network_config.h"
#include "rtc.h"
#if U64 && P08_SERVICE
#include "p14_platform.h"
#endif

extern "C" {
    #include "lwip/apps/sntp.h"

    void sntp_time_received(uint32_t sec)
    {
        printf("--> Time Received: %u  (current TZ = %s)\n", sec, getenv("TZ"));
#if U64 && P08_SERVICE
        uint32_t prewrite_utc=0;
        bool prewrite_valid=p14::utc_snapshot(prewrite_utc);
#endif
        rtc.set_time_utc(sec);
#if U64 && P08_SERVICE
        // Only an actual native SNTP callback marks TLS time as synchronized.
        // Publish after the hardware UTC write so readers never see a new
        // anchor paired with the old RTC value. SNTP is not authenticated.
        p14::note_sntp(sec,prewrite_utc,prewrite_valid);
#endif
    }
}

void start_sntp(void)
{
    sntp_stop();
    if (networkConfig.cfg->get_value(CFG_NETWORK_NTP_EN) == 0) {
        return;
    }
    const char *timezone = networkConfig.get_posix_timezone();
    printf("Setting timezone: %s\n", timezone);
    setenv("TZ", timezone, 1);
    tzset();
    sntp_setservername(0, networkConfig.cfg->get_string(CFG_NETWORK_NTP_SRV1));
    sntp_setservername(1, networkConfig.cfg->get_string(CFG_NETWORK_NTP_SRV2));
    sntp_setservername(2, networkConfig.cfg->get_string(CFG_NETWORK_NTP_SRV3));
    sntp_init();
}

