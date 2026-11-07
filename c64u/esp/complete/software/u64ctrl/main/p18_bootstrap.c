/* Private boot-seeded DRBG for automatic WiC64 TLS setup. GPL-3.0-or-later.
 * The SAR entropy source is used only before the original power ADC and RF
 * initialize. Later requests never touch either peripheral or reuse seed bytes.
 */
#include "p18_bootstrap.h"
#include "p18_tls_wire.h"
#include "bootloader_random.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/ctr_drbg.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static mbedtls_ctr_drbg_context bootstrap_drbg;
static portMUX_TYPE bootstrap_lock=portMUX_INITIALIZER_UNLOCKED;
static bool bootstrap_attempted,bootstrap_busy,bootstrap_ready,bootstrap_capturing;
static size_t bootstrap_captured;

static void bootstrap_wipe(void *data,size_t length){volatile uint8_t *p=data;while(length--)*p++=0;}
static int bootstrap_entropy(void *unused,unsigned char *output,size_t length){
    (void)unused;
    /* 48 bytes cover the 256-bit CTR-DRBG entropy and nonce requirement in one
     * early capture. Refuse reseeding after the SAR source has been disabled. */
    if(!bootstrap_capturing||!output||!length||length>48||bootstrap_captured>48-length)
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    esp_fill_random(output,length);
    bootstrap_captured+=length;
    return 0;
}
void p18_bootstrap_early_init(void){
    portENTER_CRITICAL(&bootstrap_lock);
    if(bootstrap_attempted){portEXIT_CRITICAL(&bootstrap_lock);return;}
    bootstrap_attempted=true;bootstrap_busy=true;
    portEXIT_CRITICAL(&bootstrap_lock);

    mbedtls_ctr_drbg_init(&bootstrap_drbg);
    mbedtls_ctr_drbg_set_entropy_len(&bootstrap_drbg,48);
    static const unsigned char domain[]="Ultimate-P18-bootstrap-seed-v1";
    bootloader_random_enable();
    bootstrap_captured=0;bootstrap_capturing=true;
    int result=mbedtls_ctr_drbg_seed(&bootstrap_drbg,bootstrap_entropy,NULL,domain,sizeof(domain)-1);
    bootstrap_capturing=false;
    bootloader_random_disable();
    if(!result&&bootstrap_captured!=48)result=MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    if(result){mbedtls_ctr_drbg_free(&bootstrap_drbg);bootstrap_wipe(&bootstrap_drbg,sizeof(bootstrap_drbg));}

    portENTER_CRITICAL(&bootstrap_lock);
    bootstrap_ready=result==0;bootstrap_busy=false;
    portEXIT_CRITICAL(&bootstrap_lock);
}
uint8_t p18_bootstrap_get_seed(uint8_t output[32]){
    if(!output)return P18_TLS_FAILED;
    bootstrap_wipe(output,32);
    portENTER_CRITICAL(&bootstrap_lock);
    if(bootstrap_busy){portEXIT_CRITICAL(&bootstrap_lock);return P18_TLS_BUSY;}
    if(!bootstrap_ready){portEXIT_CRITICAL(&bootstrap_lock);return P18_TLS_FAILED;}
    bootstrap_busy=true;
    portEXIT_CRITICAL(&bootstrap_lock);

    /* No crypto, heap work or hardware entropy call while a spinlock is held.
     * State advances even if the reply is lost, so the next request is fresh. */
    int result=mbedtls_ctr_drbg_random(&bootstrap_drbg,output,32);
    if(result){
        bootstrap_wipe(output,32);
        mbedtls_ctr_drbg_free(&bootstrap_drbg);
        bootstrap_wipe(&bootstrap_drbg,sizeof(bootstrap_drbg));
    }
    portENTER_CRITICAL(&bootstrap_lock);
    if(result)bootstrap_ready=false;
    bootstrap_busy=false;
    portEXIT_CRITICAL(&bootstrap_lock);
    return result?P18_TLS_FAILED:P18_TLS_OK;
}
