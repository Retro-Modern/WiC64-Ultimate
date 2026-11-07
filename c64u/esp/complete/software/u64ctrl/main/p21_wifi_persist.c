#include "p21_wifi_persist.h"
#include "nvs.h"
#include <string.h>

static void wipe(void *ptr, size_t size)
{
    volatile uint8_t *bytes = ptr;
    while (size--) *bytes++ = 0;
}

esp_err_t p21_wifi_store_verified(const char *ssid, const char *password,
                                 uint8_t auth, int16_t *index)
{
    if (!ssid || !password || !index || !ssid[0] ||
        strnlen(ssid, 32) == 32 || strnlen(password, 64) == 64 || auth > 7)
        return ESP_ERR_INVALID_ARG;
    nvs_handle_t handle;
    esp_err_t err = nvs_open("recent_aps", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    int slot = -1, empty = -1;
    char key[4] = {'s', 'a', '0', 0}, saved_ssid[32] = {0};
    for (int i = 0; i < 16; ++i) {
        key[1] = 'a' + i;
        size_t length = sizeof(saved_ssid);
        err = nvs_get_str(handle, key, saved_ssid, &length);
        if (err == ESP_OK) {
            if (!strcmp(saved_ssid, ssid)) { slot = i; break; }
        } else if (err == ESP_ERR_NVS_NOT_FOUND) {
            if (empty < 0) empty = i;
        } else {
            nvs_close(handle);
            return err; /* Corrupt/oversize data is not an unused slot. */
        }
    }
    if (slot < 0) slot = empty >= 0 ? empty : 0;
    key[1] = 'a' + slot;
    key[0] = 's'; err = nvs_set_str(handle, key, ssid);
    if (err == ESP_OK) { key[0] = 'p'; err = nvs_set_str(handle, key, password); }
    if (err == ESP_OK) { key[0] = 'm'; err = nvs_set_u8(handle, key, auth); }
    if (err == ESP_OK) err = nvs_set_i8(handle, "last", (int8_t)slot);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) return err;

    /* A fresh handle and full values, rather than commit() alone, establish
     * the final reply. Do not retry partial writes or substitute RAM success. */
    err = nvs_open("recent_aps", NVS_READONLY, &handle);
    if (err != ESP_OK) return err;
    char saved_password[64] = {0};
    uint8_t saved_auth = 0;
    int8_t saved_last = -1;
    size_t length = sizeof(saved_ssid);
    key[0] = 's'; err = nvs_get_str(handle, key, saved_ssid, &length);
    if (err == ESP_OK && strcmp(saved_ssid, ssid)) err = ESP_FAIL;
    length = sizeof(saved_password);
    if (err == ESP_OK) { key[0] = 'p'; err = nvs_get_str(handle, key, saved_password, &length); }
    if (err == ESP_OK && strcmp(saved_password, password)) err = ESP_FAIL;
    if (err == ESP_OK) { key[0] = 'm'; err = nvs_get_u8(handle, key, &saved_auth); }
    if (err == ESP_OK && saved_auth != auth) err = ESP_FAIL;
    if (err == ESP_OK) err = nvs_get_i8(handle, "last", &saved_last);
    if (err == ESP_OK && saved_last != slot) err = ESP_FAIL;
    nvs_close(handle);
    wipe(saved_password, sizeof(saved_password));
    if (err == ESP_OK) *index = slot;
    return err;
}

esp_err_t p21_wifi_forget_verified(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open("recent_aps", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_erase_all(handle);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) return err;
    err = nvs_open("recent_aps", NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t used = 0;
    err = nvs_get_used_entry_count(handle, &used);
    nvs_close(handle);
    return err != ESP_OK ? err : used == 0 ? ESP_OK : ESP_FAIL;
}
