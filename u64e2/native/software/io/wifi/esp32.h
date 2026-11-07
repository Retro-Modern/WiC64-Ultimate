/*
 * esp32.h
 *
 *  Created on: Sep 2, 2018
 *      Author: gideon
 */
#ifndef ESP32_H_
#define ESP32_H_

#include "dma_uart.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "menu.h"

extern "C" {
    #include "cmd_buffer.h"
}

#if U64 == 2
#   define ESP_MODE_OFF       3
#   define ESP_MODE_RUN       0
#   define ESP_MODE_RUN_MODE  2
#   define ESP_MODE_BOOT      1
#   define ESP_MODE_RUN_UART  4
#   define ESP_MODE_BOOT_UART 5
#else
#   define ESP_MODE_OFF       0
#   define ESP_MODE_RUN_MODE  1
#   define ESP_MODE_RUN       3
#   define ESP_MODE_BOOT      2
#   define ESP_MODE_RUN_UART  7
#   define ESP_MODE_BOOT_UART 6
#endif
typedef void (*EspDownloadCallback_t)(void *context);
// Supply authenticated bytes for this block, or return false before it is sent.
typedef bool (*EspReadCallback_t)(void *context, uint8_t *dest, uint32_t offset, uint32_t length);

class Esp32Application
{
public:
    Esp32Application() {}
    virtual ~Esp32Application() {}
    virtual void Init(DmaUART *uart, command_buf_context_t *packets) {}
    virtual void Start() {}
    virtual void Terminate() {}
};

class Esp32
{
    SemaphoreHandle_t rxSemaphore;
    QueueHandle_t commandQueue;
    command_buf_context_t *packets;
    Esp32Application *registered_app;
    Esp32Application *application;
    bool doClose;
    bool programError;
    bool running;

    void Disable();
    void Boot();
    void PackParams(uint8_t *buffer, int numparams, ...);
    bool Command(uint8_t opcode, uint16_t length, uint8_t chk, uint8_t *data, uint8_t *receiveBuffer, int timeout);
public:
    static const uint32_t FLASH_BLOCK_BYTES = 0x400;
    Esp32();
    void Quit();
    int  Download(void); // Switch to download mode and setup flash
    int  Flash(const uint8_t *binary, uint32_t address, uint32_t length, EspDownloadCallback_t callback, void *context);
    int  FlashFrom(EspReadCallback_t read, void *read_context, uint32_t address, uint32_t length, EspDownloadCallback_t callback, void *context);
    void AttachApplication(Esp32Application *app);

    DmaUART *uart;
    void ReadRxMessage(void);
    int  DetectModule(void *buffer, int buffer_len);
    void EnableRunMode();
    void StartApp();
    void StopApp();
    bool isRunning() {
        return running;
    }
#ifdef NO_ESP
    friend class U64Config; // Only for the RF test version
#endif
};

extern Esp32 esp32;

#endif /* ESP32_H_ */
