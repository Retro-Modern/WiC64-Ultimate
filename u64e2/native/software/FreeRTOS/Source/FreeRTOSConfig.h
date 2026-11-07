#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* Here is a good place to include header files that are required across
your application. */
#define PRIO_BACKGROUND 0
#define PRIO_MAIN       0
#define PRIO_USERIFACE  0
#define PRIO_HW_SERVICE 1
#define PRIO_NETSERVICE 1
#define PRIO_DRIVER     1
#define PRIO_FLOPPY     1
#define PRIO_POLL       1
#define PRIO_TCPIP      2
#define PRIO_REALTIME   3

#define configUSE_PREEMPTION                    1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0
#define configUSE_TICKLESS_IDLE                 0
#define configCPU_CLOCK_HZ                      62500000
#define configTICK_RATE_HZ                      200
#define configMAX_PRIORITIES                    5
#define configMINIMAL_STACK_SIZE                1600
#if defined(P18M_INITIALIZED_ESP_HEAP) && P18M_INITIALIZED_ESP_HEAP
#if !defined(P05_RAM_DIAGNOSTIC) || !P05_RAM_DIAGNOSTIC || !defined(P18_TLS) || !P18_TLS
#error P18M initialized heap requires the reviewed RAM ESP application
#endif
#if defined(P18F_LOG_STREAM_HEAP_PROFILE) || defined(P18D_LOG_HEAP_PROFILE) || defined(P17D_FULL_SP521_PROFILE)
#error P18M and previous named heap profiles are mutually exclusive
#endif
#ifndef P18M_HEAP_BYTES
#define P18M_HEAP_BYTES 0x4E8000
#endif
#if P18M_HEAP_BYTES != 0x4E8000 && P18M_HEAP_BYTES != 0x4E4000
#error P18M requires an explicit reviewed heap size
#endif
#define configTOTAL_HEAP_SIZE P18M_HEAP_BYTES
#elif defined(P18F_LOG_STREAM_HEAP_PROFILE) && P18F_LOG_STREAM_HEAP_PROFILE
#if !defined(P05_RAM_DIAGNOSTIC) || !P05_RAM_DIAGNOSTIC || !defined(P18_LOG) || !P18_LOG
#error P18F stream heap profile requires the reviewed RAM log application
#endif
#if (defined(P18D_LOG_HEAP_PROFILE) && P18D_LOG_HEAP_PROFILE) || (defined(P17D_FULL_SP521_PROFILE) && P17D_FULL_SP521_PROFILE)
#error P18F and previous named heap profiles are mutually exclusive
#endif
// Rebudget another16KiB for the log formatter and dedicated Raw TCP access.
// Preserve the unchanged strict64KiB BSS/startup headroom guard.
#define configTOTAL_HEAP_SIZE                   0x4E8000
#elif defined(P18D_LOG_HEAP_PROFILE) && P18D_LOG_HEAP_PROFILE
#if !defined(P05_RAM_DIAGNOSTIC) || !P05_RAM_DIAGNOSTIC || !defined(P18_LOG) || !P18_LOG
#error P18D log heap profile requires the reviewed RAM log application
#endif
#if defined(P17D_FULL_SP521_PROFILE) && P17D_FULL_SP521_PROFILE
#error P18D and P17D heap profiles are mutually exclusive
#endif
// Rebudget16KiB from the previous RTOS arena for bounded RAM log support.
// The original strict64KiB BSS/startup headroom guard remains unchanged.
#define configTOTAL_HEAP_SIZE                   0x4EC000
#elif defined(P17D_FULL_SP521_PROFILE) && P17D_FULL_SP521_PROFILE
#if !defined(P05_RAM_DIAGNOSTIC) || !P05_RAM_DIAGNOSTIC
#error P17D memory profile requires the reviewed RAM application
#endif
// Rebudget64KiB from the RTOS arena to the faster portable crypto code.
// The strict image profile still reserves at least64KiB before startup SP.
#define configTOTAL_HEAP_SIZE                   0x4F0000
#elif defined(P05_RAM_DIAGNOSTIC) && P05_RAM_DIAGNOSTIC
#define configTOTAL_HEAP_SIZE                   0x500000
#else
#define configTOTAL_HEAP_SIZE                   0x800000
#endif
#define configMAX_TASK_NAME_LEN                 16
#define configUSE_16_BIT_TICKS                  0
#define configIDLE_SHOULD_YIELD                 1
#define configUSE_TASK_NOTIFICATIONS            1
#define configUSE_MUTEXES                       1
#define configUSE_RECURSIVE_MUTEXES             1
#define configUSE_COUNTING_SEMAPHORES           0
#define configUSE_ALTERNATIVE_API               0 /* Deprecated! */
#define configQUEUE_REGISTRY_SIZE               10
#define configUSE_QUEUE_SETS                    0
#define configUSE_TIME_SLICING                  1
#define configUSE_NEWLIB_REENTRANT              1
#define configENABLE_BACKWARD_COMPATIBILITY     0

/* Hook function related definitions. */
#define configUSE_IDLE_HOOK                     0
#define configUSE_TICK_HOOK                     0
#define configCHECK_FOR_STACK_OVERFLOW          0
#define configUSE_MALLOC_FAILED_HOOK            0

/* Run time and task stats gathering related definitions. */
#define configGENERATE_RUN_TIME_STATS           0
#define configUSE_TRACE_FACILITY                1 //////
#define configUSE_STATS_FORMATTING_FUNCTIONS    1 //////

/* Co-routine related definitions. */
#define configUSE_CO_ROUTINES                   0
#define configMAX_CO_ROUTINE_PRIORITIES         1

/* Software timer related definitions. */
#define configUSE_TIMERS                        1
#define configTIMER_TASK_PRIORITY               3
#define configTIMER_QUEUE_LENGTH                10
#define configTIMER_TASK_STACK_DEPTH            configMINIMAL_STACK_SIZE

/* Definitions added for RiscV. */
#define configISR_STACK_SIZE_WORDS      256
#define configMTIME_BASE_ADDRESS        ( 0 )
#define configMTIMECMP_BASE_ADDRESS     ( 0 )

/* Interrupt nesting behaviour configuration. */
#define configKERNEL_INTERRUPT_PRIORITY         0x01
#define configMAX_SYSCALL_INTERRUPT_PRIORITY    0x03
//#define configMAX_API_CALL_INTERRUPT_PRIORITY   0x03

/* Define to trap errors during development. */
void vAssertCalled( const char* fileName, uint16_t lineNo );
#define configASSERT( x )     if( ( x ) == 0 ) vAssertCalled( __FILE__, __LINE__ )

/* FreeRTOS MPU specific definitions. */
#define configINCLUDE_APPLICATION_DEFINED_PRIVILEGED_FUNCTIONS 0

/* Optional functions - most linkers will remove unused functions anyway. */
#define INCLUDE_vTaskPrioritySet                1
#define INCLUDE_uxTaskPriorityGet               1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_vTaskSuspend                    1
#define INCLUDE_xResumeFromISR                  1
#define INCLUDE_vTaskDelayUntil                 1
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_xTaskGetSchedulerState          1
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#define INCLUDE_uxTaskGetStackHighWaterMark     0
#define INCLUDE_xTaskGetIdleTaskHandle          0
#define INCLUDE_xTimerGetTimerDaemonTaskHandle  0
#define INCLUDE_pcTaskGetTaskName               0
#define INCLUDE_eTaskGetState                   0
#define INCLUDE_xEventGroupSetBitFromISR        0
#define INCLUDE_xTimerPendFunctionCall          0

/* A header file that defines trace macro can be included here. */

#include "profiler.h"
#define traceTASK_SWITCHED_OUT(x)  PROFILER_TASK = 0;
#define traceTASK_SWITCHED_IN(x)   PROFILER_TASK = pxCurrentTCB->uxTCBNumber;
//#define traceTASK_SWITCHED_IN(x)   do { PROFILER_TASK = pxCurrentTCB->uxTCBNumber; outbyte(0x40 + (pxCurrentTCB->uxTCBNumber)); } while(0);

#endif /* FREERTOS_CONFIG_H */
