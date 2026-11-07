#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"

#include "itu.h"
#include "syslog.h"
#include "c64.h"
#include "c64_subsys.h"
#include "screen.h"
#include "keyboard.h"
#include "userinterface.h"
#include "tree_browser.h"
#include "browsable_root.h"
#include "filemanager.h"
#include "config.h"
#include "path.h"
#include "rtc.h"
#include "stream.h"
#include "host_stream.h"
#include "ui_stream.h"
#include "stream_menu.h"
#include "overlay.h"
#include "init_function.h"
#include "stream_uart.h"
#include "stream_textlog.h"
#include "dump_hex.h"
#include "usb_base.h"
#include "home_directory.h"
#include "u2p.h"
#include "u64.h"
#include "keyboard_usb.h"
#include "i2c_drv.h"
#include "product.h"
#include "main_menu.h"

#if defined(C64U_BOOT_TRACE) && C64U_BOOT_TRACE
#include <stdint.h>
#include "c64u_boot_trace.h"
#define C64U_TRACE_STAGE(stage, detail) c64u_boot_stage((stage), (detail))
#define C64U_TRACE_READY() c64u_boot_ready()
#define C64U_TRACE_POLL() c64u_boot_poll()
#else
#define C64U_TRACE_STAGE(stage, detail) do { } while (0)
#define C64U_TRACE_READY() do { } while (0)
#define C64U_TRACE_POLL() do { } while (0)
#endif

#if defined(P17I_WD_DMA) && P17I_WD_DMA
#include "p17i_wd_dma.h"
#endif

#if U64
    #include "u64_config.h"
#endif
bool connectedToU64 = false;

static TreeBrowser *root_tree_browser;
static TreeBrowser *root_tree_browser_overlay;

StreamMenu *root_menu;
Overlay *overlay;
C64 *c64;
C64_Subsys *c64_subsys;
StreamTextLog textLog(96*1024);
Syslog syslog;

extern "C" bool push_active_menu_button(void)
{
    if (overlay && overlay->is_accessible()) {
        overlay->setButtonPushed();
        return true;
    }
    return false;
}

extern "C" void (*custom_outbyte)(int c);

extern "C" {
	void print_tasks(void);
}

void outbyte_log(int c)
{
	textLog.charout(c);
}

void outbyte_log_syslog(int c)
{
	textLog.charout(c);  // Internal log
	syslog.charout(c);  // Remote syslog server
}

extern "C" void ultimate_main(void *a)
{
    C64U_TRACE_STAGE(0x10, 0);
    // Normal boot log size is about 5k right now, so 16k should be enough to
    // give time to flush the buffer.
    const int syslog_bufsize = 16*1024;

    char time_buffer[32];

    uint32_t capabilities = getFpgaCapabilities();
    C64U_TRACE_STAGE(0x11, capabilities);

    char product_version[64];
    printf("*** %s ***\n", getProductVersionString(product_version, sizeof(product_version), true));
    printf("*** FPGA Capabilities: %8x ***\n\n", capabilities);

	puts("Executing init functions.");
    C64U_TRACE_STAGE(0x12, 0);
	InitFunction :: executeAll();
    C64U_TRACE_STAGE(0x13, 0);
    C64U_TRACE_STAGE(0x14, 0);
    custom_outbyte = syslog.init(syslog_bufsize) ? outbyte_log_syslog : outbyte_log;
    C64U_TRACE_STAGE(0x15, 0);

    printf("%s ", rtc.get_long_date(time_buffer, 32));
    printf("%s\n", rtc.get_time_string(time_buffer, 32));

	if (capabilities & CAPAB_CARTRIDGE) {
        C64U_TRACE_STAGE(0x30, 0);
		c64 = C64 :: getMachine();
		c64_subsys = new C64_Subsys(c64);
        C64U_TRACE_STAGE(0x31, (unsigned)(uintptr_t)c64);
		c64->init();
        C64U_TRACE_STAGE(0x32, (unsigned)(uintptr_t)c64);
		c64->start();
        C64U_TRACE_STAGE(0x33, (unsigned)(uintptr_t)c64);
	} else {
		c64 = NULL;
	}

    C64U_TRACE_STAGE(0x40, 0);
    usb2.initHardware();
    C64U_TRACE_STAGE(0x41, 0);

#if defined(P17I_WD_DMA) && P17I_WD_DMA
    C64U_TRACE_STAGE(0x42, 0);
    p17i_wd_dma::mark_hardware_ready();
    C64U_TRACE_STAGE(0x43, 0);
#endif

    C64U_TRACE_STAGE(0x50, 0);
    char title[48];
    getProductTitleString(title, sizeof(title), false);

    if(capabilities & CAPAB_ULTIMATE64) {
        system_usb_keyboard.setMatrix((volatile uint8_t *)MATRIX_KEYB);
        system_usb_keyboard.enableMatrix(true);
    }

    C64U_TRACE_STAGE(0x51, 0);
#if defined(C64U_BOOT_TRACE) && C64U_BOOT_TRACE
    // Both UIs share hardware matrices with the early diagnostic. Stop normal
    // trace publication BEFORE constructing/drawing them; keep fatal capture.
    c64u_boot_hide();
#endif
    overlay = NULL;
    UserInterface *overlayUserInterface = NULL;

#if U64 == 2
    overlay_settings_t overlay_default;
    u64_configurator->getOverlaySettings(overlay_default);
    overlay = new Overlay(false, 12, U64II_OVERLAY_BASE, overlay_default);
    Keyboard_C64 *kb = new Keyboard_C64(overlay, &U64II_KEYB_ROW, &U64II_KEYB_COL, &U64II_KEYB_JOY);
    overlay->setKeyboard(kb);
#elif U64 == 1
    overlay_settings_t overlay_default = { 40, 25, 366, 274,  8, OVERLAY_CHARHEIGHT_9 };
    overlay = new Overlay(false, 11, U64_OVERLAY_BASE, overlay_default);
    Keyboard_C64 *kb = new Keyboard_C64(overlay, C64_PLD_PORTB, C64_PLD_PORTA, C64_PLD_PORTA);
    overlay->setKeyboard(kb);
#endif

#if U64
    C64U_TRACE_STAGE(0x52, (unsigned)(uintptr_t)overlay);
    C64U_TRACE_STAGE(0x53, 0);
    overlayUserInterface = new UserInterface(title, true);

  #if COMMERCIAL
    MainMenu *mainMenuOverlay = new MainMenu(overlayUserInterface);
    overlayUserInterface->activate_uiobject(mainMenuOverlay); // root of all evil!
    C64U_TRACE_STAGE(0x54, (unsigned)(uintptr_t)overlayUserInterface);
    overlayUserInterface->init(overlay);
  #else
    Browsable *root = new BrowsableRoot();
    root_tree_browser_overlay = new TreeBrowser(overlayUserInterface, root);
    overlayUserInterface->activate_uiobject(root_tree_browser_overlay); // root of all evil!
    C64U_TRACE_STAGE(0x54, (unsigned)(uintptr_t)overlayUserInterface);
    overlayUserInterface->init(overlay);
    if(overlayUserInterface->cfg->get_value(CFG_USERIF_START_HOME)) {
        new HomeDirectory(overlayUserInterface, root_tree_browser_overlay);
        // will clean itself up
    }
  #endif

#endif

    C64U_TRACE_STAGE(0x55, (unsigned)(uintptr_t)overlayUserInterface);
    UserInterface *c64UserInterface = NULL;
    if(c64) {
        C64U_TRACE_STAGE(0x56, 0);
        c64UserInterface = new UserInterface(title, true);
        // Instantiate and attach the root tree browser
#if COMMERCIAL
        MainMenu *mainMenu = new MainMenu(c64UserInterface);
        c64UserInterface->activate_uiobject(mainMenu); // root of all evil!
        C64U_TRACE_STAGE(0x57, (unsigned)(uintptr_t)c64UserInterface);
        c64UserInterface->init(c64);
#else
        Browsable *root = new BrowsableRoot();
        root_tree_browser = new TreeBrowser(c64UserInterface, root);
        c64UserInterface->activate_uiobject(root_tree_browser); // root of all evil!
        C64U_TRACE_STAGE(0x57, (unsigned)(uintptr_t)c64UserInterface);
        c64UserInterface->init(c64);
        if(c64UserInterface->cfg->get_value(CFG_USERIF_START_HOME)) {
            new HomeDirectory(c64UserInterface, root_tree_browser);
            // will clean itself up
        }
#endif
    }

    C64U_TRACE_STAGE(0x58, (unsigned)(uintptr_t)c64UserInterface);
    C64U_TRACE_STAGE(0x59, 0);
    printf("All linked modules have been initialized and are now running.\n");
    print_tasks();
    C64U_TRACE_STAGE(0x5a, 0);

    C64U_TRACE_STAGE(0x60, (unsigned)(uintptr_t)c64);
#if defined(C64U_BOOT_TRACE) && C64U_BOOT_TRACE
#if U64 == 2
    if (overlay) overlay->update_settings(overlay_default);
#endif
    C64U_TRACE_READY();
#endif
    while(c64) {
        int doIt = 0;
        c64->checkButton();
        if (c64->buttonPush()) {
            doIt = 1;
        }
        switch(system_usb_keyboard.getch()) {
        case KEY_SCRLOCK:
        case KEY_F10:
            doIt = 1;
            break;
        case 0x04: // CTRL-D
            doIt = 2;
            break;
        }
        UserInterface *ui = c64UserInterface;
        if (overlayUserInterface) {
            if ((U64_HDMI_REG & U64_HDMI_HPD_CURRENT) && (doIt)) {
                if (overlayUserInterface->getPreferredType() == 1) {
                    ui = overlayUserInterface;
                }
            }
        }

        switch (doIt) {
        case 0:
            c64UserInterface->pollInactive();
            if (overlayUserInterface) {
                overlayUserInterface->pollInactive();
            }
            break;
        case 1:
            system_usb_keyboard.enableMatrix(false);
            C64U_TRACE_STAGE(0x61, (unsigned)(uintptr_t)ui);
            ui->run_once();
            C64U_TRACE_STAGE(0x62, (unsigned)(uintptr_t)ui);
            system_usb_keyboard.enableMatrix(true);
            break;
        case 2:
            ui->swapDisk();
            break;
        }
        vTaskDelay(3);
        C64U_TRACE_POLL();
    }

    custom_outbyte = 0; // stop logging
    printf("GUI running on C64 host has terminated? This should not happen.\n");

    vTaskDelay(400);
    puts(textLog.getText());

    vTaskSuspend(NULL); // Stop executing init task

    // We will never come here.

    if(overlay)
        delete overlay;
    if(root_tree_browser)
        delete root_tree_browser;
    if(root_tree_browser_overlay)
        delete root_tree_browser_overlay;
    if(overlayUserInterface)
        delete overlayUserInterface;
    if(c64UserInterface)
        delete c64UserInterface;
    if(c64_subsys)
        delete c64_subsys;
    if(c64)
        delete c64;

    printf("Graceful exit!!\n");
//    return 0;
}
