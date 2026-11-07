
CROSS	     = riscv32-unknown-elf-
ELFTYPE      = elf32-littleriscv
ARCHITECTURE = riscv
# CPU architecture and ABI
MARCH ?= rv32i
MABI  ?= ilp32

include ../../../common/environment.mk
# /home/gideon/proj/ultimate/target/u64ii/riscv/ultimate/result/ultimate.elf
PRJ      =  ultimate
FINAL    =  $(RESULT)/$(PRJ).app $(RESULT)/$(PRJ).elf $(OUTPUT)/$(PRJ).sim

SRCS_C   =	c64u_newlib.c \
			itu.c \
			dump_hex.c \
			assert.c \
			profiler.c \
			croutine.c \
			event_groups.c \
			list.c \
			queue.c \
			tasks.c \
			timers.c \
			port.c \
			heap_4.c \
			ff.c \
			ffsystem.c \
			ffunicode.c \
			time.c \
			mdio.c \
			sid_coeff.c \
			riscv_main.c \
			do_ctors.c \
			malloc_lock.c \
			server.c \
			http_protocol.c \
			middleware.c \
			multipart.c \
			cmd_buffer.c \
			url.c \

SRCS_CC	 =  p08_service.cc \
            p14_platform.cc \
            p14_tls.cc \
            filetype_wic64.cc \
            p08_http.cc \
            p12_commands.cc \
            p15_commands_extra.cc \
            p15_network.cc \
            p15_ip.cc \
            p12_wifi.cc \
            p12_storage.cc \
            p12_tcp.cc \
            u64ii_init.cc \
			color_timings.cc \
			hdmi_scan.cc \
			usb_hwinit.cc \
			i2c_drv.cc \
			hw_i2c_drv.cc \
			nau8822.cc \
			small_printf.cc \
			stream.cc \
			stream_uart.cc \
			memory_wrap.cc \
			init_function.cc \
			flash.cc \
			w25q_flash.cc \
			s25fl_flash.cc \
			s25fl_l_flash.cc \
			product.cc \
			config.cc \
			subsys.cc \
			filemanager.cc \
			file_device.cc \
			file_partition.cc \
			embedded_d64.cc \
			embedded_t64.cc \
			embedded_iso.cc \
			embedded_fat.cc \
			ramdisk.cc \
			rtc_dummy.cc \
			c64.cc \
			c64_crt.cc \
			u64_machine.cc \
			c64_subsys.cc \
			screen.cc \
			keyboard_c64.cc \
			disk_image.cc \
			c1541.cc \
			wd177x.cc \
			mfmdisk.cc \
			mystring.cc \
			path.cc \
			pattern.cc \
			blockdev.cc \
			blockdev_file.cc \
			blockdev_ram.cc \
			blockdev_flash.cc \
			disk.cc \
			partition.cc \
			file_system.cc \
			diskio.cc \
			directory.cc \
			file.cc \
			filesystem_iso9660.cc \
			filesystem_root.cc \
			filesystem_d64.cc \
			filesystem_t64.cc \
			filesystem_fat.cc \
			sd_card.cc \
			sdio.cc \
			sdcard_manager.cc \
			size_str.cc \
			userinterface.cc \
			ui_elements.cc \
			user_file_interaction.cc \
			editor.cc \
			tree_browser.cc \
			tree_browser_state.cc \
			main_menu.cc \
			config_menu.cc \
			context_menu.cc \
			task_menu.cc \
			filetype_d64.cc \
			filetype_g64.cc \
			filetype_t64.cc \
			filetype_prg.cc \
			filetype_u2p.cc \
			filetype_reu.cc \
			filetype_crt.cc \
			filetype_sid.cc \
			filetype_bin.cc \
			filetype_cfg.cc \
			filetype_vpl.cc \
			host_stream.cc \
			keyboard_vt100.cc \
			screen_vt100.cc \
			usb_base.cc \
			usb_device.cc \
			usb_scsi.cc \
			usb_hub.cc \
			usb_ax88772.cc \
			usb_hid.cc \
			usb_ms_cbi.cc \
			keyboard_usb.cc \
			network_config.cc \
			network_interface.cc \
			vfs.cc \
			ftpd.cc \
			tape_controller.cc \
			tape_recorder.cc \
			command_intf.cc \
			dos.cc \
			network_target.cc \
			control_target.cc \
			filetype_tap.cc \
			socket_stream.cc \
			rmii_interface.cc \
			home_directory.cc \
			reu_preloader.cc \
			led_strip.cc \
			bling_board.cc \
			data_streamer.cc \
			configio.cc \
			u64_config.cc \
			sid_editor.cc \
			sid_device.cc \
			sid_device_fpgasid.cc \
			sid_device_swinsid.cc \
			sid_device_armsid.cc \
			acia.cc \
			modem.cc \
			socket_gui.cc \
			socket_dma.cc \
			syslog.cc \
			listener_socket.cc \
			system_info.cc \
			ult_syscalls.cc \
			httpd.cc \
			json.cc \
			routes.cc \
			route_files.cc \
			route_drives.cc \
			route_runners.cc \
			route_configs.cc \
			route_machine.cc \
			route_streams.cc \
			assembly_search.cc \
			assembly.cc \
			filesystem_a64.cc \
			dma_uart.cc \
			esp32.cc \
			network_esp32.cc \
			wifi_cmd.cc \
			wifi.cc \
			sntp_time.cc \
			$(PRJ).cc


SRCS_CC +=  iec_interface.cc \
			iec_drive.cc \
			iec_channel.cc \
			iec_printer.cc \
			mps_printer.cc \
			mps_printer_cbm.cc \
			mps_printer_epson.cc \
			mps_printer_ibmgp.cc \
			mps_printer_ibmpp.cc \
			mps_chargen.cc \
			mps_charset.cc \
			mps_png.cc \
			iec_ulticopy.cc \
			softiec_target.cc

VPATH +=	$(PATH_SW)/FreeRTOS/Source/portable/risc-v
VPATH +=	$(PATH_SW)/FreeRTOS/Source/portable/risc-v/chip_specific_extensions/RV32I_CLINT_no_extensions
VPATH +=	$(PATH_SW)/portable/riscv
VPATH +=	$(PATH_SW)/6502/sidcrt/target
VPATH +=	$(PATH_SW)/u64ii
VPATH +=	$(PATH_SW)/u64
VPATH +=	$(PATH_SW)/u64ctrl/main

SRCS_ASM =  licenses.s

SRCS_ASMS = crt0.S port_asm.S
ifneq ($(filter -DC64U_BOOT_TRACE=1,$(EFFORT)),)
SRCS_ASMS += c64u_boot_trap.S
SRCS_C += c64u_boot_trace.c
endif

SRCS_6502 = bootcrt.tas cmd_test_rom.tas ulticopy.tas eapi.tas # default_kernal.tas

SRCS_BIN =  basic.bin chars.bin module.bin sidcrt.bin muscrt.bin musplayer.bin raminit.bin characters.901225-01.bin kernal.901227-03.bin # default_chars.bin

SRCS_IEC = iec_code.iec

SRCS_NANO = nano_minimal.nan

PATH_INC =  $(addprefix -I, $(VPATH))
OPTIONS  = -march=$(MARCH) -mabi=$(MABI) $(EFFORT) -ffunction-sections -fdata-sections -nostartfiles -mno-fdiv
OPTIONS += -gdwarf-2 -Os -DRISCV -DU64=2 -DUSB2513 -DOS -DIOBASE=0x10000000 -DU2P_IO_BASE=0x10100000 -DCLOCK_FREQ=100000000 -Wno-write-strings -DFP_SUPPORT=1
OPTIONS += -DCOMMERCIAL=1
# Flash‑protection removal code should not be included in the Ultimate application binary.
# So even if the application crashes, no code exists anywhere in memory that could
# accidentally disable the flash protection.
OPTIONS += -DFLASH_EXTRA_PROTECTION=1
# The P14 build script supplies the separately source-bound wolfSSL archive.
# No configure result, OS entropy provider or system SSL library is selected.
ifneq ($(P14_TLS_LIBRARY),)
SRCS_CC += p17e_crypto_trace.cc
ifneq ($(filter -DP18_TLS=1,$(EFFORT)),)
SRCS_CC += p18_tls_client.cc p18_tls_rpc.cc filetype_esp.cc p18m_esp_firmware.cc
ifneq ($(filter -DC64U_ESP_PERSIST=1,$(EFFORT)),)
SRCS_CC += p21_store_client.cc p21_store_rpc.cc p21_preferences.cc
endif
ifneq ($(filter -DC64U_ESP_RETURN_APP=1,$(EFFORT)),)
SRCS_CC += c64u_esp_return.cc
endif
ifneq ($(filter -DP18M_INITIALIZED_ESP_HEAP=1,$(EFFORT)),)
SRCS_CC += p18m_esp_resource.cc
SRCS_ASMS += p18m_esp_heap.S
endif
endif
ifneq ($(filter -DP18_LOG=1,$(EFFORT)),)
SRCS_CC += p18_log.cc p18_log_stream.cc
endif
ifneq ($(filter -DP17F_CACHED_MATH=1,$(EFFORT)),)
SRCS_CC += p17f_cache.cc
SRCS_ASMS += p17f_cache_asm.S
endif
ifneq ($(filter -DP17I_WD_DMA=1,$(EFFORT)),)
SRCS_CC += p17i_wd_dma.cc
endif
PATH_INC += -I$(P14_TLS_CONFIG) -I$(P14_WOLFSSL_DIR)
OPTIONS += -DWOLFSSL_USER_SETTINGS -DP14_WOLFSSL_BUILD_INPUT_SHA256=$(P14_TLS_INPUT_SHA256)
P14_TLS_IDENTITY_OPTION = -include $(P14_TLS_IDENTITY_HEADER)
P17E_CRYPTO_WRAP = wc_ecc_make_key_ex wc_ecc_verify_hash wc_ecc_shared_secret wc_RsaSSL_VerifyInline wc_RsaPSS_VerifyInline wc_RsaPSS_VerifyInline_ex
endif
COPTIONS = $(OPTIONS) $(P14_TLS_IDENTITY_OPTION) -std=gnu99
CPPOPT   = $(OPTIONS) $(P14_TLS_IDENTITY_OPTION) -std=gnu++11 -fno-exceptions -fno-rtti -fno-threadsafe-statics -fpermissive
LINK 	 = linker.x
LIBS    = ../../../libs/riscv/lwip/result/liblwip.a $(P14_TLS_LIBRARY)
#LFLAGS   = --gc-sections -msys-crt0=$(BSP)/obj/HAL/src/crt0.o
LFLAGS   = --gc-sections --wrap=malloc --wrap=_malloc_r --wrap=free --wrap=_free_r --wrap=realloc --wrap=_realloc_r --wrap=calloc --wrap=_calloc_r
LFLAGS  += $(addprefix --wrap=,$(P17E_CRYPTO_WRAP))
LINKMETHOD = ld

include ../../../common/rules.mk

licenses.o: $(PATH_SW)/licenses/licenses.txt $(PATH_SW)/licenses/licenses.s

mps_png.o: mps_png.cc
	@echo Compiling $(<F) optimized for speed
	@$(CPP) $(CPPOPT) -O3 $(PATH_INC) -B. -c -o $(OUTPUT)/$(@F) $<
	@$(CPP) -MM $(PATH_INC) $< >$(OUTPUT)/$(@F:.o=.d)

$(PATH_SW)/6502/sidcrt/target/sidcrt.bin::
	make -C $(PATH_SW)/6502/sidcrt

$(PATH_SW)/6502/sidcrt/target/muscrt.bin::
	make -C $(PATH_SW)/6502/sidcrt

$(PATH_SW)/6502/sidcrt/target/musplayer.bin::
	make -C $(PATH_SW)/6502/sidcrt
