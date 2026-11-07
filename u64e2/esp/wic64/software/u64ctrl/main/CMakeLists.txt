set(EXTERNAL "../../io/uart")
idf_component_register(SRCS "button_handler.c" "control_main.c" "my_uart.c" "dump_hex.c" "rpc_dispatch.c" "wifi_modem.c" "button_handler.c" "jtag.c" "sntp.c" "power_state.c" "wol_magic.c" "recovery_manifest.c" "recovery_verify.c" "recovery_image.c" "recovery_url.c" "recovery.c" "recovery_trust.c" "p18_tls.c" "p18_ca.c" "p18_bootstrap.c" ${EXTERNAL}/cmd_buffer.c
                       INCLUDE_DIRS "." ${EXTERNAL})

set(P18_CA_STORE "${CMAKE_CURRENT_BINARY_DIR}/p18_ca_store.bin")
set(P18_CA_GENERATOR "${CMAKE_CURRENT_LIST_DIR}/../ca/generate_store.py")
set(P18_CA_PEM "${CMAKE_CURRENT_LIST_DIR}/../ca/cacert.pem")
add_custom_command(OUTPUT "${P18_CA_STORE}"
                   COMMAND "${PYTHON}" "${P18_CA_GENERATOR}" "${P18_CA_PEM}" "${P18_CA_STORE}"
                   DEPENDS "${P18_CA_GENERATOR}" "${P18_CA_PEM}"
                   VERBATIM)
add_custom_target(p18_ca_store DEPENDS "${P18_CA_STORE}")
add_dependencies(${COMPONENT_LIB} p18_ca_store)
target_add_binary_data(${COMPONENT_LIB} "${P18_CA_STORE}" BINARY)

