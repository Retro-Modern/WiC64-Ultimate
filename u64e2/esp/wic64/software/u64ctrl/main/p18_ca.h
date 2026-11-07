/* P18 trusted CA candidates. GPL-3.0-or-later. */
#ifndef P18_CA_H
#define P18_CA_H
#include "mbedtls/ssl.h"

int p18_ca_attach(mbedtls_ssl_config *config);

#endif
