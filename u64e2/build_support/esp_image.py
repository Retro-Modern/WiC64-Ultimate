# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate the ESP32-S3 application and generate its native build identity."""
import hashlib
import struct

RESOURCE_BYTES = 1183024
RESOURCE_SHA256 = '513e4c154be1765db813eb1ffd12f5de9fda70e83de7a3ec9e8fea937ddcd706'
MAX_APP_BYTES = 3 * 1024 * 1024


def application(data):
    if data[:4] == b'SEGM':
        if len(data) < 36:
            raise ValueError('Truncated ESP application segment')
        size, address = struct.unpack_from('<II', data, 4)
        if address != 0x10000 or size != len(data) - 12:
            raise ValueError('ESP segment must contain one application at 0x10000')
        data = data[12:]
    if not 24 <= len(data) <= MAX_APP_BYTES:
        raise ValueError('Invalid ESP application length')
    if data[0] != 0xe9 or data[12:14] != b'\x09\x00':
        raise ValueError('Expected an ESP32-S3 application')
    return data


def header(data):
    digest = hashlib.sha256(data).digest()
    values = ','.join('0x%02x' % byte for byte in digest)
    return ('/* Current embedded ESP identity. GPL-3.0-or-later. */\n'
            '#ifndef P18M_ESP_IMAGE_H\n#define P18M_ESP_IMAGE_H\n'
            '#define P18M_ESP_IMAGE_BYTES %d\n' % len(data) +
            '#define P18M_ESP_IMAGE_SHA256 %s\n#endif\n' % values)


def configure(data):
    from . import cfw, memory_layout
    digest = hashlib.sha256(data).hexdigest()
    cfw.RESOURCE_BYTES = memory_layout.RESOURCE_BYTES = len(data)
    cfw.RESOURCE_SHA256 = memory_layout.RESOURCE_SHA256 = digest
    return digest
