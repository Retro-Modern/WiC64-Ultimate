#!/usr/bin/env python3
"""HTTPS-Einrichtungsdatei (.W64) für die WiC64-Emulation erzeugen.

Ohne die ESP-TLS-App (Ultimate 64 der ersten Generation) braucht die
WiC64 einen geheimen Zufallsstartwert für TLS. Diese Datei enthält ihn.
Einmal auf USB/SD kopieren, im Dateibrowser RETURN -> "Set up WiC64 HTTPS",
danach die Datei löschen. Der Startwert bleibt im Flash der Ultimate.

Aufbau (64 Bytes): "W14S", 1, 0, 64, 0, Startwert (32), ID (16) =
SHA-256("C64U-WiC64-P14-bootstrap-id-v1\\0" + Startwert)[:16], 0 (4),
CRC-32 der ersten 60 Bytes.

Aufruf: w64_erzeugen.py [datei]   (Vorgabe: wic64_https.w64)
"""
import hashlib
import secrets
import struct
import sys
import zlib

ID_DOMAIN = b'C64U-WiC64-P14-bootstrap-id-v1\0'


def main():
    ziel = sys.argv[1] if len(sys.argv) > 1 else 'wic64_https.w64'
    if not ziel.lower().endswith('.w64'):
        sys.exit('Der Dateiname muss auf .w64 enden.')
    startwert = secrets.token_bytes(32)
    kennung = hashlib.sha256(ID_DOMAIN + startwert).digest()[:16]
    rumpf = b'W14S' + bytes([1, 0, 64, 0]) + startwert + kennung + bytes(4)
    with open(ziel, 'xb') as f:
        f.write(rumpf + struct.pack('<I', zlib.crc32(rumpf)))
    print(ziel + ' geschrieben (64 Bytes). Nach der Einrichtung löschen.')


if __name__ == '__main__':
    main()
