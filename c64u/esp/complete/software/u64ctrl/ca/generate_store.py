#!/usr/bin/env python3
"""Build the P18 immutable CA table from the project's Mozilla PEM roots.

GPL-3.0-or-later. Each entry contains its DER subject and complete certificate;
duplicate subjects remain separate candidates for certificate/key rollover.
"""
import argparse
import re
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


def generate(source: bytes) -> bytes:
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", source, re.S
    )
    if not 1 <= len(blocks) <= 200:
        raise ValueError("expected 1..200 CA certificates")
    entries = []
    for block in blocks:
        cert = x509.load_pem_x509_certificate(block)
        subject = cert.subject.public_bytes()
        der = cert.public_bytes(Encoding.DER)
        if not subject or len(subject) > 65535 or not der or len(der) > 0xFFFFFFFF:
            raise ValueError("CA certificate does not fit table format")
        entries.append(struct.pack("<HI", len(subject), len(der)) + subject + der)
    return b"P18CAs01" + struct.pack("<I", len(entries)) + b"".join(entries)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_bytes(generate(args.source.read_bytes()))
