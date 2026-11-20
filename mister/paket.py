#!/usr/bin/env python3
# Baut das MiSTer-Paket: release/mister-<fassung>/ und dist/WiC64_MiSTer_<fassung>.zip
#
#   python3 mister/paket.py <C64.rbf aus dem Bau>
#
# Der Kern kommt aus bauen.sh (C:/mister/<ziel>/output_files/C64.rbf auf dem
# Gaming-PC). Alles andere nimmt das Skript aus dem Repo.
# Retro-Modern - https://retro-modern.net

import os, shutil, sys, zipfile

FASSUNG = "1.0"
DATUM = "20261120"
HIER = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HIER)
ZIEL = os.path.join(REPO, "release", "mister-" + FASSUNG)
ZIP = os.path.join(REPO, "dist", "WiC64_MiSTer_%s.zip" % FASSUNG)
GPL = os.path.join(REPO, "u64e2", "licenses", "GPL-3.0.txt")


def kopie(quelle, *ziel, lf=False):
    pfad = os.path.join(ZIEL, *ziel)
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    if lf:                                  # Skripte fuer Linux: nur LF
        daten = open(quelle, "rb").read().replace(b"\r\n", b"\n")
        open(pfad, "wb").write(daten)
        os.chmod(pfad, 0o755)
    else:
        shutil.copyfile(quelle, pfad)


def crlf(quelle, *ziel):                    # Texte fuer alle: CRLF
    pfad = os.path.join(ZIEL, *ziel)
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    daten = open(quelle, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    open(pfad, "wb").write(daten)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__ or "python3 mister/paket.py <C64.rbf>")
    rbf = sys.argv[1]
    if os.path.getsize(rbf) < 1000000:
        sys.exit("Das ist kein Kern: " + rbf)
    shutil.rmtree(ZIEL, ignore_errors=True)
    kopie(rbf, "_Computer", "C64_WiC64_%s.rbf" % DATUM)
    kopie(os.path.join(HIER, "linux", "wic64d.py"), "linux", "wic64", "wic64d.py", lf=True)
    for s in ("wic64_einrichten.sh", "wic64_entfernen.sh"):
        kopie(os.path.join(HIER, "paket", s), "Scripts", s, lf=True)
    crlf(os.path.join(HIER, "paket", "LIESMICH.TXT"), "WiC64-MiSTer", "LIESMICH.TXT")
    crlf(os.path.join(HIER, "paket", "README.TXT"), "WiC64-MiSTer", "README.TXT")
    crlf(GPL, "WiC64-MiSTer", "GPL-3.0.txt")
    q = ("WiC64-MiSTer", "quellen")
    kopie(os.path.join(HIER, "patches", "c64-wic64.patch"), *q, "c64-wic64.patch")
    kopie(os.path.join(HIER, "rtl", "wic64_bridge.sv"), *q, "wic64_bridge.sv")
    kopie(os.path.join(HIER, "LIESMICH.md"), *q, "LIESMICH.md")
    kopie(os.path.join(HIER, "linux", "test_wic64d.py"), *q, "test_wic64d.py")
    kopie(os.path.join(HIER, "sim", "tb_bridge.sv"), *q, "tb_bridge.sv")

    os.makedirs(os.path.dirname(ZIP), exist_ok=True)
    if os.path.exists(ZIP):
        os.remove(ZIP)
    with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        for wurzel, _, dateien in sorted(os.walk(ZIEL)):
            for d in sorted(dateien):
                voll = os.path.join(wurzel, d)
                name = os.path.relpath(voll, ZIEL)
                info = zipfile.ZipInfo(name, date_time=(2026, 11, 20, 12, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o755 if name.endswith(".sh") or name.endswith(".py")
                                      else 0o644) << 16
                z.writestr(info, open(voll, "rb").read())
    print("Paket:", ZIEL)
    print("Zip:  ", ZIP, os.path.getsize(ZIP), "Bytes")


if __name__ == "__main__":
    main()
