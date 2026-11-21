#!/usr/bin/env python3
# Baut die Datenbank fuer den MiSTer-Downloader (update_all) aus dem fertigen
# Paket release/mister-<fassung>/ (erst paket.py laufen lassen).
#
#   python3 mister/datenbank.py <ordner>
#
# Legt in <ordner> an:  db.json  und  files/<md5>/<name>  fuer jede Datei.
# Die Adresse haengt am Inhalt: raw.githubusercontent cacht bis 5 min, unter
# gleichem Pfad kaeme sonst noch die alte Datei (Downloader: "Bad hash").
# <ordner> ist ein Klon des Zweigs "db" von Retro-Modern/WiC64-Ultimate;
# committen und pushen, dann holen die MiSTer die neue Fassung.
#
# Nutzer tragen in /media/fat/downloader.ini ein:
#   [retro-modern/wic64]
#   db_url = https://raw.githubusercontent.com/Retro-Modern/WiC64-Ultimate/db/db.json
#
# Der Downloader darf nicht nach linux/ schreiben; der Dienst liegt deshalb
# seit 1.1 unter Scripts/.config/wic64. Die db_id NIE aendern.
# Retro-Modern - https://retro-modern.net

import hashlib, json, os, shutil, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paket                                    # FASSUNG und ZIEL

DB_ID = "retro-modern/wic64"
ROH = "https://raw.githubusercontent.com/Retro-Modern/WiC64-Ultimate/db/"
NUR = ("_Computer/", "Scripts/")                # die Anleitung bleibt im Zip


def main():
    if len(sys.argv) != 2:
        sys.exit("python3 mister/datenbank.py <klon des db-zweigs>")
    ziel = sys.argv[1]
    if not os.path.isdir(paket.ZIEL):
        sys.exit("Erst paket.py laufen lassen: " + paket.ZIEL)
    ablage = os.path.join(ziel, "files")
    # Alte Dateien bleiben liegen: eine db.json aus dem Cache verweist noch darauf.

    dateien, ordner = {}, {}
    for wurzel, _, namen in sorted(os.walk(paket.ZIEL)):
        for n in sorted(namen):
            voll = os.path.join(wurzel, n)
            rel = os.path.relpath(voll, paket.ZIEL).replace(os.sep, "/")
            if not rel.startswith(NUR):
                continue
            daten = open(voll, "rb").read()
            md5 = hashlib.md5(daten).hexdigest()
            ort = md5 + "/" + n
            eintrag = {"hash": md5, "size": len(daten), "url": ROH + "files/" + ort}
            if rel.endswith(".rbf"):
                eintrag["tangle"] = ["retro-modern-c64-wic64"]
            dateien[rel] = eintrag
            kopie = os.path.join(ablage, ort)
            os.makedirs(os.path.dirname(kopie), exist_ok=True)
            shutil.copyfile(voll, kopie)
            teile = rel.split("/")[:-1]
            for i in range(1, len(teile) + 1):
                ordner["/".join(teile[:i])] = {}

    db = {
        "v": 1,
        "db_id": DB_ID,
        "timestamp": int(time.time()),
        "files": dateien,
        "folders": dict(sorted(ordner.items())),
    }
    with open(os.path.join(ziel, "db.json"), "w") as f:
        json.dump(db, f, indent=2)
        f.write("\n")
    for rel, e in dateien.items():
        print("%-40s %9d  %s" % (rel, e["size"], e["hash"]))
    print("db.json:", os.path.join(ziel, "db.json"))


if __name__ == "__main__":
    main()
