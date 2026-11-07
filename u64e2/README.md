# WiC64 U64E2 B5RM2 – Quellen

WiC64 2.4.4 / PORT64 1.1.4 für Ultimate64 Elite II.

## CFW bauen

Linux x86_64, WSL2 oder macOS arm64 mit Python 3.10+, Make, GCC und G++ verwenden.
Geprüfte Build-Plattform: Linux x86_64.
Zusätzlich separat installieren:

- [xPack RISC-V GCC 11.3.0-1, passende Host-Plattform](https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/tag/v11.3.0-1)
- [64tass](https://sourceforge.net/projects/tass64/), geprüft mit 1.53.1515.

Aus dem entpackten Quellenverzeichnis, mit Pfaden ohne Leerzeichen:

```sh
python3 build.py --toolchain /pfad/xpack-riscv-none-elf-gcc-11.3.0-1 --tass /pfad/64tass
```

Die Ergebnisse liegen in `build-work/out/`. Für einen weiteren Lauf ein neues
Arbeitsverzeichnis mit `--work-dir neuer-build` wählen. `--jobs 4` setzt die
Anzahl paralleler Compilerprozesse. Die Skripte greifen auf kein Gerät zu.

`native/` enthält die Firmwarequellen, `crypto/` die verwendeten wolfSSL-Quellen.
Der Build verwendet das mitgelieferte ESP-Abbild. Das Control Center liegt als
separate Datei `assets/WIC64CC.PRG` bei; seine Quellen werden nicht mitgeliefert.

## Eingebettete Daten bearbeiten

Helper- und Portal-Assemblerquellen liegen in `firmware_assets/`, die native
CA-Quelle in `certificates/cacert.pem`. Die erzeugten Header sind enthalten.
Bei Änderungen mit separat installiertem [ACME](https://sourceforge.net/projects/acme-crossass/)
neu erzeugen:

```sh
python3 build_assets.py --acme /pfad/acme
```

SID/MUS-Assets können mit `make -C native/software/6502/sidcrt TASS=/pfad/64tass`
aus den enthaltenen Quellen gebaut werden.

## ESP-Apps bauen

Die Quellen liegen in `esp/wic64/` und `esp/restore/`. ESP-IDF und die zugehörigen
Werkzeuge werden separat installiert. Die passenden SDK-Quellen vollständig beziehen:

```sh
git clone --branch v5.3.1 --depth 1 https://github.com/espressif/esp-idf.git /pfad/esp-idf
git -C /pfad/esp-idf checkout --detach c8fc5f643b7a7b0d3b182d3df610844e3dc9bd74
git -C /pfad/esp-idf submodule update --init --recursive
/pfad/esp-idf/install.sh esp32s3
. /pfad/esp-idf/export.sh
python3 esp/build.py wic64
python3 esp/build.py restore
```

Ergebnisse: `esp-build-wic64/` und `esp-build-restore/`, jeweils mit `.bin` und
passender `.ESP`-Datei. Der CFW-Build bindet `assets/wic64_esp.bin` ein. Ein Neubau überschreibt das mitgelieferte Abbild nicht. Ein eigenes Abbild kann
explizit mit `python3 build.py --toolchain /pfad/toolchain --tass /pfad/64tass
--esp-app /pfad/WiC64_ESP.ESP` eingebunden werden (als eine Befehlszeile).
Größe, Hashfreigabe und Speicherlayoutprüfung verwenden dabei dasselbe Abbild.
Die Eingabe muss eine ESP32-S3-App sein; ein `.ESP`-Segment muss bei `0x10000`
beginnen und genau die angegebene Anwendung enthalten.

Der CFW-Build verwendet feste Buildangaben. Optional setzt `SOURCE_DATE_EPOCH`
einen anderen UTC-Buildzeitpunkt. Buildbericht: `build-work/build_report.json`.

Lizenztexte und erforderliche Herkunftshinweise: `NOTICES.txt` und `licenses/`.
