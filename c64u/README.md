# WiC64 C64 Ultimate Beta2 Source

Sources for the C64 Ultimate RAM application and ESP controller applications.
The Control Center is included as `WiC64/WIC64CC.PRG`, in binary form only.

## Build

Use Ubuntu 24.04 **Linux x86_64** or Ubuntu 24.04 under **WSL2**, with
**CPython 3.12**. Extract into the Linux filesystem, using a path without spaces.

```sh
sudo apt install build-essential python3 python3-venv bash git xz-utils unzip
./setup.sh
./build.sh all --clean --jobs 2
```

Setup downloads the pinned compilers, SDK and build dependencies. Generated
dependencies stay in the component `.deps` directories.

- `all` is the default: build both ESP applications, then embed the TLS app in the UE2.
- `native`: rebuild the UE2 using the ESP output in `esp/build/`; build ESP first if missing.
- `esp`: build only the ESP applications in `esp/build/`.

`native` and `all` recreate `dist/` with the UE2, ESP restore file,
installation instructions, `WiC64/WIC64CC.PRG` and the required licence notices.
Installation instructions
are in `README.TXT`. Building does not flash the device.

## Deutsch

Benötigt werden Ubuntu 24.04 auf Linux x86_64 oder unter WSL2 und CPython 3.12.
In einen Linux-Pfad ohne Leerzeichen entpacken. Die obigen Befehle installieren
die Systempakete, laden die passenden Build-Abhängigkeiten und bauen ESP und UE2.

`all` baut beide ESP-Anwendungen aus den Quellen und bettet die erzeugte
TLS-App in die UE2 ein. `native` verwendet vorhandene ESP-Builddateien und
baut diese bei Bedarf zuerst. Die fertigen
Laufzeitdateien liegen unter `dist/`. Das Control Center liegt ausschließlich
als PRG bei. Die Installation ist in `README.TXT` beschrieben.

Copyright and licence notices: `THIRD_PARTY_NOTICES.txt` and `LICENSES/`.
