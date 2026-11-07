# WiC64 for Ultimate 64 Elite II and C64 Ultimate

WiC64 emulation as a RAM custom firmware (CFW) for the **Ultimate 64 Elite II**
(firmware 3.15) and the **Commodore C64 Ultimate** (firmware 1.1.0). Programs
on the C64 see a WiC64 on the user port; HTTP and HTTPS run over the
Ultimate's LAN or WLAN. HTTPS is handled by an app on the ESP32-S3 WLAN module.

Created by **TheRealWanderer** (Forum64), who released the sources under
GPL-3.0 in November 2026 so that others can continue the project. Since his
last versions (U64E2 Beta 5, C64U Beta 2) it is maintained here by
**SanstarR / Retro-Modern**, with his permission.

*Deutsch weiter unten.*

## Status

| Folder | Device | Version | State |
|---|---|---|---|
| `u64e2/` | Ultimate 64 Elite II, firmware 3.15 | **B5RM2** (Beta 5 + changes below) | built on macOS arm64, tested on hardware |
| `c64u/` | C64 Ultimate, firmware 1.1.0 | Beta 2 + `WOLFSSL_ALT_CERT_CHAINS` | **not built, not tested** (no device here) |
| `tests/` | test programs (64tass) and telnet helpers | | |

**Download** (ready-to-use package, CFW + ESP app + restore + Control Center):
- https://retro-modern.net/downloads.html#wic64
- GitHub release: https://github.com/Retro-Modern/WiC64-Ultimate/releases/latest

Discussion (German): https://www.forum64.de/index.php?thread/167059/

### Changes since Beta 5 (U64E2)

- ESP app **B5RM1**: certificate chains are built by mbedTLS from the app's own
  table of 118 Mozilla roots (`p18_ca.c`, taken from C64U Beta 2), so servers
  that send an extra cross-signed certificate (e.g. example.com) work. The
  older callback on top of the ESP-IDF bundle is gone. Older P18 apps
  (Beta 4, Beta 5) are offered the update when WiC64 starts.
- "Flash into ESP32" in the file browser verifies the image only once, in RAM,
  with a progress bar. SHA-256 is slow on the Ultimate CPU (~40 s per image);
  before, the file was hashed three times without any display.
- WiC64 Status shows the correct version ("B5RM2" instead of "Beta 4").
- `build.py` bundles the B5RM1 app by default (`assets/wic64_esp.bin`).

Earlier fixes by us that are already part of Beta 5 / C64U Beta 2: HTTPS to
cross-signed chains on the CPU (`WOLFSSL_ALT_CERT_CHAINS`), crash of the
on-screen menu when it was closed with a context menu open, "Connection"
cycling Auto → LAN → WLAN → Auto again, closing files on a removed medium,
"Flash into ESP32" running out of memory.

### Hardware test (U64 Elite II, firmware 3.15a, 07.11.2026)

`tests/tlsprobe.tass`: example.com 2.5 s, badssl.com 5.7 s, api.github.com
1.9 s; expired, wrong.host, self-signed, untrusted-root and incomplete-chain
(badssl.com) are rejected. ESP update from the Beta 5 app via "Start WiC64",
and "Flash into ESP32" from the file browser (prompt after ~45 s,
installation ~50 s) both worked.

### Known issues

- WiC64 Status shows the TLS engine of the last HTTPS connection ("ESP TLS (BIO)"
  or "wolfSSL" on the CPU); before the first connection it says "wolfSSL".
- C64U: no build on macOS (`setup.py` requires Linux x86_64 or WSL2).

## Build

**U64E2** (`u64e2/`, Linux x86_64, WSL2 or macOS arm64): see `u64e2/README.md`.
In short, with xPack RISC-V GCC 11.3.0-1 and 64tass:

```sh
cd u64e2
python3 build.py --toolchain /path/xpack-riscv-none-elf-gcc-11.3.0-1 --tass 64tass --work-dir build-work
```

On macOS arm64 this produced the tested CFW byte for byte (sha256
`b35d48c1…f64e`). The ESP app is built with ESP-IDF v5.3.1
(commit `c8fc5f64`): `python3 esp/build.py wic64 --work-dir esp-build`, then
`build.py … --esp-app esp-build/WiC64_ESP.ESP`.

**C64U** (`c64u/`, Ubuntu 24.04 x86_64 or WSL2): `./setup.sh`, then
`./build.sh all`. See `c64u/README.md`.

The Control Center (`WIC64CC.PRG`) is included as a binary only, as in the
original packages.

## Licence

GPL-3.0-or-later (see `LICENSE`). Third-party parts keep their licences:
`u64e2/licenses/`, `u64e2/NOTICES.txt`, `c64u/LICENSES/`,
`c64u/THIRD_PARTY_NOTICES.txt`. Based on the 1541 Ultimate firmware by
Gideon Zweijtzer; uses wolfSSL, mbedTLS, ESP-IDF, lwIP, FreeRTOS and the
WiC64 API.

---

# WiC64 für Ultimate 64 Elite II und C64 Ultimate

WiC64-Emulation als RAM-CFW für die **Ultimate 64 Elite II** (Firmware 3.15)
und den **Commodore C64 Ultimate** (Firmware 1.1.0). Programme auf dem C64
sehen am Userport ein WiC64; HTTP und HTTPS laufen über LAN oder WLAN der
Ultimate. HTTPS übernimmt eine App auf dem ESP32-S3 des WLAN-Moduls.

Geschrieben von **TheRealWanderer** (Forum64), der die Quellen im November
2026 unter GPL-3.0 freigegeben hat, damit andere weitermachen können. Seit
seinen letzten Fassungen (U64E2 Beta 5, C64U Beta 2) pflegt
**SanstarR / Retro-Modern** das Projekt hier weiter, mit seiner Erlaubnis.

## Stand

| Ordner | Gerät | Fassung | Zustand |
|---|---|---|---|
| `u64e2/` | Ultimate 64 Elite II, Firmware 3.15 | **B5RM2** (Beta 5 + Änderungen unten) | auf macOS arm64 gebaut, am Gerät getestet |
| `c64u/` | C64 Ultimate, Firmware 1.1.0 | Beta 2 + `WOLFSSL_ALT_CERT_CHAINS` | **weder gebaut noch getestet** (kein Gerät) |
| `tests/` | Testprogramme (64tass) und Telnet-Helfer | | |

**Download** (fertiges Paket: CFW, ESP-App, Wiederherstellung, Control Center):
- https://retro-modern.net/downloads.html#wic64
- GitHub-Release: https://github.com/Retro-Modern/WiC64-Ultimate/releases/latest

Diskussion: https://www.forum64.de/index.php?thread/167059/

### Änderungen gegenüber Beta 5 (U64E2)

- ESP-App **B5RM1**: Zertifikatsketten baut mbedTLS aus einer eigenen Tabelle
  mit 118 Mozilla-Wurzeln (`p18_ca.c`, aus C64U Beta 2). Server, die ein
  zusätzliches Querzertifikat mitschicken (z. B. example.com), gehen damit.
  Der bisherige Rückruf auf dem ESP-IDF-Bündel entfällt. Ältere P18-Apps
  (Beta 4, Beta 5) bekommen beim Start von WiC64 das Update angeboten.
- „Flash into ESP32“ im Dateibrowser prüft die Datei nur noch einmal, im RAM,
  mit Fortschrittsbalken. SHA-256 ist auf der Ultimate-CPU langsam (~40 s je
  Abbild); vorher wurde die Datei dreimal geprüft, ohne Anzeige.
- WiC64 Status zeigt die richtige Version („B5RM2“ statt „Beta 4“).
- `build.py` bündelt standardmäßig die B5RM1-App (`assets/wic64_esp.bin`).

Frühere Korrekturen von uns, die schon in Beta 5 / C64U Beta 2 stecken: HTTPS
zu quersignierten Ketten auf der CPU (`WOLFSSL_ALT_CERT_CHAINS`), Absturz des
Bildschirmmenüs beim Schließen mit offenem Kontextmenü, „Connection“ wieder
Auto → LAN → WLAN → Auto, Schließen von Dateien auf gezogenem Medium,
„Flash into ESP32“ ohne Speicherfehler.

### Test am Gerät (U64 Elite II, Firmware 3.15a, 07.11.2026)

`tests/tlsprobe.tass`: example.com 2,5 s, badssl.com 5,7 s, api.github.com
1,9 s; expired, wrong.host, self-signed, untrusted-root und incomplete-chain
(badssl.com) werden abgelehnt. ESP-Update von der Beta-5-App über „Start
WiC64“ und „Flash into ESP32“ aus dem Dateibrowser (Rückfrage nach ~45 s,
Installation ~50 s) liefen.

### Bekannte Punkte

- WiC64 Status zeigt den TLS-Weg der letzten HTTPS-Verbindung („ESP TLS (BIO)“
  oder „wolfSSL“ auf der CPU); vor der ersten Verbindung steht dort „wolfSSL“.
- C64U: kein Bau auf macOS (`setup.py` verlangt Linux x86_64 oder WSL2).

## Bauen

**U64E2** (`u64e2/`, Linux x86_64, WSL2 oder macOS arm64): siehe
`u64e2/README.md`. Kurz, mit xPack RISC-V GCC 11.3.0-1 und 64tass:

```sh
cd u64e2
python3 build.py --toolchain /pfad/xpack-riscv-none-elf-gcc-11.3.0-1 --tass 64tass --work-dir build-work
```

Auf macOS arm64 kam dabei bytegleich die getestete CFW heraus (sha256
`b35d48c1…f64e`). Die ESP-App entsteht mit ESP-IDF v5.3.1 (Commit `c8fc5f64`):
`python3 esp/build.py wic64 --work-dir esp-build`, danach
`build.py … --esp-app esp-build/WiC64_ESP.ESP`.

**C64U** (`c64u/`, Ubuntu 24.04 x86_64 oder WSL2): `./setup.sh`, dann
`./build.sh all`. Siehe `c64u/README.md`.

Das Control Center (`WIC64CC.PRG`) liegt wie in den Originalpaketen nur als
Programmdatei bei.

## Lizenz

GPL-3.0-or-later (siehe `LICENSE`). Fremdteile behalten ihre Lizenzen:
`u64e2/licenses/`, `u64e2/NOTICES.txt`, `c64u/LICENSES/`,
`c64u/THIRD_PARTY_NOTICES.txt`. Grundlage ist die 1541-Ultimate-Firmware von
Gideon Zweijtzer; verwendet werden wolfSSL, mbedTLS, ESP-IDF, lwIP, FreeRTOS
und die WiC64-API.
