# WiC64 für den Ultimate 64 der ersten Generation (U64-I)

Die WiC64-Emulation aus `u64e2/` auf dem Ultimate 64 / Ultimate 64 Elite
der **ersten Generation** (Nios II, Firmware 3.15a). Fertiges Paket:
`release/u64i-b5rm3/`.

Gepflegt von [Retro-Modern](https://retro-modern.net), Downloads unter
<https://retro-modern.net/downloads.html#wic64>.

## Bauen

```
u64i/werkzeug/nios2-toolchain.sh   # einmal: nios2-elf GCC 13.3 nach ~/opt/nios2-elf-gcc13
u64i/bauen.sh <arbeitsordner>      # ~30 s, ergibt WiC64_U64I_B5RM3.u64
```

`bauen.sh` holt Gideons 1541ultimate bei `dddd29b2` (3.15a), legt
`u64e2/native/software` darüber, spielt `patches/u64i.patch` ein, baut
wolfSSL aus `u64e2/crypto` für den Nios (`werkzeug/wolfssl_nios2.py`)
und die Firmware mit `WIC64_RAM=1` und
`-DP08_SERVICE=1 -DP05_RAM_DIAGNOSTIC=1 -DP14_TLS=1`. Kein `P18`: Der
ESP32 der ersten Generation ist kein S3, die ESP-TLS-App läuft dort nicht.

Das Abbild (`werkzeug/u64_abbild.py`) hat Gideons Updater-Format:
Ladeadresse `0x03000000`, Länge, Einsprung, danach die Bytes. „Run Update“
lädt es in den Updater-Bereich und springt hinein, der Flash bleibt
unberührt.

## Was der Patch ändert

| Datei | Warum |
|---|---|
| `target/u64/nios2/ultimate/Makefile` | WiC64-Quellen, wolfSSL, `WIC64_RAM` (eigener Linker, `alt_load.c`) |
| `target/u64/nios2/ultimate/wic64_ram_linker.x` | alles ab `0x03000000` (bis `0x03C00000`), Ausnahmen nach `0x0` |
| `software/portable/nios/alt_do_ctors.c` | GCC 13 legt `-1`/`0` in die `.ctors`-Liste; Gideons Schleife rief sie auf → Absturz |
| `software/drive/p14_platform.cc` | Kein FPGA-Sekundenzähler (der U64-I hat einen I2C-RTC): Software-UTC, bei jedem SNTP verankert |
| `software/io/c64/c64_subsys.cc` | WLAN-Teil der WiC64 auch für `U64 == 1` |
| `software/system/memory_wrap.cc` | `__dso_handle` schwach (neuere GCC bringen ihn mit) |
| `software/portable/nios/sys/reent.h` | Gideons altes newlib-Header beiseite (newlib 4) |
| `target/common/rules.mk` | `gitinfo.h` atomar schreiben (Wettlauf bei `-j`) |

## HTTPS

Ohne ESP-App kommt der TLS-Startwert aus einer `.W64`-Datei
(`werkzeug/w64_erzeugen.py`, Format in `p14_platform.cc`:
`import_setup`). Einmal im Dateibrowser „Set up WiC64 HTTPS“, danach
liegt er im Flash (WiC64-Bereich in Gideons Config-Seiten).

Messung 15.11.2026, Elite der ersten Generation, LAN und WLAN gleich:
HTTP example.com 0,3 s; HTTPS api.github.com/zen 7,3 s, 35 KB 13,9 s,
retro-modern.net/robots.txt 9,1 s, example.com 6,9 s (alles mit `$32`,
60 s). Radio und Portal gehen.
