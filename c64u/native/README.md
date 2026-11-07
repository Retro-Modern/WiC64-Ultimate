# WiC64 C64U Beta2

Native Firmwarequellen für Linux x86_64 bzw. Ubuntu 24.04 unter WSL2.
Benötigt werden Bash, Python 3.12 und die üblichen C/C++-Entwicklungswerkzeuge.

Im Hauptverzeichnis `./setup.sh` und danach `./build.sh all` ausführen.
Das Setup lädt die gepinnten Compiler-, Bibliotheks- und Buildabhängigkeiten
nach `.deps`. Die native Firmware übernimmt die dabei aus den ESP-Quellen
gebaute Anwendung und die Prüfdaten der ESP-Rückkehrdatei.
Ausgabe: `native/build/WiC64_C64U_Beta2.ue2`.

Für einen einzelnen nativen Neubau nach dem ESP-Build:

```sh
./native/build.sh --clean --jobs 6
```
