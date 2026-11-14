WiC64 U64E2 B5RM3 (14.11.2026)
WiC64 2.4.4 / PORT64 1.1.4 - TheRealWanderers Beta 5, weitergepflegt
von Retro-Modern / maintained by Retro-Modern

DEUTSCH

Installation
1. ZIP entpacken und alle Dateien einschließlich des Ordners WiC64
   auf USB oder SD kopieren. Die Ordnerstruktur beibehalten.
2. Ultimate vollständig aus- und einschalten. Im Dateibrowser
   WiC64_U64E2_B5RM3.cfw auswählen und mit "Run Update" laden.
3. F5 -> WiC64 öffnen, unter "Connection" Auto, LAN oder WLAN wählen
   und "Start WiC64" oder "WiC64 Portal" aufrufen.
4. Wird die Installation der eingebetteten ESP-Firmware angeboten,
   bestätigen und den vollständigen Abschluss abwarten. Danach Ultimate
   vollständig aus- und einschalten, die CFW erneut laden und WiC64 starten.

Die CFW läuft im RAM und muss nach dem Ausschalten erneut geladen werden.
Die ESP-Firmware bleibt gespeichert. Während des Flashens nicht ausschalten.
Das mitgelieferte Control Center liegt unter WiC64/WIC64CC.PRG.
Zum Starten F5 -> WiC64 -> WiC64 Control Center wählen.

Deinstallation / ESP wiederherstellen
1. Die WiC64-CFW laden, falls sie nicht bereits läuft.
   "Stop WiC64" wählen, falls WiC64 aktiv ist. Die CFW geladen lassen.
2. Im Dateibrowser U64E2_ESP_RESTORE.ESP auswählen und
   "Flash into ESP32" aufrufen. Bestätigen und den Abschluss abwarten.
   Während des Flashens nicht ausschalten.
3. Ultimate vollständig aus- und einschalten. Die WiC64-CFW nicht laden,
   um die reguläre Ultimate-Firmware zu verwenden.

Die ESP-Datei stellt die Stock-App 1.21 wieder her. Sie ist kein Backup
der individuellen Geräteeinstellungen oder des gesamten ESP-Flashs.

Neu in B5RM3
- WiC64 bleibt nach einem C64-Reset nutzbar (wie ein echter WiC64 am
  Userport). Bisher ging er bei jedem Reset - auch beim Starten eines
  Programms oder Moduls über das Menü oder die REST-Schnittstelle - in
  den Fehlerzustand "C64_RESET_NOTIFIED" und antwortete nicht mehr, bis
  man ihn von Hand stoppte und neu startete. Jetzt startet er nach etwa
  1 s von selbst neu. Ein gestoppter WiC64 bleibt gestoppt.

Änderungen gegenüber Beta 5 (B5RM2)
- ESP-App B5RM1: Zertifikatsketten über eigene Wurzeltabelle (wie C64U
  Beta 2). Ältere ESP-Apps (Beta 4, Beta 5) bekommen das Update angeboten.
- "Flash into ESP32" prüft die Datei nur noch einmal (im RAM), mit
  Fortschrittsbalken: Rückfrage nach ~45 s statt über 100 s.
- WiC64 Status zeigt die richtige Version (vorher "Beta 4").

ENGLISH

Installation
1. Extract the ZIP and copy all files, including the WiC64 folder,
   to USB or SD. Keep the folder structure intact.
2. Fully power-cycle the Ultimate. In the file browser, select
   WiC64_U64E2_B5RM3.cfw and choose "Run Update".
3. Open F5 -> WiC64, select Auto, LAN or WLAN under "Connection"
   and choose "Start WiC64" or "WiC64 Portal".
4. If prompted to install the embedded ESP firmware, confirm and wait
   for completion. Then fully power-cycle the Ultimate, load the CFW
   again and start WiC64.

The CFW runs in RAM and must be loaded again after power-off.
The ESP firmware remains installed. Do not switch off while flashing.
The supplied Control Center is located at WiC64/WIC64CC.PRG.
To launch it, choose F5 -> WiC64 -> WiC64 Control Center.

Uninstallation / ESP restore
1. Load the WiC64 CFW if it is not already running. Choose "Stop WiC64"
   if WiC64 is active. Keep the CFW loaded for the next step.
2. In the file browser, select U64E2_ESP_RESTORE.ESP and choose
   "Flash into ESP32". Confirm and wait for completion.
   Do not switch off while flashing.
3. Fully power-cycle the Ultimate. Leave the WiC64 CFW unloaded
   to use the regular Ultimate firmware.

The ESP file restores the stock 1.21 app. It is not a backup of your
individual device settings or the entire ESP flash.

New in B5RM3
- WiC64 stays usable across a C64 reset (like a real WiC64 on the user
  port). Previously every reset - including starting a program or
  cartridge from the menu or the REST API - put it into the error state
  "C64_RESET_NOTIFIED", and it stopped answering until it was stopped and
  started again by hand. It now restarts on its own within about 1 s.
  A stopped WiC64 stays stopped.

Changes since Beta 5 (B5RM2)
- ESP app B5RM1: certificate chains are built from its own root table
  (as in C64U Beta 2). Older ESP apps (Beta 4, Beta 5) are offered the update.
- "Flash into ESP32" verifies the file only once (in RAM), with a progress
  bar: the prompt appears after ~45 s instead of more than 100 s.
- WiC64 Status shows the correct version (previously "Beta 4").

Firmware: GPL-3.0-or-later. Quellen / sources: https://github.com/Retro-Modern/WiC64-Ultimate
