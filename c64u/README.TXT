WiC64 C64U B2RM1
Commodore C64 Ultimate / Firmware 1.1.0
Retro-Modern - https://retro-modern.net

B2RM1 = WiC64 C64U Beta 2 von TheRealWanderer plus zwei Korrekturen
von Retro-Modern / Beta 2 by TheRealWanderer plus two fixes:
- WiC64 bleibt nach einem C64-Reset nutzbar (auch PRG/CRT-Start ueber
  REST) / WiC64 survives a C64 reset (also PRG/CRT starts via REST)
- HTTPS-Rueckfallweg auf der CPU mit WOLFSSL_ALT_CERT_CHAINS (wie
  Elite II) / HTTPS fallback on the CPU with WOLFSSL_ALT_CERT_CHAINS

NICHT AM C64U GETESTET - Retro-Modern hat kein Geraet. Dieselben
Aenderungen laufen auf der Ultimate 64 Elite II (B5RM3). Im Zweifel
zurueck zu Beta 2 von TheRealWanderer.
NOT TESTED ON A C64U - Retro-Modern has no device. The same changes run
on the Ultimate 64 Elite II (B5RM3). If in doubt, go back to Beta 2.

DEUTSCH

Installation
1. ZIP samt Ordner WiC64 ins Hauptverzeichnis eines USB-Sticks
   entpacken. Die Ordnerstruktur beibehalten.
2. C64U aus-/einschalten. Im Dateibrowser WiC64_C64U_B2RM1.ue2
   auswählen und mit "Run Update" laden.
3. Im F1-Menü unter "WiC64" die gewünschte LAN-/WLAN-Verbindung
   wählen und "WiC64 Portal" starten.
4. Wird eine ESP-Installation angeboten, mit "Yes" bestätigen und
   die Fortschrittsanzeige bis zur Abschlussmeldung abwarten.
   Währenddessen nicht ausschalten. Danach WiC64 erneut starten.

Die UE2 muss nach jedem Aus-/Einschalten erneut geladen werden.
Die Installation auf dem ESP bleibt gespeichert.

Control Center: WiC64/WIC64CC.PRG muss auf dem USB-Stick bleiben.
Es wird über das F1-Menü unter "WiC64" gestartet und von dort geladen.

Deinstallation / ESP auf Firmware 1.11 zurücksetzen
1. WiC64_C64U_B2RM1.ue2 muss aktiv sein; falls nötig mit "Run Update"
   laden. Laufendes WiC64 im F1-Menü mit "Stop WiC64" beenden.
   Unter "WiC64 Status" auf IDLE oder RESTORED warten.
2. Im Dateibrowser C64U_ESP_STOCK_1.11.ESP auswählen und im
   Dateimenü "Flash into ESP32" wählen. Mit "Yes" bestätigen.
3. Nicht ausschalten, bis die Meldung "ESP application installed.
   Module restarted." erscheint.
4. Danach C64U aus-/einschalten. Das Gerät startet mit der
   gespeicherten Commodore-Firmware und der ESP-Firmware 1.11.

ENGLISH

Installation
1. Extract the ZIP, including the WiC64 folder, to the root of a
   USB drive. Keep the folder structure.
2. Power-cycle the C64U. In the file browser, select
   WiC64_C64U_B2RM1.ue2 and choose "Run Update".
3. Open "WiC64" in the F1 menu, select the desired LAN/WLAN
   connection and launch "WiC64 Portal".
4. If an ESP installation is offered, confirm with "Yes" and wait
   for the progress display and completion message. Do not switch
   off during installation. Then start WiC64 again.

Reload the UE2 after each power-cycle.
The installation on the ESP remains stored.

Control Center: Keep WiC64/WIC64CC.PRG on the USB drive.
Launch it from "WiC64" in the F1 menu; it is loaded from that file.

Uninstallation / restore ESP firmware 1.11
1. WiC64_C64U_B2RM1.ue2 must be running; load it with "Run Update"
   if necessary. Select "Stop WiC64" in the F1 menu and wait for
   IDLE or RESTORED in "WiC64 Status".
2. In the file browser, select C64U_ESP_STOCK_1.11.ESP and choose
   "Flash into ESP32" from its file menu. Confirm with "Yes".
3. Do not switch off until "ESP application installed.
   Module restarted." is displayed.
4. Power-cycle the C64U. It starts with the stored Commodore
   firmware and ESP firmware 1.11.

Source / Quellen: https://github.com/Retro-Modern/WiC64-Ultimate (c64u/)
https://retro-modern.net/downloads.html#wic64
