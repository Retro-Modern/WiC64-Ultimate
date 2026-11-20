# WiC64 für den C64-Kern des MiSTer

Eine WiC64 am Userport des C64-Kerns, ohne Zusatzhardware. Der Kern reicht
die Userport-Seite über die serielle Leitung des MiSTer an einen kleinen
Dienst auf dem Linux-Teil weiter, und der beantwortet die WiC64-Befehle mit
dem Netz des MiSTer (LAN oder WLAN).

Gepflegt von [Retro-Modern](https://retro-modern.net).

```
C64 (CIA 2: PB0-7, PA2, PC2, FLAG2)
  └─ rtl/wic64_bridge.sv  im Kern, Handshake wie die WiC64-Firmware 2.x
       └─ UART 1 562 500 Baud ── /dev/ttyS1 ── linux/wic64d.py (Python 3)
                                                 └─ HTTP/HTTPS/TCP übers Netz
```

## Teile

| Datei | Was |
|---|---|
| `rtl/wic64_bridge.sv` | Brücke im FPGA: quittiert Bytes vom C64 selbst (FLAG2), liefert Antwortbytes je PC2, 4-KB-Puffer, Kreditrechnung |
| `patches/c64-wic64.patch` | `c64.sv`: Menüpunkt *Hardware → WiC64 (Userport)* (Status-Bit 99), Einbau der Brücke; `files.qip` |
| `linux/wic64d.py` | Dienst auf dem MiSTer, Befehlssatz der WiC64-Firmware 2.x |
| `linux/test_wic64d.py` | Test am Mac: FPGA und C64 (`wic64.asm`) als Modell, eigener HTTP-/TCP-Server |
| `sim/tb_bridge.sv` | Testbank der Brücke (iverilog): C64 wie `wic64.asm`, Linux als UART-Modell |
| `bauen.sh`, `bau.ps1` | Bau auf einem Windows-Rechner mit Quartus Lite 17.0 (per SSH) |
| `paket.py`, `paket/` | baut das Paket `dist/WiC64_MiSTer_<Fassung>.zip` |

Kern-Stand: MiSTer-devel/C64_MiSTer `88354ba` (29.10.2026).

## Leitung FPGA ↔ Linux

8N1 mit 1 562 500 Baud. Linux stellt `B1500000` ein; bei 100 MHz `uartclk`
ergibt das Teiler 4, also genau 1 562 500. Die Brücke zählt mit einem
24-Bit-Phasenakkumulator (PAL 831465, NTSC 800996).

Linux → FPGA: `10 n d…` DATA (n = 0 heißt 256), `11` HS (ein FLAG2-Puls),
`12` PING, `13` PB nach dem nächsten PC2 loslassen, `14` MARKE.
Jede **DTR-Flanke** verwirft die Warteschlange im FPGA (Antwort `04 00`).

FPGA → Linux, je zwei Bytes: `01 b` Byte vom C64, `02 l` PA2-Wechsel,
`03 k` Kredit (256 Befehlsbytes verbraucht), `04 00` verworfen, `05 00` Reset,
`06 v` PONG, `07 00` MARKE erreicht.

Antwort auf eine Anfrage: `11`, dann der Kopf und die Nutzdaten in
DATA-Rahmen, dann `14`. Der C64 holt jedes Byte mit einem Lesezugriff auf
`$dd01` (PC2) ab, die Brücke legt dann das nächste Byte an und pulst FLAG2.
Beginnt der C64 eine neue Anfrage (PA2 hoch), bevor die MARKE kam,
verwirft der Dienst den Rest per DTR.

## Dienst

Arbeitet nur, solange `/tmp/CORENAME` = `C64` ist und kein UART-Modus
(`/tmp/uartmode1…6`) läuft. Im OSD muss *UART Mode* auf **None** stehen.
Einstellungen (Server, Zeitzone, Security-Token, Bearer-Token) in
`wic64d.json` daneben, nur für root lesbar.
`WIC64D_LOG=1` protokolliert Anfragen, `=2` zusätzlich jedes Ereignis.

Auf dem MiSTer: `/media/fat/linux/wic64/wic64d.py`, gestartet aus
`/media/fat/linux/user-startup.sh`:

```sh
# WiC64 fuer den C64-Kern (retro-modern.net) - beantwortet die WiC64-Befehle
# vom Userport (OSD: WiC64 (Userport) = Enabled, UART Mode = None). Arbeitet
# nur, solange der C64-Kern laeuft. Die Schleife startet den Dienst neu, falls
# ihn das MiSTer-Skript uartmode beim Wechsel des UART-Modus beendet.
if [ "$1" = "start" ] && [ -f /media/fat/linux/wic64/wic64d.py ]; then
	setsid sh -c "while true; do python3 /media/fat/linux/wic64/wic64d.py; sleep 2; done" > /dev/null 2>&1 < /dev/null &
fi
```

Im Paket trägt `Scripts/wic64_einrichten.sh` einen gleichwertigen Block
(zwischen `# >>> WiC64` und `# <<< WiC64`) ein. Auf dem Testgerät steht er seit dem 20.11.2026 am Ende der
`user-startup.sh` (Sicherung davor: `user-startup.sh.vor-wic64`); nach einem
Neustart lief der Dienst von selbst und das Control Center fand die WiC64.

Die Schleife ist nötig, weil das MiSTer-Skript `uartmode` beim Wechsel
des UART-Modus alles beendet, was `/dev/ttyS1` offen hat.

Unterschiede zur echten WiC64: keine Firmware-Updates (`$27`), WLAN
verwaltet Linux (`$02`/`$0D` sind wirkungslos, `$0C` meldet das aktuelle
Netz), Antworten über 64 KB nur mit Protokoll `E`. Veraltete Befehle
antworten wie die Firmware mit Status 0 und dem Erklärtext.

### PORT64-Erweiterungen

Wie in unserer WiC64-Fassung für den Ultimate 64 (`u64e2/`, Quelle
`software/drive/p12_commands.cc`, `p15_network.cc`, `p08_http.cc`):

| Befehl | Am MiSTer |
|---|---|
| `$33`/`$34`/`$35` UDP Port, Senden, Empfangen (auch die alten `$0E`, `$0B`/`$1F`, `$0A`/`$1E`) | ja |
| `$3A` IP-Einstellungen (DHCP/STATIC, Adresse, Maske, Gateway, 2× DNS) | ja, nur lesen |
| `$3D` WLAN-Zustand | `02 00` mit Netz, sonst `00 00` |
| `$3E` Ping (4 ICMP-Echos, 25 Byte Antwort) | ja |
| `$3F` Speedtest (HTTP/HTTPS, 28 Byte Antwort) | ja |
| `$40` TLS-Sockel, Zertifikat geprüft, danach `$22`/`$23`/`$30`/`$2E` | ja |
| `$42` Bearer-Token (PORT64 und ein eigener Ursprung), nur über HTTPS und nur an den eigenen Ursprung, nach Weiterleitung nicht mehr | ja |
| `$36`–`$39`, `$3B`, `$3C`, `$43` (WPS, WLAN löschen, IP setzen, Web-Admin) | Status 1, das Netz gehört dem Linux |
| `$41` Build-Info | **absichtlich nicht** |

`$41` fehlt mit Absicht. Das WiC64 Control Center 1.2.2 kennt nur die
Anbieterkennung `U64 `. Meldet die Build-Info eine andere Kennung, sperrt
es sich ganz („Function blocked – unknown provider“). Ohne `$41` behandelt
es den Dienst wie eine echte WiC64 und testet die PORT64-Teile nicht mit
(„not supported“). Die prüft stattdessen `tests/port64probe.prg`.

## Prüfen

```
cd mister/sim && iverilog -g2012 -o tb.vvp tb_bridge.sv ../rtl/wic64_bridge.sv && vvp -n tb.vvp
python3 mister/linux/test_wic64d.py          # WIC64D_NETZ=0: ohne Internet-Tests
```

Am Gerät: `tests/port64probe.prg` (Quelle `.tass`, mit 64tass ohne `-a`) ruft
jeden PORT64-Befehl einmal auf; für Speedtest und UDP muss
`tests/port64gegenstelle.py` auf dem Rechner laufen, dessen Adresse in der
Quelle unter `MAC` steht.

## Messungen

MiSTer im LAN, 20.11.2026, Kern `C64_WIC64.rbf`, LAN:

- `tlsprobe.prg`: alle 9 Proben richtig (4 Seiten geladen, 5 kaputte
  Zertifikate abgelehnt, auch *incomplete-chain*). example.com per HTTPS
  0,32 s, retro-modern.net/robots.txt 0,23 s (erste U64: 9,1 s).
- WiC64 Control Center 1.2.2: *Run Safe* alles PASS (außer *Device build
  info*, PORT64-Erweiterung), *Plain TCP* PASS, *Binary Echo* PASS.
- Bau 2 (Verwerfen im selben Takt wie der Parser-Reset, `13` erst nach
  PC2): *Forced Timeout* und *One-shot Timeouts* PASS (mit Bau 1 hing die
  Brücke nach dem Verwerfen), *Read-only Core* alles PASS.
- `wic64test.prg`: 35 147 Bytes (LICENSE von GitHub per HTTPS) in 3,5 s,
  rund 10 KB/s einschließlich der Empfangsschleife am C64.
- Die Versionskennung muss genau die Form der Firmware haben (`2.4.4`);
  mit Zusatz („2.4.4 MiSTer“) meldet das Control Center *Version
  endpoints: FAIL*.
- `port64probe.prg` (20.11.2026): TLS-Sockel zu example.com öffnet, `HEAD`
  senden, Lesen liefert „HTTP/1.1 200 OK“; selbstsigniertes Zertifikat
  abgelehnt (Status 4); Ping zum Router 4/4; IP-Einstellungen DHCP
  mit Adresse/Maske; Speedtest 1 MB in 3 s, Ziel erreicht; UDP
  hin und zurück („HALLO VOM C64“); `$07` mit Status 0 und Text.
- `radiotest.prg`: httpbin (User-Agent, `%mac`/`%ser`) Status 0, 323 Bytes;
  Radio-Server `c64.route64.de:5555` Status 0, 2 940 Bytes in 0,7 s. Ein
  Radio-Programm selbst ist nicht ausprobiert.
- Control Center danach: *Run Safe* komplett PASS (Build-Info „not
  supported“).
- Belegung: 67 % der ALMs, Brücke rund 300 Logikzellen und 33 Kbit RAM;
  Timing überall positiv.
