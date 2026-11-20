WiC64 for the MiSTer C64 core - version 1.0 (2026-11-20)
Retro-Modern - https://retro-modern.net

A WiC64 on the user port of the MiSTer C64 core, no extra hardware. The
core passes the user port over the MiSTer's serial line to a small service
on MiSTer Linux, which answers the WiC64 commands using the MiSTer's network
(LAN or WLAN). Programs see a WiC64 with firmware 2.4.4.

Not a product of the WiC64 team but a re-creation. Please send questions
and bug reports to Retro-Modern, not to the WiC64 team.


CONTENTS

  _Computer/C64_WiC64_20261120.rbf   C64 core with WiC64 (MiSTer-devel
                                     C64_MiSTer as of 2026-10-29)
  linux/wic64/wic64d.py              the service (Python 3, part of
                                     MiSTer Linux)
  Scripts/wic64_einrichten.sh        set up and start the service
  Scripts/wic64_entfernen.sh         stop and remove the service
  WiC64-MiSTer/                      this text, sources, license


SETUP

1. Copy the folders _Computer, linux and Scripts to the root of the MiSTer
   SD card (merge with the existing folders).
2. MiSTer menu: Scripts > wic64_einrichten. This adds the service to
   linux/user-startup.sh (backup: user-startup.sh.vor-wic64) and starts it
   right away. It starts by itself after every reboot.
3. Load Computer > C64_WiC64. In the OSD (F12):
     Hardware > WiC64 (Userport) = Enabled
     UART Mode                   = None
   and save the settings.

The service only acts while the C64 core is running; other cores are not
affected. If a UART mode is set (modem, MIDI ...), it stays out of the way.

Try it: load the WiC64 launcher from https://wic64.net (portal with SID
radio and programs), or the WiC64 Control Center.

Remove: Scripts > wic64_entfernen. Delete the core and linux/wic64 by hand
if you like.


WHAT WORKS

- all commands of WiC64 firmware 2.4.4: HTTP, HTTPS (certificates are
  verified), POST, TCP, time/time zone, server, security token, protocols
  W, R and E (responses above 64 KB)
- plus the PORT64 extensions of the Ultimate 64 version: UDP ($33-$35, also
  the old $0A/$0B/$0E/$1E/$1F), IP info ($3A), WLAN state ($3D), ping ($3E),
  speed test ($3F), TLS socket ($40), bearer tokens ($42)

Measured on a MiSTer on LAN: HTTPS pages in about 0.3 s, 35 KB over HTTPS
in 3.5 s (about 10 KB/s including the C64 receive loop), SID radio and the
portal work, Control Center "Run Safe" all PASS.


DIFFERENCES

- MiSTer Linux manages the network. WLAN settings from the C64 ($02/$0D)
  change nothing; WPS, forgetting WLAN and static IP are not available.
  $0C shows the current network.
- No firmware updates ($27).
- Build info $41 is left out on purpose: Control Center 1.2.2 locks itself
  on an unknown provider ID. Without $41 it treats the MiSTer like a real
  WiC64 and shows the PORT64 tests as "not supported".
- The MiSTer reports its own MAC address, so the WiC64 portal sees it as a
  separate device (log in once).


TROUBLESHOOTING

Is it running?     over SSH or terminal:  ps | grep wic64d
See requests:      Scripts > wic64_entfernen, then over SSH
                     WIC64D_LOG=1 python3 /media/fat/linux/wic64/wic64d.py
                   (afterwards run wic64_einrichten again)
Settings:          linux/wic64/wic64d.json (server, time zone, token)


SOURCES AND LICENSE

The core is MiSTer-devel/C64_MiSTer (commit 88354ba, GPL-2.0-or-later)
with the patch in WiC64-MiSTer/quellen/c64-wic64.patch and the bridge
wic64_bridge.sv (GPL-3.0-or-later), so the core in this package is under
GPL-3.0 (text: WiC64-MiSTer/GPL-3.0.txt). To build: apply the patch to that
commit, copy wic64_bridge.sv to rtl/, compile with Quartus Lite 17.0.
Details (German): WiC64-MiSTer/quellen/LIESMICH.md.

wic64d.py: GPL-3.0-or-later. The command set follows the WiC64 firmware
(github.com/WiC64-Team/wic64-firmware, BSD-2-Clause, Henning Liebenau).

https://retro-modern.net
