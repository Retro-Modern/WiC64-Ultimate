#!/bin/sh
# WiC64 fuer den C64-Kern - einrichten / set up
# Retro-Modern - https://retro-modern.net
#
# Traegt den WiC64-Dienst in /media/fat/linux/user-startup.sh ein und startet
# ihn sofort. Mehrfaches Aufrufen schadet nicht.
# Adds the WiC64 service to user-startup.sh and starts it right away.

DIENST=/media/fat/linux/wic64/wic64d.py
US=/media/fat/linux/user-startup.sh
ANFANG="# >>> WiC64 fuer den C64-Kern (retro-modern.net)"
ENDE="# <<< WiC64"

if [ ! -f "$DIENST" ]; then
	echo "Fehlt / missing: $DIENST"
	echo "Bitte den Ordner linux/wic64 aus dem Paket auf die SD-Karte kopieren."
	exit 1
fi
if ! command -v python3 > /dev/null 2>&1; then
	echo "python3 fehlt / missing - MiSTer-Linux bitte aktualisieren."
	exit 1
fi

# Laeuft der Dienst? Nur die eigene Befehlszeile zaehlt, nicht irgendein
# Prozess, der "wic64d" im Text hat.
laeuft() {
	for f in /proc/[0-9]*/cmdline; do
		case "$(tr '\0' ' ' < "$f" 2> /dev/null)" in
			"python3 $DIENST "*) return 0 ;;
		esac
	done
	return 1
}

if [ ! -f "$US" ]; then
	printf '#!/bin/sh\n\necho "***" $1 "***"\n' > "$US"
fi

if grep -q "wic64d.py" "$US"; then
	echo "user-startup.sh: WiC64 ist schon eingetragen / already set up."
else
	cp "$US" "$US.vor-wic64"
	cat >> "$US" <<EOF

$ANFANG
# Beantwortet die WiC64-Befehle vom Userport (OSD: WiC64 (Userport) =
# Enabled, UART Mode = None). Arbeitet nur, solange der C64-Kern laeuft.
# Die Schleife startet den Dienst neu, falls ihn uartmode beendet.
if [ "\$1" = "start" ] && [ -f $DIENST ]; then
	setsid sh -c "while true; do python3 $DIENST; sleep 2; done" > /dev/null 2>&1 < /dev/null &
fi
$ENDE
EOF
	echo "user-startup.sh: eingetragen / added (Sicherung: user-startup.sh.vor-wic64)"
fi

if laeuft; then
	echo "Dienst laeuft schon / service already running."
else
	setsid sh -c "while true; do python3 $DIENST; sleep 2; done" > /dev/null 2>&1 < /dev/null &
	echo "Dienst gestartet / service started."
fi
sync
echo
echo "Fertig. Im C64-Kern: OSD > Hardware > WiC64 (Userport) = Enabled, UART Mode = None."
echo "Done. In the C64 core: OSD > Hardware > WiC64 (Userport) = Enabled, UART Mode = None."
