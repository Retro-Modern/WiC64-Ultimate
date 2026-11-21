#!/bin/sh
# WiC64 fuer den C64-Kern - einrichten / set up (Fassung 1.1)
# Retro-Modern - https://retro-modern.net
#
# Traegt den WiC64-Dienst in /media/fat/linux/user-startup.sh ein und startet
# ihn sofort. Mehrfaches Aufrufen schadet nicht. Eine Einrichtung der Fassung
# 1.0 (Dienst unter linux/wic64) wird samt Einstellungen umgezogen.
# Adds the WiC64 service to user-startup.sh and starts it right away.

DIENST=/media/fat/Scripts/.config/wic64/wic64d.py
ALT=/media/fat/linux/wic64/wic64d.py
US=/media/fat/linux/user-startup.sh
ANFANG="# >>> WiC64 fuer den C64-Kern (retro-modern.net)"
ENDE="# <<< WiC64"

if [ ! -f "$DIENST" ]; then
	echo "Fehlt / missing: $DIENST"
	echo "Bitte den Ordner Scripts aus dem Paket auf die SD-Karte kopieren."
	echo "Please copy the Scripts folder from the package to the SD card."
	exit 1
fi
if ! command -v python3 > /dev/null 2>&1; then
	echo "python3 fehlt / missing - MiSTer-Linux bitte aktualisieren."
	exit 1
fi

# Einstellungen der Fassung 1.0 uebernehmen / keep settings from 1.0
if [ -f /media/fat/linux/wic64/wic64d.json ] && [ ! -f /media/fat/Scripts/.config/wic64/wic64d.json ]; then
	cp /media/fat/linux/wic64/wic64d.json /media/fat/Scripts/.config/wic64/wic64d.json
	echo "Einstellungen uebernommen / settings taken over (wic64d.json)."
fi

# Laufende Dienste anhalten (neuer und alter Ort): erst die Neustart-
# Schleife, dann den Dienst - nur diese Befehlszeilen, sonst nichts.
stoppen() {
	for muster in "sh -c while true; do python3 $DIENST" "sh -c while true; do python3 $ALT" \
	              "python3 $DIENST" "python3 $ALT"; do
		for f in /proc/[0-9]*/cmdline; do
			case "$(tr '\0' ' ' 2> /dev/null < "$f")" in
				"$muster"*)
					p=${f#/proc/}
					kill "${p%/cmdline}" 2> /dev/null ;;
			esac
		done
	done
}

if [ ! -f "$US" ]; then
	printf '#!/bin/sh\n\necho "***" $1 "***"\n' > "$US"
fi

# Den eigenen Block (auch den alten von 1.0) herausnehmen und neu schreiben.
if grep -q "^$ANFANG" "$US"; then
	cp "$US" "$US.vor-wic64"
	awk '
		/^# >>> WiC64/ { weg = 1 }
		!weg { print }
		/^# <<< WiC64/ { weg = 0 }
	' "$US.vor-wic64" > "$US"
elif ! grep -q "wic64d.py" "$US"; then
	cp "$US" "$US.vor-wic64"
fi
if grep -q "wic64d.py" "$US"; then
	echo "user-startup.sh enthaelt WiC64-Zeilen, die nicht von diesem Skript stammen."
	echo "Bitte von Hand entfernen und das Skript noch einmal starten."
	echo "user-startup.sh has WiC64 lines not written by this script - please remove them by hand."
	exit 1
fi
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
echo "user-startup.sh: eingetragen / added (Sicherung / backup: user-startup.sh.vor-wic64)"

stoppen
sleep 1
setsid sh -c "while true; do python3 $DIENST; sleep 2; done" > /dev/null 2>&1 < /dev/null &
echo "Dienst gestartet / service started."

if [ -f "$ALT" ]; then
	echo
	echo "Der Ordner linux/wic64 (Fassung 1.0) wird nicht mehr gebraucht und kann weg."
	echo "The folder linux/wic64 (version 1.0) is no longer needed and can be deleted."
fi
sync
echo
echo "Fertig. Im C64-Kern: OSD > Hardware > WiC64 (Userport) = Enabled, UART Mode = None."
echo "Done. In the C64 core: OSD > Hardware > WiC64 (Userport) = Enabled, UART Mode = None."
