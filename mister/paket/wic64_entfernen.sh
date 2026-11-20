#!/bin/sh
# WiC64 fuer den C64-Kern - entfernen / remove
# Retro-Modern - https://retro-modern.net
#
# Haelt den WiC64-Dienst an und nimmt ihn aus user-startup.sh heraus.
# Der Ordner linux/wic64 und der Kern bleiben liegen.
# Stops the WiC64 service and removes it from user-startup.sh.

US=/media/fat/linux/user-startup.sh

DIENST=/media/fat/linux/wic64/wic64d.py
# Erst die Neustart-Schleife, dann den Dienst - nur diese beiden Befehlszeilen.
for muster in "sh -c while true; do python3 $DIENST" "python3 $DIENST"; do
	for f in /proc/[0-9]*/cmdline; do
		case "$(tr '\0' ' ' < "$f" 2> /dev/null)" in
			"$muster"*)
				p=${f#/proc/}
				kill "${p%/cmdline}" 2> /dev/null ;;
		esac
	done
done
echo "Dienst angehalten / service stopped."

if [ -f "$US" ] && grep -q "wic64d.py" "$US"; then
	cp "$US" "$US.mit-wic64"
	awk '
		/^# >>> WiC64/ { weg = 1 }
		!weg { print }
		/^# <<< WiC64/ { weg = 0 }
	' "$US.mit-wic64" > "$US"
	if grep -q "wic64d.py" "$US"; then
		cp "$US.mit-wic64" "$US"
		echo "user-startup.sh: WiC64-Zeilen von Hand entfernen (nicht vom Einrichtungsskript)."
		echo "Please remove the WiC64 lines from user-startup.sh by hand."
	else
		echo "user-startup.sh: ausgetragen / removed (Sicherung: user-startup.sh.mit-wic64)"
	fi
fi
sync
