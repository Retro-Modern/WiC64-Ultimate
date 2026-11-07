#!/usr/bin/python3
"""Telnet-Menue der Ultimate (Port 23) fernbedienen und als Text ausgeben.

    python3 -I telnetmenue.py f5 down down right     # WiC64-Untermenue zeigen
    python3 -I telnetmenue.py f5 down down right down ret warte2

Tasten: f1..f8 up down left right ret esc space del, warteN (N Sekunden),
sonst wird der Text getippt. Mit '!' davor (z.B. !ret) wird der Schirm nach
dieser Taste ausgegeben, am Ende immer. Jede Verbindung startet im
Hauptverzeichnis; die Markierung (gruen) steht in der Zeile "gruen:".

Warum Telnet: Unter der WiC64-CFW BETA3 hing das Bildschirmmenue nach
schnellem Schliessen/Oeffnen per REST (menu_button), das Telnet-Menue nicht.
Im WiC64-Untermenue werden ausgegraute Punkte (Start/Stop) beim Zaehlen
uebersprungen - immer erst die Markierung pruefen, dann ret.
"""
import os
import re
import socket
import sys
import time

HOST = os.environ.get("U64_IP")
if not HOST:
    sys.exit("U64_IP setzen, z.B. U64_IP=192.168.1.64 python3 -I telnetmenue.py ...")

KEYS = {"up": b"\x1b[A", "down": b"\x1b[B", "right": b"\x1b[C", "left": b"\x1b[D",
        "ret": b"\r", "esc": b"\x1b", "space": b" ", "del": b"\x7f",
        "f1": b"\x1bOP", "f2": b"\x1bOQ", "f3": b"\x1bOR", "f4": b"\x1bOS",
        "f5": b"\x1b[15~", "f6": b"\x1b[17~", "f7": b"\x1b[18~", "f8": b"\x1b[19~"}

W, H = 80, 30
scr = [[" "] * W for _ in range(H)]
cur = [0, 0]
mark = {}
gruen = [False]


def feed(d):
    i = 0
    while i < len(d):
        c = d[i]
        if c == 0xff:  # telnet IAC
            i += 3 if i + 1 < len(d) and d[i + 1] in (251, 252, 253, 254) else 2
            continue
        if c == 0x1b:
            m = re.match(rb"\x1b\[([0-9;?]*)([A-Za-z])", d[i:])
            if m:
                a, f = m.group(1).decode(), m.group(2).decode()
                n = [int(x) if x.isdigit() else 0 for x in a.split(";")] if a else []
                if f in "Hf":
                    cur[0] = (n[0] if n and n[0] else 1) - 1
                    cur[1] = (n[1] if len(n) > 1 and n[1] else 1) - 1
                elif f == "J":
                    for r in range(H):
                        scr[r] = [" "] * W
                elif f == "K":
                    for x in range(cur[1], W):
                        if cur[0] < H:
                            scr[cur[0]][x] = " "
                elif f == "m":
                    if a.startswith("0;"):
                        gruen[0] = a.startswith("0;32;1")
                elif f == "C":
                    cur[1] += n[0] if n else 1
                i += len(m.group(0))
                continue
            i += 3 if i + 1 < len(d) and d[i + 1] in b"()" else 2
            continue
        if c == 13:
            cur[1] = 0
        elif c == 10:
            cur[0] += 1
        elif c >= 32:
            if cur[0] < H and cur[1] < W:
                scr[cur[0]][cur[1]] = chr(c) if c < 127 else "."
                if 32 < c < 127:
                    mark[(cur[0], cur[1])] = gruen[0]
            cur[1] += 1
        i += 1


def lesen(s, t=0.8):
    s.settimeout(t)
    try:
        while True:
            x = s.recv(8192)
            if not x:
                break
            feed(x)
    except socket.timeout:
        pass


def zeigen():
    for r in range(H):
        z = "".join(scr[r]).rstrip()
        if z:
            print("%2d  %s" % (r, z))
    gr = ["".join(scr[r][x] for x in range(W) if mark.get((r, x)) and scr[r][x] != " ")
          for r in range(H)]
    print("gruen:", [(r, g) for r, g in enumerate(gr)
                     if g and g not in ("Nomedia", "Ready", "LinkUp")])
    print("-" * 40)


def main():
    s = socket.create_connection((HOST, 23), timeout=5)
    lesen(s, 1.5)
    for k in sys.argv[1:]:
        show = k.startswith("!")
        k = k.lstrip("!")
        if k.startswith("warte"):
            time.sleep(float(k[5:] or 1))
            lesen(s, 0.5)
            if show:
                print("nach %s:" % k)
                zeigen()
            continue
        s.sendall(KEYS.get(k, k.encode()))
        lesen(s, 0.6)
        if show:
            zeigen()
    zeigen()
    s.close()


if __name__ == "__main__":
    main()
