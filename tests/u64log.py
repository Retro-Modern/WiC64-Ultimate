#!/usr/bin/python3
"""Firmware-Log der Ultimate ueber das Telnet-Menue abschreiben (Strg+L).

    python3 -I u64log.py > log.txt
    python3 -I u64log.py | grep -v 'Accept client\\|GET /v1/info\\|GET /v1/drives'

Das Log (96 KB Ringpuffer) zeigt u.a. GURU MEDITATION samt Taskliste, wenn
ein Task der Firmware abstuerzt. So wurde am 07.11.2026 der "Menue-Haenger"
als Absturz des Tasks "UII Main" erkannt. Programme, die die Ultimate
ueberwachen, fragen oft /v1/info und /v1/drives ab; diese Zeilen herausfiltern.
Die ersten Zeichen jeder Zeile koennen fehlen (Fensterrand des Editors).
"""
import importlib.util
import os
import socket

HIER = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("t", os.path.join(HIER, "telnetmenue.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

s = socket.create_connection((t.HOST, 23), timeout=5)
t.lesen(s, 1.5)
s.sendall(b"\x0c")  # Strg+L: Log im Editor zeigen
t.lesen(s, 1.5)
vorher = None
for _ in range(600):
    seite = ["".join(t.scr[r])[3:62].rstrip() for r in range(3, 22)]
    if seite == vorher:
        break
    print("\n".join(seite))
    vorher = seite
    s.sendall(b"\x1b[6~")  # Bild runter
    t.lesen(s, 0.25)
s.sendall(b"\x1b")
t.lesen(s, 0.5)
s.close()
