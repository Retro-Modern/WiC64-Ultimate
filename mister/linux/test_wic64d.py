#!/usr/bin/env python3
# Test fuer wic64d.py am Mac: FPGA-Bruecke und C64 (wic64.asm) als Modell,
# dazu ein HTTP- und ein TCP-Server auf localhost.
#
#   python3 test_wic64d.py

import http.server, os, socket, socketserver, struct, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wic64d

wic64d.SETTINGS_FILE = "/tmp/wic64d-test.json"


class FpgaModel:
    """Verhaelt sich an der Leitung wie rtl/wic64_bridge.sv."""

    def __init__(self, sock):
        self.sock = sock
        self.lock = threading.Condition()
        self.cmdq = bytearray()
        self.state = "cmd"
        self.n = 0
        self.need_byte = False
        self.pulses = 0
        self.pb = 0xFF
        self.consumed = 0
        self.credit = 0
        self.wlock = threading.Lock()
        threading.Thread(target=self.reader, daemon=True).start()
        threading.Thread(target=self.parser, daemon=True).start()

    def ev(self, a, b):
        with self.wlock:
            self.sock.sendall(bytes([a, b]))

    def reader(self):
        while True:
            d = self.sock.recv(4096)
            if not d:
                return
            with self.lock:
                self.cmdq += d
                if len(self.cmdq) > 4096:
                    raise SystemExit("FIFO im FPGA uebergelaufen")
                self.lock.notify_all()

    def pop(self):
        b = self.cmdq.pop(0)
        self.consumed += 1
        if self.consumed % 256 == 0:
            self.credit = (self.credit + 1) & 255
            self.ev(3, self.credit)
        return b

    def parser(self):
        with self.lock:
            while True:
                progressed = False
                if self.state == "cmd" and self.cmdq:
                    c = self.pop()
                    progressed = True
                    if c == 0x10:
                        self.state = "len"
                    elif c == 0x11:
                        self.pulses += 1
                    elif c == 0x12:
                        self.ev(6, 1)
                    elif c == 0x14:
                        self.ev(7, 0)
                elif self.state == "len" and self.cmdq:
                    self.n = self.pop() or 256
                    self.state = "data"
                    progressed = True
                elif self.state == "data" and self.need_byte and self.cmdq:
                    self.pb = self.pop()
                    self.need_byte = False
                    self.pulses += 1
                    self.n -= 1
                    if self.n == 0:
                        self.state = "cmd"
                    progressed = True
                if progressed:
                    self.lock.notify_all()
                else:
                    self.lock.wait(0.05)

    def flush(self):                      # DTR-Flanke
        with self.lock:
            self.cmdq.clear()
            self.state = "cmd"
            self.need_byte = False
            self.consumed = self.credit = 0
            self.ev(4, 0)
            self.lock.notify_all()

    # ---- C64-Seite
    def pa2(self, level):
        with self.lock:
            if level:
                self.need_byte = False
            self.ev(2, level)

    def put(self, b):                     # sta $dd01, Bruecke quittiert
        with self.lock:
            self.ev(1, b)
            self.pulses += 1

    def wait_hs(self, timeout=12.0):
        end = time.time() + timeout
        with self.lock:
            while self.pulses == 0:
                if time.time() > end:
                    raise TimeoutError("kein FLAG2")
                self.lock.wait(0.05)
            self.pulses -= 1

    def read(self):                       # lda $dd01 -> PC2
        with self.lock:
            v = self.pb
            self.need_byte = True
            self.lock.notify_all()
            return v


def c64_request(f, proto, cmd, payload=b""):
    if proto == "W":
        hdr = bytes([ord("W"), (len(payload) + 4) & 255, (len(payload) + 4) >> 8, cmd])
    elif proto == "R":
        hdr = bytes([ord("R"), cmd, len(payload) & 255, len(payload) >> 8])
    else:
        hdr = bytes([ord("E"), cmd]) + struct.pack("<I", len(payload))
    f.pa2(1)
    for b in hdr + payload:
        f.put(b)
        f.wait_hs()
    f.pa2(0)
    f.wait_hs()                           # Antwort bereit
    f.read()                              # blind
    hsize = {"W": 2, "R": 3, "E": 5}[proto]
    h = []
    for _ in range(hsize):
        f.wait_hs()
        h.append(f.read())
    if proto == "W":
        status, size = None, h[0] << 8 | h[1]
    elif proto == "R":
        status, size = h[0], h[1] | h[2] << 8
    else:
        status, size = h[0], struct.unpack("<I", bytes(h[1:5]))[0]
    data = bytearray()
    for _ in range(size):
        f.wait_hs()
        data.append(f.read())
    return status, bytes(data)


# ------------------------------------------------------------- Testserver
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/hello":
            body = b"HELLO " + self.headers.get("User-Agent", "").encode()
        elif self.path == "/big":
            body = bytes(i * 7 & 255 for i in range(100000))
        elif self.path == "/mid":
            body = bytes(i * 3 & 255 for i in range(20000))
        elif self.path == "/huge":
            body = bytes(300000)
        elif self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/hello")
            self.end_headers()
            return
        elif self.path == "/prog.prg":
            body = b"\x01\x08ABCDEF"
        elif self.path.startswith("/hex/"):
            body = self.path[5:].encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(1024)
            if not d:
                return
            self.request.sendall(d.upper())


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data.upper(), self.client_address)


def main():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    tcpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TcpEcho)
    threading.Thread(target=tcpd.serve_forever, daemon=True).start()
    tport = tcpd.server_address[1]
    udpd = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UdpEcho)
    threading.Thread(target=udpd.serve_forever, daemon=True).start()
    uport = udpd.server_address[1]

    a, b = socket.socketpair()
    a.setblocking(False)
    f = FpgaModel(b)
    wic = wic64d.WiC64(wic64d.Settings(wic64d.SETTINGS_FILE))
    stop = threading.Event()
    threading.Thread(target=wic64d.run_link, args=(a.fileno(), f.flush, wic),
                     kwargs={"stop": stop}, daemon=True).start()
    time.sleep(0.3)

    fails = 0

    def check(name, ok, info=""):
        nonlocal fails
        print(("OK    " if ok else "FEHLER"), name, info)
        if not ok:
            fails += 1

    s, d = c64_request(f, "R", 0x00)
    check("Version", s == 0 and d == b"2.4.4\0", d)
    s, d = c64_request(f, "R", 0x26)
    check("Versionsnummern", d == bytes([2, 4, 4, 0]))
    s, d = c64_request(f, "R", 0xFE, bytes(range(256)) * 5)
    check("Echo 1280", s == 0 and d == bytes(range(256)) * 5)
    s, d = c64_request(f, "R", 0xFE)
    check("Echo leer", s == 0 and d == b"")
    s, d = c64_request(f, "R", 0x01, (base + "/hello").encode())
    check("HTTP GET", s == 0 and d.startswith(b"HELLO WiC64/"), d)
    s, d = c64_request(f, "R", 0x01, (base + "/redir").encode())
    check("Weiterleitung", s == 0 and d.startswith(b"HELLO"), d)
    s, d = c64_request(f, "R", 0x01, (base + "/fehlt").encode())
    check("404", s == 5 and d == b"")
    s, d = c64_request(f, "R", 0x2A, b"\0")
    check("Statusmeldung", d.startswith(b"404 nOT fOUND"), d)
    t = time.time()
    s, d = c64_request(f, "R", 0x01, (base + "/mid").encode())
    dt = time.time() - t
    check("HTTP 20000 Bytes", s == 0 and d == bytes(i * 3 & 255 for i in range(20000)),
          "%.1f s" % dt)
    s, d = c64_request(f, "R", 0x01, (base + "/big").encode())
    check("Standard >64K abgelehnt", s == 2)
    s, d = c64_request(f, "E", 0x01, (base + "/big").encode())
    check("Extended 100000 Bytes", s == 0 and d == bytes(i * 7 & 255 for i in range(100000)))
    s, d = c64_request(f, "W", 0x01, (base + "/prog.prg").encode())
    check("Legacy .prg (Laenge minus 2)", d == b"\x01\x08ABCD", d)
    s, d = c64_request(f, "W", 0x01, (base + "/fehlt").encode())
    check("Legacy Fehler !0", d == b"!0", d)
    s, d = c64_request(f, "R", 0x0F, b"/hex/<$" + bytes([3, 0, 1, 0xAB, 0xFF]) + b"x")
    check("kodierte URL ohne Server", s == 3 or s == 2, (s, d))
    c64_request(f, "R", 0x08, (base + "/hex/").encode())
    s, d = c64_request(f, "R", 0x0F, b"!<$" + bytes([3, 0, 1, 0xAB, 0xFF]) + b"x")
    check("kodierte URL mit !", s == 0 and d == b"01abffx", d)
    c64_request(f, "R", 0x08, wic64d.DEFAULT_SERVER.encode())
    c64_request(f, "R", 0x28, (base + "/post").encode())
    s, d = c64_request(f, "R", 0x2B, b"DATEN\x00\xff")
    check("HTTP POST", s == 0 and d == wic64d.POST_HEADER + b"DATEN\x00\xff" + wic64d.POST_FOOTER)
    s, d = c64_request(f, "R", 0x21, ("127.0.0.1:%d" % tport).encode())
    check("TCP open", s == 0)
    s, d = c64_request(f, "R", 0x23, b"hallo c64")
    check("TCP write", s == 0)
    time.sleep(0.2)
    s, d = c64_request(f, "R", 0x30)
    check("TCP available", s == 0 and d == bytes([9, 0]), d)
    s, d = c64_request(f, "R", 0x22)
    check("TCP read", s == 0 and d == b"HALLO C64", d)
    time.sleep(0.1)
    s, d = c64_request(f, "R", 0x30)
    check("TCP gelesen bestaetigt", d == bytes([0, 0]), d)
    s, d = c64_request(f, "R", 0x2E)
    check("TCP close", s == 0)
    s, d = c64_request(f, "R", 0x15)
    check("Uhrzeit", s == 0 and len(d) == 20, d)
    s, d = c64_request(f, "R", 0x77)
    check("unbekannter Befehl", s == 2)

    # Firmware: veraltete Befehle mit Status 0 und Erklaerung
    s, d = c64_request(f, "R", 0x07)
    check("veraltet $07", s == 0 and d.startswith(b"Command $07 has been deprecated"), d[:40])

    # PORT64-Erweiterungen
    s, d = c64_request(f, "R", 0x41, b"\1")
    check("keine Build-Info (wie echte WiC64)", s == 2)
    s, d = c64_request(f, "R", 0x3D)
    check("WLAN-Status", s == 0 and d == bytes([2, 0]), d)
    s, d = c64_request(f, "R", 0x33, struct.pack("<H", 47011))
    check("UDP Port", s == 0)
    pkt = b"\x09127.0.0.1" + struct.pack("<H", uport) + b"udp hallo"
    s, d = c64_request(f, "R", 0x34, pkt)
    check("UDP senden", s == 0)
    s, d = c64_request(f, "R", 0x35, struct.pack("<H", 1000))
    check("UDP empfangen", s == 0 and d[:4] == bytes([127, 0, 0, 1]) and
          struct.unpack("<H", d[4:6])[0] == uport and d[6:] == b"UDP HALLO", d)
    s, d = c64_request(f, "R", 0x35, struct.pack("<H", 50))
    check("UDP leer", s == 0 and d == b"", d)
    s, d = c64_request(f, "W", 0x0E, struct.pack("<H", 47012))
    check("UDP alter Befehl $0E", d == b"0", d)
    s, d = c64_request(f, "R", 0x3F, bytes([1, 3]) + struct.pack("<I", 262144) +
                       (base + "/huge").encode())
    ok = s == 0 and len(d) == 28 and d[0] == 1
    if ok:
        got, ms, bps = struct.unpack("<III", d[2:14])
        ok = got == 262144 and d[1] & 1 and d[1] & 8 and struct.unpack("<H", d[22:24])[0] == 200
    check("Speedtest", ok, d[:14])
    s, d = c64_request(f, "R", 0x3F, bytes([1, 3]) + struct.pack("<I", 100) + b"http://x/")
    check("Speedtest Ziel zu klein", s == 2)
    s, d = c64_request(f, "R", 0x3B)
    check("DHCP schalten abgelehnt", s == 1)
    s, d = c64_request(f, "R", 0x40, ("127.0.0.1:%d" % tport).encode())
    check("TLS-Sockel ohne Namen abgelehnt", s == 2)
    if os.environ.get("WIC64D_NETZ") != "0":     # braucht Internet
        s, d = c64_request(f, "R", 0x40, b"example.com:443")
        check("TLS-Sockel oeffnen (example.com)", s == 0)
        c64_request(f, "R", 0x23, b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        d = b""
        for _ in range(30):
            s, d = c64_request(f, "R", 0x22)
            if d:
                break
            time.sleep(0.2)
        check("TLS-Sockel lesen", d.startswith(b"HTTP/1."), d[:20])
        c64_request(f, "R", 0x2E)
        s, d = c64_request(f, "R", 0x40, b"self-signed.badssl.com:443")
        check("TLS-Sockel lehnt falsches Zertifikat ab", s == 4)
    s, d = c64_request(f, "R", 0x3E, b"\x01127.0.0.1")
    check("Ping (am Mac ohne root: Fehler 4)", (s == 0 and len(d) == 25) or s == 4, (s, d[:7]))

    # Bearer-Token
    tok = "ab" * 32
    s, d = c64_request(f, "R", 0x42, b"\1\1\0" + tok.encode())
    check("Bearer PORT64 setzen", s == 0)
    org = b"https://Beispiel.Example"
    s, d = c64_request(f, "R", 0x42, b"\1\1\1" + struct.pack("<H", len(org)) + org + b"CD" * 32)
    check("Bearer eigener Ursprung setzen", s == 0)
    s, d = c64_request(f, "R", 0x42, b"\1\0\xff")
    check("Bearer Zustand", s == 0 and d[:5] == b"P64A\1" and d[5] == 3 and
          d[8:] == b"https://beispiel.example:443", d)
    us = wic64d.urllib.parse.urlsplit
    check("Bearer nur am Ursprung",
          wic.bearer_for(us("https://api.port64.de/x")) == tok and
          wic.bearer_for(us("http://api.port64.de/x")) is None and
          wic.bearer_for(us("https://beispiel.example/")) == "cd" * 32 and
          wic.bearer_for(us("https://beispiel.example:444/")) is None)
    s, d = c64_request(f, "R", 0x42, b"\1\1\1" + struct.pack("<H", 25) +
                       b"https://api.port64.de:443" + b"CD" * 32)
    check("Bearer PORT64-Ursprung als eigener abgelehnt", s == 2)
    s, d = c64_request(f, "W", 0x42, b"\1\2\0")
    check("Bearer nur Protokoll R", d == b"!0", d)
    c64_request(f, "R", 0x42, b"\1\2\0")
    c64_request(f, "R", 0x42, b"\1\2\1")
    s, d = c64_request(f, "R", 0x42, b"\1\0\xff")
    check("Bearer geloescht", s == 0 and d[5] == 0 and d[6:8] == b"\0\0", d)

    # Abbruch: C64 holt nur einen Teil der Antwort und schickt neue Anfrage
    f.pa2(1)
    for x in b"R\xfe\x00\x04" + b"\x55" * 1024:
        f.put(x)
        f.wait_hs()
    f.pa2(0)
    f.wait_hs()
    f.read()
    for _ in range(100):
        f.wait_hs()
        f.read()
    s, d = c64_request(f, "R", 0xFE, b"NEU")
    check("nach Abbruch", s == 0 and d == b"NEU", d)

    stop.set()
    print("BESTANDEN" if fails == 0 else "%d FEHLER" % fails)
    return fails


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
