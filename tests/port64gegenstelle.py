#!/usr/bin/env python3
# Gegenstelle fuer port64probe.prg: HTTP auf 8064 (/eins.bin = 1 MB fuer den
# Speedtest $3f) und UDP-Echo auf 8065 (antwortet in Grossbuchstaben).
# Retro-Modern - https://retro-modern.net
import http.server, socketserver, threading

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = bytes(1048576) if self.path == "/eins.bin" else None
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class U(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        print("UDP von %s:%d: %r" % (self.client_address + (data,)), flush=True)
        sock.sendto(data.upper(), self.client_address)

u = socketserver.ThreadingUDPServer(("0.0.0.0", 8065), U)
threading.Thread(target=u.serve_forever, daemon=True).start()
print("HTTP 8064, UDP 8065", flush=True)
http.server.ThreadingHTTPServer(("0.0.0.0", 8064), H).serve_forever()
