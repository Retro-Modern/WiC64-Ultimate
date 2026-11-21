#!/usr/bin/env python3
# wic64d - WiC64-Dienst fuer den C64-Kern des MiSTer.
#
# Gegenstueck zu rtl/wic64_bridge.sv: liest ueber /dev/ttyS1 die Bytes, die
# der C64 an den Userport schreibt, beantwortet die WiC64-Befehle (HTTP,
# HTTPS, TCP, Zeit ...) wie die WiC64-Firmware 2.x und schickt die Antwort
# zurueck. Das Netz kommt vom Linux des MiSTer (LAN oder WLAN).
#
# Aktiv nur, solange der C64-Kern laeuft (/tmp/CORENAME = C64) und im Menue
# kein UART-Modus (Modem, MIDI ...) eingestellt ist.
#
# Befehlssatz nach der WiC64-Firmware (github.com/WiC64-Team/wic64-firmware,
# BSD-2-Clause, Henning Liebenau), dazu die PORT64-Erweiterungen $33-$43, wie
# sie die WiC64-Fassung fuer den Ultimate 64 von Retro-Modern beantwortet
# (UDP, Ping, Speedtest, IP-Anzeige, TLS-Sockel, Bearer-Token). Die
# Build-Info $41 fehlt absichtlich: das WiC64 Control Center sperrt sich, wenn
# sie eine andere Anbieterkennung als die des U64 meldet; ohne $41 behandelt es
# den Dienst wie eine echte WiC64.
#
# GPL-3.0-or-later, Retro-Modern - https://retro-modern.net

import errno, fcntl, glob, http.client, ipaddress, json, os, select, socket, ssl
import struct, sys, termios, threading, time, urllib.parse

VERSION = (2, 4, 4, 0)
VERSION_STRING = "2.4.4"            # wie die Firmware; das Control Center prueft genau diese Form
TTY = "/dev/ttyS1"
HIER = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(HIER, "wic64d.json")
DEFAULT_SERVER = "http://x.wic64.net/prg/"
LOG = os.environ.get("WIC64D_LOG", "") not in ("", "0")
LOG_EVENTS = os.environ.get("WIC64D_LOG", "") == "2"

SUCCESS, INTERNAL_ERROR, CLIENT_ERROR, CONNECTION_ERROR, NETWORK_ERROR, SERVER_ERROR = range(6)
DEFAULT_TRANSFER_TIMEOUT = 1.0
DEFAULT_REMOTE_TIMEOUT = 5.0
MAX_INFLIGHT = 3584                   # FIFO im FPGA: 4096 Bytes

TIMEZONES = [0, 0, 3600, 7200, 7200, 10800, 12600, 14400, 18000, 19800, 21600,
             25200, 28800, 32400, 34200, 36000, 39600, 43200, -39600, -36000,
             -32400, -28800, -25200, -25200, -21600, -18000, -18000, -14400,
             -12600, -10800, -10800, -3600]

HTTP_STATUS = {
    400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
    407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
    410: "Gone", 411: "Length Required", 412: "Precondition Failed",
    413: "Content Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
    416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot",
    421: "Misdirected Request", 422: "Unprocessable Content", 423: "Locked",
    424: "Failed Dependency", 425: "Too Early", 426: "Upgrade Required",
    428: "Precondition Required", 429: "Too Many Requests",
    431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
    505: "HTTP Version Not Supported", 506: "Variant Also Negotiates",
    507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended",
    511: "Network Authentication Required",
}

UDP_ALIAS = {0x0E: 0x33, 0x0B: 0x34, 0x1F: 0x34, 0x0A: 0x35, 0x1E: 0x35}
NATIVE_ONLY = {   # PORT64-Befehle, die am MiSTer das Linux erledigt
    0x36: "WPS unavailable on MiSTer", 0x37: "WPS unavailable on MiSTer",
    0x38: "WPS unavailable on MiSTer", 0x39: "Network is managed by MiSTer Linux",
    0x3B: "Network is managed by MiSTer Linux", 0x3C: "Network is managed by MiSTer Linux",
    0x43: "No web admin on MiSTer",
}
PORT64_ORIGIN = "https://api.port64.de:443"

DEPRECATED = {
    0x03: "Firmware updates are now handled by the new update command $27. The old update program(s) may still appear to be working, but will actually no longer install any updates.",
    0x07: "Firmware is now versioned semantically, use command $00 to get a version string to display to the user, or use command $26 to get the version as individual bytes (<major> <minor> <patch> <devel>)",
    0x09: "We see no reason to log to the esp console from the c64. If you *really* need this, please drop us a line.",
    0x13: "The command for getting the external IP has never worked correctly, nor has it been used in any programs we are aware of.",
    0x19: "The commands for getting or setting ESP preferences from the c64 have been removed because they are inherently unsafe. Third parties should not be able to write arbitrary data to the ESP flash memory.",
    0x20: "This command was called \"set tcp port\" but has apparently never had any effect in the legacy firmware, apart from setting a global variable that was never used.",
    0x24: "The previous implementation of HTTP POST was broken and the payload structure was unnecessarily complex. Please use the new commands WIC64_HTTP_POST_SET_URL and WIC64_HTTP_POST_DATAinstead.",
    0x25: "This command was called \"big loader\" and was intended as aHTTP GET request implementation for transfer sizes above 64kb. It has never worked properly and has never been officially documented. General support for payloads larger than 64kb has been added with the extended command protocol.",
    0x63: "The factory reset command has been deprecated. If this turns outto be required at all, it will be implemented from the web interface instead.",
}
for _c in (0x04, 0x05, 0x18):
    DEPRECATED[_c] = DEPRECATED[0x03]
DEPRECATED[0x1A] = DEPRECATED[0x19]

POST_HEADER = b'--WiC64-Binary-Data\nContent-Disposition: form-data; name="data"\r\n\r\n'
POST_FOOTER = b"\r\n--WiC64-Binary-Data--\r\n"


def log(*a):
    if LOG:
        print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------- Einstellungen
class Settings:
    def __init__(self, path):
        self.path = path
        self.server = DEFAULT_SERVER
        self.gmt_offset = 0
        self.token_key = ""
        self.token = ""
        self.port64_bearer = ""           # $42 Profil 0, nur fuer https://api.port64.de
        self.custom_bearer = ""           # $42 Profil 1, nur fuer custom_origin
        self.custom_origin = ""
        try:
            with open(path) as f:
                d = json.load(f)
            self.server = d.get("server", self.server)
            self.gmt_offset = int(d.get("gmt_offset", 0))
            self.token_key = d.get("token_key", "")
            self.token = d.get("token", "")
            self.port64_bearer = d.get("port64_bearer", "")
            self.custom_bearer = d.get("custom_bearer", "")
            self.custom_origin = d.get("custom_origin", "")
        except (OSError, ValueError):
            pass

    def save(self):
        try:
            tmp = self.path + ".neu"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"server": self.server, "gmt_offset": self.gmt_offset,
                           "token_key": self.token_key, "token": self.token,
                           "port64_bearer": self.port64_bearer,
                           "custom_bearer": self.custom_bearer,
                           "custom_origin": self.custom_origin}, f)
            os.replace(tmp, self.path)
            return True
        except OSError as e:
            log("Einstellungen nicht gespeichert:", e)
            return False


# ------------------------------------------------------------------- Netz
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))      # nichts wird gesendet
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def network_ready():
    return local_ip() != "0.0.0.0"


def mac_address():
    for dev in ("eth0", "wlan0"):
        try:
            return open("/sys/class/net/%s/address" % dev).read().strip().upper()
        except OSError:
            pass
    return "00:00:00:00:00:00"


def wifi_ssid():
    for dev in ("wlan0", "wlan1"):
        try:
            out = os.popen("iwgetid -r %s 2>/dev/null" % dev).read().strip()
            if out:
                return out
        except OSError:
            pass
    return "MiSTer"


def default_route():
    """(Schnittstelle, Gateway) der Standardroute."""
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                return f[0], socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    except (OSError, IndexError, ValueError):
        pass
    return None, "0.0.0.0"


def netmask(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            r = fcntl.ioctl(s.fileno(), 0x891B, struct.pack("256s", ifname.encode()[:15]))
            return socket.inet_ntoa(r[20:24])
        finally:
            s.close()
    except (OSError, AttributeError):
        return "0.0.0.0"


def nameservers():
    out = []
    try:
        for line in open("/etc/resolv.conf"):
            f = line.split()
            if len(f) >= 2 and f[0] == "nameserver":
                try:
                    ipaddress.IPv4Address(f[1])
                    out.append(f[1])
                except ValueError:
                    pass
    except OSError:
        pass
    return (out + ["0.0.0.0", "0.0.0.0"])[:2]


def dhcp_running():
    for d in glob.glob("/proc/[0-9]*/comm"):
        try:
            if open(d).read().strip() in ("dhcpcd", "udhcpc", "dhclient"):
                return True
        except OSError:
            pass
    return False


def resolve4(host, timeout=2.0):
    """IPv4-Adresse oder None."""
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    res = []

    def look():
        try:
            res.append(socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0])
        except (OSError, IndexError):
            pass
    t = threading.Thread(target=look, daemon=True)
    t.start()
    t.join(timeout)
    return res[0] if res else None


HOST_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


def host_text(b):
    if not b or len(b) > 253 or any(c not in HOST_CHARS for c in b):
        return None
    return b.decode()


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def canonical_origin(source):
    """https://host[:port] -> https://host:port in Kleinbuchstaben, sonst None."""
    if not source.startswith("https://") or len(source) > 96:
        return None
    rest = source[8:]
    host, _, port = rest.partition(":")
    if not host or host.startswith(".") or host.endswith("."):
        return None
    for label in host.split("."):
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or \
                not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label):
            return None
    if ":" in rest:
        if not port.isdigit() or not 0 < int(port) < 65536:
            return None
        port = int(port)
    else:
        port = 443
    out = "https://%s:%d" % (host.lower(), port)
    return out if len(out) <= 96 else None


def hex_bearer(t):
    return len(t) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in t)


def icmp_checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def wifi_rssi():
    try:
        for line in open("/proc/net/wireless").read().splitlines()[2:]:
            parts = line.split()
            return "%ddbm" % int(float(parts[3]))
    except (OSError, IndexError, ValueError):
        pass
    return "-40dbm"


# ------------------------------------------------------------------ Befehle
class Request:
    def __init__(self, protocol, cmd, payload):
        self.protocol = protocol          # 'W', 'R' oder 'E'
        self.cmd = cmd
        self.payload = payload

    @property
    def legacy(self):
        return self.protocol == "W"


class Result:
    def __init__(self):
        self.status = SUCCESS
        self.data = b""
        self.size_to_report = None
        self.send = True                  # False: gar keine Antwort (wie Firmware)
        self.on_delivered = None


class WiC64:
    def __init__(self, settings):
        self.settings = settings
        self.status_message = ""
        self.custom_transfer_timeout = None
        self.custom_remote_timeout = None
        self.remote_timeout = DEFAULT_REMOTE_TIMEOUT
        self.post_url = ""
        self.tcp = None
        self.tcp_rx = bytearray()         # gelesen, noch nicht abgeholt
        self.tcp_unconfirmed = b""
        self.udp = None
        self.http_status = -1
        self.reboot_requested = False

    # Zeitlimits gelten fuer die naechste Anfrage, dann wieder Standard
    def next_transfer_timeout(self):
        t = self.custom_transfer_timeout or DEFAULT_TRANSFER_TIMEOUT
        self.custom_transfer_timeout = None
        return t

    def take_remote_timeout(self):
        self.remote_timeout = self.custom_remote_timeout or DEFAULT_REMOTE_TIMEOUT
        self.custom_remote_timeout = None

    # Command::status
    def status(self, req, res, code, message, legacy_message=None):
        if req.legacy:
            res.data = (legacy_message if legacy_message is not None else message).encode("latin-1")
        else:
            res.status = code
            self.status_message = message[:39]

    def error(self, req, res, code, message, legacy_message=None):
        self.status(req, res, code, message, legacy_message)

    @staticmethod
    def cstring(s):
        return s.encode("latin-1", "replace") + b"\0"

    def supports(self, req):
        c = req.cmd
        if c in (0x01, 0x0F, 0x28, 0x2B):
            return True                   # Http kann alle drei Protokolle
        if c == 0x2F:
            return req.protocol == "R"
        return req.protocol in ("W", "R")

    def execute(self, req):
        res = Result()
        self.take_remote_timeout()
        if not self.supports(req):
            log("Befehl $%02x nicht mit Protokoll %s" % (req.cmd, req.protocol))
            res.send = False
            return res
        c = req.cmd
        p = req.payload
        try:
            if c == 0x00:
                res.data = self.cstring(VERSION_STRING)
            elif c == 0x26:
                res.data = bytes(VERSION)
            elif c == 0x0C:
                sep = b"\1" if req.legacy else b"\0"
                res.data = b"0" + sep + wifi_ssid().encode("latin-1", "replace") + sep + \
                    wifi_rssi()[:-3].encode() + sep
                if not req.legacy:
                    res.data += b"\xff"
            elif c in (0x02, 0x0D):
                self.status(req, res, SUCCESS, "wifi config changed")
            elif c == 0x2F:
                if network_ready():
                    res.data = bytes([8])
                else:
                    self.error(req, res, INTERNAL_ERROR, "WiFi not configured")
            elif c == 0x2C:
                t = (p[0] if p else 0)
                end = time.time() + t
                while not network_ready() and time.time() < end:
                    time.sleep(0.1)
                if not network_ready():
                    self.error(req, res, CONNECTION_ERROR, "No IP address assigned")
            elif c == 0x14:
                res.data = self.cstring(mac_address())
            elif c == 0x10:
                res.data = self.cstring(wifi_ssid())
            elif c == 0x11:
                res.data = self.cstring(wifi_rssi())
            elif c == 0x06:
                res.data = self.cstring(local_ip())
            elif c in (0x01, 0x0F, 0x28, 0x2B):
                self.http(req, res)
            elif c in (0x21, 0x30, 0x22, 0x23, 0x2E, 0x40):
                self.tcp_cmd(req, res)
            elif c in UDP_ALIAS or c in (0x33, 0x34, 0x35):
                self.udp_cmd(req, res, UDP_ALIAS.get(c, c))
            elif c == 0x3E:
                self.ping(req, res)
            elif c == 0x3F:
                self.speedtest(req, res)
            elif c == 0x3A:
                self.ip_config(req, res)
            elif c == 0x3D:
                if p:
                    self.error(req, res, CLIENT_ERROR, "Command expects no payload", "!0")
                else:
                    res.data = bytes([2 if network_ready() else 0, 0])
            elif c == 0x42:
                self.auth(req, res)
            elif c in NATIVE_ONLY:
                self.error(req, res, INTERNAL_ERROR, NATIVE_ONLY[c], "!0")
            elif c == 0x12:
                res.data = self.cstring(self.settings.server)
            elif c == 0x08:
                self.settings.server = p.decode("latin-1").rstrip("\0")
                self.settings.save()
            elif c == 0x17:
                res.data = self.cstring(str(self.settings.gmt_offset))
            elif c == 0x16:
                if len(p) >= 2:
                    idx = p[1] * 10 + p[0]
                    if idx < len(TIMEZONES):
                        self.settings.gmt_offset = TIMEZONES[idx]
                        self.settings.save()
            elif c == 0x15:
                t = time.gmtime(time.time() + self.settings.gmt_offset)
                res.data = self.cstring(time.strftime("%H:%M:%S %d-%m-%Y", t))
            elif c == 0x27:
                self.error(req, res, INTERNAL_ERROR, "No firmware updates on MiSTer")
            elif c == 0x29:
                self.reboot_requested = True
                res.send = False
            elif c == 0x2A:
                msg = self.status_message
                if p and p[0]:
                    msg = msg.lower()
                res.data = self.cstring(ascii2petscii(msg))
            elif c in (0x2D, 0x32):
                if len(p) < 1:
                    self.error(req, res, CLIENT_ERROR, "Timeout value not specified")
                elif p[0] == 0:
                    self.error(req, res, CLIENT_ERROR, "Timeout must be >= 1 second")
                elif c == 0x2D:
                    self.custom_transfer_timeout = p[0]
                else:
                    self.custom_remote_timeout = p[0]
            elif c == 0x31:
                pass
            elif c == 0xFE:
                res.data = bytes(p)
            elif c == 0xFC:
                time.sleep(p[0] if p else 1)
            elif c == 0xFD:
                self.error(req, res, INTERNAL_ERROR, "Test error")
            elif c in DEPRECATED:          # wie die Firmware: Status 0, Erklaerung als Text
                res.data = self.cstring("Command $%02x has been deprecated since firmware "
                                        "version 2.0.0:\r\n%s" % (c, DEPRECATED[c]))
            else:
                self.error(req, res, CLIENT_ERROR, "Undefined command id 0x%02x" % c)
        except Exception as e:     # nie den Dienst sterben lassen
            log("Fehler in Befehl $%02x: %r" % (c, e))
            self.error(req, res, INTERNAL_ERROR, "Internal error", "!0")
        return res

    # ------------------------------------------------------------- HTTP
    def expand_url(self, url):
        url = url.replace(" ", "")
        if "%ser" in url:
            url = url.replace("%ser", self.settings.server)
        if url.startswith("!"):
            url = url.replace("!", self.settings.server)
        if "%mac" in url:
            url = url.replace("%mac", mac_address().replace(":", "") + self.settings.token)
        return url

    @staticmethod
    def encode_url(data):
        if b"<$" not in data:
            return data
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i:i + 2] == b"<$" and i + 3 < len(data):
                n = data[i + 2] | (data[i + 3] << 8)
                out += data[i + 4:i + 4 + n].hex().encode()
                i += 4 + n
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def http(self, req, res):
        if not network_ready():
            self.error(req, res, CONNECTION_ERROR, "WiFi not connected ", "!0")
            return
        c = req.cmd
        if c == 0x28:
            self.post_url = self.expand_url(req.payload.decode("latin-1"))
            return
        if c == 0x2B:
            url, body = self.post_url, POST_HEADER + bytes(req.payload) + POST_FOOTER
        else:
            raw = bytes(req.payload).split(b"\0")[0]
            if c == 0x0F:
                raw = self.encode_url(bytes(req.payload)).split(b"\0")[0]
            url, body = self.expand_url(raw.decode("latin-1")), None
        if not url:
            self.error(req, res, CLIENT_ERROR, "URL not specified", "!0")
            return
        if len(url) > 0x2000:
            self.error(req, res, CLIENT_ERROR, "URL too long (max 2000 bytes)", "!0")
            return
        agent = "ESP32HTTPClient" if req.legacy else "WiC64/%d.%d.%d (MiSTer)" % VERSION[:3]
        log("HTTP", "POST" if body is not None else "GET", url)
        try:
            status, data = self.http_fetch(url, body, agent, self.remote_timeout)
        except _HttpError as e:
            self.error(req, res, e.code, e.message, "!0")
            return
        self.http_status = status
        if status >= 400:
            self.error(req, res, SERVER_ERROR,
                       "%d %s" % (status, HTTP_STATUS.get(status, "")), "!0")
            return
        if len(data) >= 0x10000 and req.protocol != "E":
            self.error(req, res, CLIENT_ERROR, "Response too large (use protocol E)", "!0")
            return
        res.data = data
        if req.legacy:
            if url.endswith(".prg") and len(data) > 2:
                res.size_to_report = len(data) - 2
            if url.startswith(("http://x.wic64.net", "http://t.wic64.net")) and status == 201:
                fields = data.split(b"\1")
                res.data = fields[3] if len(fields) > 3 else b""

    def bearer_for(self, u):
        """Bearer-Token fuer diese HTTPS-Adresse oder None (wie PORT64)."""
        if u.scheme != "https" or (u.hostname or "").lower() == "firmware.port64.de":
            return None
        origin = "https://%s:%d" % (u.hostname.lower(), u.port or 443)
        st = self.settings
        if origin == PORT64_ORIGIN and hex_bearer(st.port64_bearer):
            return st.port64_bearer
        if hex_bearer(st.custom_bearer) and st.custom_origin == origin:
            return st.custom_bearer
        return None

    def http_fetch(self, url, body, agent, timeout):
        start = time.time()
        suppressed = False                # nach Weiterleitung kein Token mehr
        for _ in range(11):
            u = urllib.parse.urlsplit(url)
            if u.scheme not in ("http", "https") or not u.hostname:
                raise _HttpError(CLIENT_ERROR, "Malformed URL")
            left = max(1.0, timeout - (time.time() - start))
            port = u.port
            if u.scheme == "https":
                conn = http.client.HTTPSConnection(u.hostname, port or 443, timeout=left,
                                                   context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(u.hostname, port or 80, timeout=left)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            headers = {"User-Agent": agent, "Connection": "close"}
            bearer = None if suppressed else self.bearer_for(u)
            if bearer:
                headers["Authorization"] = "Bearer " + bearer
            if body is not None:
                headers["Content-Type"] = 'multipart/form-data;boundary="WiC64-Binary-Data"'
            try:
                conn.request("POST" if body is not None else "GET", path, body, headers)
                r = conn.getresponse()
                for k, v in r.getheaders():
                    if k.lower() == "wic64-security-token-key":
                        self.settings.token_key = v
                        self.settings.save()
                    elif k.lower() == "wic64-security-token":
                        self.settings.token = v
                        self.settings.save()
                if r.status in (301, 302, 303, 307, 308):
                    loc = r.getheader("Location")
                    r.read()
                    conn.close()
                    if not loc:
                        raise _HttpError(NETWORK_ERROR, "Failed to follow redirect")
                    url = urllib.parse.urljoin(url, loc)
                    if bearer:
                        suppressed = True
                    if r.status == 303:
                        body = None
                    continue
                data = r.read()
                conn.close()
                return r.status, data
            except _HttpError:
                raise
            except socket.timeout:
                raise _HttpError(NETWORK_ERROR, "Failed to open connection")
            except ssl.SSLError as e:
                log("TLS:", e)
                raise _HttpError(NETWORK_ERROR, "Failed to open connection")
            except (OSError, http.client.HTTPException) as e:
                log("HTTP:", e)
                raise _HttpError(NETWORK_ERROR, "Failed to open connection")
        raise _HttpError(NETWORK_ERROR, "Failed to follow redirect")

    # -------------------------------------------------------------- TCP
    # Gelesen wird ohne Warten in tcp_rx; so geht dasselbe fuer TLS ($40).
    def tcp_fill(self):
        if self.tcp is None:
            return
        while len(self.tcp_rx) < 0x10000:
            try:
                d = self.tcp.recv(8192)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                return
            except OSError:
                d = b""
            if not d:
                self.tcp_end()
                return
            self.tcp_rx += d

    def tcp_end(self):
        if self.tcp is not None:
            try:
                self.tcp.close()
            except OSError:
                pass
        self.tcp = None

    def tcp_connected(self):
        self.tcp_fill()
        return bool(self.tcp_unconfirmed or self.tcp_rx or self.tcp is not None)

    def tcp_close(self):
        self.tcp_unconfirmed = b""
        self.tcp_rx = bytearray()
        self.tcp_end()

    def tcp_open(self, req, res, tls):
        p = bytes(req.payload)
        self.tcp_close()
        if not p:
            self.error(req, res, CLIENT_ERROR, "No URL specified", "!0")
            return
        host, _, port = p.split(b"\0")[0].decode("latin-1").partition(":")
        try:
            port = int(port or 0)
        except ValueError:
            port = -1
        if not host or not 0 < port < 65536 or (tls and is_ip(host)):
            self.error(req, res, CLIENT_ERROR, "Invalid TCP destination", "!0")
            return
        try:
            s = socket.create_connection((host, port), timeout=max(self.remote_timeout, 5))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if tls:
                s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            s.setblocking(False)
            self.tcp = s
            self.status(req, res, SUCCESS, "Success", "0")
        except ssl.SSLError as e:
            log("TLS:", e)
            self.error(req, res, NETWORK_ERROR, "TLS handshake failed", "!E")
        except OSError:
            self.error(req, res, NETWORK_ERROR, "Could not open connection", "!E")

    def tcp_cmd(self, req, res):
        c, p = req.cmd, bytes(req.payload)
        if not network_ready():
            self.error(req, res, CONNECTION_ERROR, "WiFi not connected", "!0")
            return
        if c in (0x21, 0x40):
            self.tcp_open(req, res, c == 0x40)
        elif c == 0x2E:
            self.tcp_close()
            self.status(req, res, SUCCESS, "Success", "0")
        elif c == 0x30:
            if self.tcp_connected():
                n = min(len(self.tcp_unconfirmed) + len(self.tcp_rx), 0xFFFF)
                res.data = bytes([n & 255, n >> 8])
            else:
                self.error(req, res, NETWORK_ERROR, "TCP connection closed", "!E")
        elif c == 0x22:
            if self.tcp_connected():
                if not self.tcp_unconfirmed:
                    self.tcp_unconfirmed = bytes(self.tcp_rx[:8192])
                    del self.tcp_rx[:len(self.tcp_unconfirmed)]
                res.data = self.tcp_unconfirmed

                def delivered():
                    self.tcp_unconfirmed = b""
                res.on_delivered = delivered
            else:
                self.error(req, res, NETWORK_ERROR, "TCP connection closed", "!E")
        elif c == 0x23:
            sent = 0
            if self.tcp is not None:
                try:
                    self.tcp.settimeout(5)
                    self.tcp.sendall(p)
                    sent = len(p)
                except OSError:
                    pass
                finally:
                    try:
                        if self.tcp is not None:
                            self.tcp.setblocking(False)
                    except OSError:
                        pass
            if self.tcp_connected() and self.tcp is not None:
                if sent == len(p):
                    self.status(req, res, SUCCESS, "Success", "0")
                else:
                    self.error(req, res, NETWORK_ERROR, "Failed to write TCP data", "!E")
            else:
                self.error(req, res, NETWORK_ERROR, "TCP connection closed", "!E")

    # -------------------------------------------------------- PORT64: UDP
    def udp_cmd(self, req, res, c):
        p = bytes(req.payload)
        if not network_ready():
            self.udp_close()
            self.error(req, res, CONNECTION_ERROR, "Network not connected", "!0")
            return
        if c == 0x33:
            port = p[0] | (p[1] << 8 if len(p) >= 2 else 0) if p else 0
            if not port:
                self.error(req, res, CLIENT_ERROR, "UDP port must be nonzero", "!0")
                return
            self.udp_close()
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                u.bind(("0.0.0.0", port))
                u.setblocking(False)
                self.udp = u
                self.status(req, res, SUCCESS, "Success", "0")
            except OSError:
                self.error(req, res, NETWORK_ERROR, "UDP bind failed", "!E")
            return
        if self.udp is None:
            self.error(req, res, CLIENT_ERROR, "UDP port not configured", "!0")
            return
        if c == 0x34:
            n = p[0] if p else 0
            host = host_text(p[1:1 + n]) if len(p) >= 4 and n + 3 <= len(p) else None
            if host is None or len(p) - n - 3 > 1460:
                self.error(req, res, CLIENT_ERROR, "Invalid UDP packet", "!0")
                return
            port = p[n + 1] | (p[n + 2] << 8)
            if not port:
                self.error(req, res, CLIENT_ERROR, "UDP port must be nonzero", "!0")
                return
            ip = resolve4(host, min(self.remote_timeout, 5))
            if ip is None:
                self.error(req, res, NETWORK_ERROR, "UDP DNS failed", "!E")
                return
            data = p[n + 3:]
            try:
                ok = self.udp.sendto(data, (ip, port)) == len(data)
            except OSError:
                ok = False
            if ok:
                self.status(req, res, SUCCESS, "Success", "0")
            else:
                self.error(req, res, NETWORK_ERROR, "UDP send failed", "!E")
            return
        # $35: Paket abholen, wartet hoechstens timeout ms
        timeout = (p[0] | (p[1] << 8)) / 1000.0 if len(p) >= 2 else 0
        end = time.monotonic() + timeout
        while True:
            try:
                data, addr = self.udp.recvfrom(2048)
                if len(data) > 1460:
                    continue                  # wie PORT64: zu grosse Pakete fallen weg
                res.data = socket.inet_aton(addr[0]) + struct.pack("<H", addr[1]) + data
                return
            except BlockingIOError:
                left = end - time.monotonic()
                if left <= 0:
                    return                    # nichts da: Erfolg ohne Daten
                select.select([self.udp], [], [], min(left, 0.05))
            except OSError:
                self.error(req, res, NETWORK_ERROR, "UDP receive failed", "!E")
                return

    def udp_close(self):
        if self.udp is not None:
            try:
                self.udp.close()
            except OSError:
                pass
        self.udp = None

    # ------------------------------------------------------- PORT64: Ping
    def ping(self, req, res):
        p = bytes(req.payload)
        host = host_text(p[1:]) if len(p) >= 2 and p[0] == 1 else None
        if host is None:
            self.error(req, res, CLIENT_ERROR, "Invalid ping request", "!0")
            return
        if not network_ready():
            self.error(req, res, CONNECTION_ERROR, "Network not connected", "!0")
            return
        start = time.monotonic()
        ip = resolve4(host, 2.0)
        if ip is None:
            self.error(req, res, NETWORK_ERROR, "ICMP probe failed", "!0")
            return
        out = bytearray(25)
        out[0] = 1
        out[1:5] = socket.inet_aton(ip)
        for i in range(4):
            struct.pack_into("<H", out, 7 + 3 * i, 0xFFFF)
        struct.pack_into("<HHH", out, 19, 0xFFFF, 0xFFFF, 0xFFFF)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError:
            self.error(req, res, NETWORK_ERROR, "ICMP probe failed", "!0")
            return
        ident = (os.getpid() + int(time.time())) & 0xFFFF
        rtts = []
        try:
            sock.setblocking(False)
            for i in range(4):
                if time.monotonic() - start > 8:
                    break
                body = struct.pack("<II", int(time.time() * 1000) & 0xFFFFFFFF, ident) + b"MSTPING1"
                pkt = struct.pack("!BBHHH", 8, 0, 0, ident, i) + body
                pkt = pkt[:2] + struct.pack("!H", icmp_checksum(pkt)) + pkt[4:]
                sent_at = time.monotonic()
                sock.sendto(pkt, (ip, 0))
                out[5] += 1
                while True:
                    left = min(1.5 - (time.monotonic() - sent_at), 8 - (time.monotonic() - start))
                    if left <= 0:
                        break
                    r, _, _ = select.select([sock], [], [], left)
                    if not r:
                        break
                    try:
                        data, addr = sock.recvfrom(256)
                    except BlockingIOError:
                        continue
                    ihl = (data[0] & 15) * 4
                    icmp = data[ihl:ihl + 24]
                    if addr[0] != ip or len(icmp) < 24 or icmp[0] != 0 or \
                            icmp[4:8] != pkt[4:8] or icmp[8:] != pkt[8:]:
                        continue
                    rtt = min(int((time.monotonic() - sent_at) * 1000), 65534)
                    struct.pack_into("<H", out, 7 + 3 * i, rtt)
                    out[9 + 3 * i] = data[8]
                    out[6] += 1
                    rtts.append(rtt)
                    break
        except OSError:
            self.error(req, res, NETWORK_ERROR, "ICMP probe failed", "!0")
            return
        finally:
            sock.close()
        if rtts:
            struct.pack_into("<HHH", out, 19, min(rtts), sum(rtts) // len(rtts), max(rtts))
        res.data = bytes(out)

    # -------------------------------------------------- PORT64: Speedtest
    def speedtest(self, req, res):
        p = bytes(req.payload)
        if len(p) < 7 or p[0] != 1 or not 3 <= p[1] <= 20 or len(p) - 6 > 512:
            self.error(req, res, CLIENT_ERROR, "Invalid speedtest request", "!0")
            return
        seconds = p[1]
        target = struct.unpack("<I", p[2:6])[0]
        if not 262144 <= target <= 16777216:
            self.error(req, res, CLIENT_ERROR, "Invalid speedtest target", "!0")
            return
        u = urllib.parse.urlsplit(p[6:].split(b"\0")[0].decode("latin-1"))
        if u.scheme not in ("http", "https") or not u.hostname:
            self.error(req, res, CLIENT_ERROR, "Invalid speedtest request", "!0")
            return
        if not network_ready():
            self.error(req, res, CONNECTION_ERROR, "Network not connected", "!0")
            return
        setup = min(self.remote_timeout, 60 - seconds)
        flags = 0x10 if u.scheme == "https" else 0
        t0 = time.monotonic()
        try:
            if u.scheme == "https":
                conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=setup,
                                                   context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=setup)
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            conn.request("GET", path, headers={"User-Agent": "WiC64-MiSTer-Speedtest",
                                               "Accept-Encoding": "identity",
                                               "Connection": "close"})
            sock = conn.sock                  # getresponse gibt ihn bei "close" ab
            r = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            log("Speedtest:", e)
            self.error(req, res, NETWORK_ERROR, "Speedtest failed", "!0")
            return
        if r.status != 200:
            conn.close()
            self.error(req, res, SERVER_ERROR, "Speedtest failed", "!0")
            return
        length = r.getheader("Content-Length")
        clen = 0xFFFFFFFF
        if length and length.isdigit():
            clen = min(int(length), 0xFFFFFFFF)
            flags |= 8
        setup_ms = int((time.monotonic() - t0) * 1000)
        t1 = time.monotonic()
        got = 0
        read = getattr(r, "read1", None) or r.read
        while got < target:
            left = seconds - (time.monotonic() - t1)
            if left <= 0:
                flags |= 2
                break
            try:
                sock.settimeout(left)
                d = read(min(65536, target - got))
            except (socket.timeout, ssl.SSLError):
                flags |= 2
                break
            except (OSError, http.client.HTTPException):
                conn.close()
                self.error(req, res, NETWORK_ERROR, "Speedtest failed", "!0")
                return
            if not d:
                flags |= 4
                break
            got += len(d)
        conn.close()
        if got >= target:
            flags |= 1
        if clen != 0xFFFFFFFF and got >= clen:
            flags |= 4
        elapsed = max(1, int((time.monotonic() - t1) * 1000))
        if got < 16384:
            self.error(req, res, NETWORK_ERROR, "Speedtest failed", "!0")
            return
        bps = min(got * 8000 // elapsed, 0xFFFFFFFF)
        display = (bps + 5000) // 10000
        if display > 65535:
            display, flags = 65535, flags | 32
        kib = min((got + 512) // 1024, 65535)
        res.data = bytes([1, flags]) + struct.pack("<IIIIIHHH", got, elapsed, bps, setup_ms,
                                                   clen, r.status, display, kib)

    # ------------------------------------------------------- PORT64: IP
    def ip_config(self, req, res):
        if req.payload:
            self.error(req, res, CLIENT_ERROR, "IP command expects no payload", "!0")
            return
        ifname, gateway = default_route()
        if ifname is None:
            self.error(req, res, INTERNAL_ERROR, "Selected network adapter unavailable", "!0")
            return
        fields = [local_ip(), netmask(ifname), gateway] + nameservers()
        res.data = (b"DHCP\0" if dhcp_running() else b"STATIC\0") + \
            b"".join(f.encode() + b"\0" for f in fields) + b"\xff"

    # ------------------------------------------- PORT64: Bearer-Token $42
    def auth(self, req, res):
        p = bytes(req.payload)
        st = self.settings
        if req.protocol != "R" or len(p) < 3 or p[0] != 1:
            self.error(req, res, CLIENT_ERROR, "Invalid auth request", "!0")
            return
        if not network_ready():
            self.error(req, res, CONNECTION_ERROR, "Network not connected", "!0")
            return
        op, profile = p[1], p[2]
        if op == 0:                       # Zustand
            if len(p) != 3 or profile not in (2, 255):
                self.error(req, res, CLIENT_ERROR, "Invalid auth request", "!0")
                return
            origin = st.custom_origin.encode() if profile == 255 else b""
            if profile == 2:
                flags = 4 if st.token else 0
            else:
                flags = (1 if st.port64_bearer else 0) | (2 if st.custom_bearer else 0)
            res.data = b"P64A\1" + bytes([flags]) + struct.pack("<H", len(origin)) + origin
            return
        if op == 2:                       # loeschen
            if len(p) != 3 or profile > 2:
                self.error(req, res, CLIENT_ERROR, "Invalid auth request", "!0")
                return
            if profile == 0:
                st.port64_bearer = ""
            elif profile == 1:
                st.custom_bearer = st.custom_origin = ""
            else:
                st.token_key = st.token = ""
            if not st.save():
                self.error(req, res, INTERNAL_ERROR, "Credential storage failed", "!0")
            return
        if op != 1 or profile > 1:
            self.error(req, res, CLIENT_ERROR, "Invalid auth request", "!0")
            return
        origin = None
        if profile == 0:
            if len(p) != 67:
                self.error(req, res, CLIENT_ERROR, "Invalid auth request", "!0")
                return
            token = p[3:]
        else:
            n = p[3] | (p[4] << 8) if len(p) >= 5 else 0
            if not 0 < n <= 96 or len(p) != 5 + n + 64 or b"\0" in p[5:5 + n]:
                self.error(req, res, CLIENT_ERROR, "Invalid auth request", "!0")
                return
            origin = canonical_origin(p[5:5 + n].decode("latin-1"))
            if origin is None or origin == PORT64_ORIGIN:
                self.error(req, res, CLIENT_ERROR, "Invalid auth origin", "!0")
                return
            token = p[5 + n:]
        token = token.decode("latin-1")
        if not hex_bearer(token):
            self.error(req, res, CLIENT_ERROR, "Invalid bearer token", "!0")
            return
        if profile == 0:
            st.port64_bearer = token.lower()
        else:
            st.custom_bearer, st.custom_origin = token.lower(), origin
        if not st.save():
            self.error(req, res, INTERNAL_ERROR, "Credential storage failed", "!0")


class _HttpError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def ascii2petscii(s):
    out = []
    for ch in s:
        o = ord(ch)
        if 0x41 <= o <= 0x5A:
            o += 0x20
        elif 0x61 <= o <= 0x7A:
            o -= 0x20
        out.append(chr(o))
    return "".join(out)


def response_header(req, status, size):
    if req.protocol == "W":
        return bytes([(size >> 8) & 255, size & 255])
    if req.protocol == "E":
        return bytes([status]) + struct.pack("<I", size)
    return bytes([status, size & 255, (size >> 8) & 255])


# ------------------------------------------------------------- Leitung
class Link:
    """Serielle Leitung zur Bruecke im FPGA (oder ein Ersatz im Test)."""

    def __init__(self, fd, flush_fn):
        self.fd = fd
        self.flush_fn = flush_fn          # wirft die Warteschlange im FPGA weg
        self.inbuf = bytearray()
        self.out = bytearray()
        self.sent = 0
        self.credits = 0
        self.wait_ack = 0.0               # nach DTR: bis 04 kommt, nichts senden

    def queue(self, b):
        self.out += b

    def pump_out(self):
        if LOG_EVENTS and self.out and not self.wait_ack:
            log("sende %d Bytes, unterwegs %d" % (len(self.out), self.sent - self.credits * 256))
        if self.wait_ack:
            if time.monotonic() - self.wait_ack < 0.5:
                return
            self.wait_ack = 0.0
            self.sent = self.credits = 0
        room = MAX_INFLIGHT - (self.sent - self.credits * 256)
        if room <= 0 or not self.out:
            return
        n = os.write(self.fd, bytes(self.out[:room]))
        del self.out[:n]
        self.sent += n

    def events(self, data):
        self.inbuf += data
        evs = []
        while len(self.inbuf) >= 2:
            tag = self.inbuf[0]
            if tag < 1 or tag > 7:        # aus dem Takt: ein Byte verwerfen
                del self.inbuf[0]
                continue
            evs.append((tag, self.inbuf[1]))
            del self.inbuf[:2]
        return evs

    def flush(self):
        self.out.clear()
        self.flush_fn()
        self.sent = 0
        self.credits = 0
        self.wait_ack = time.monotonic()

    def flushed(self):
        self.wait_ack = 0.0
        self.sent = 0
        self.credits = 0


class Service:
    """Protokoll-Zustand wie service.cpp, Bytes vom C64 hinein, Antwort hinaus."""

    def __init__(self, link, wic):
        self.link = link
        self.wic = wic
        self.gen = 0
        self.reset_parser()
        self.busy = False                 # Befehl laeuft im Arbeitsfaden
        self.pending = None               # Antwort im FPGA, noch ohne Marke
        self.results = []
        self.lock = threading.Lock()
        self.wake_r, self.wake_w = os.pipe()
        self.last_byte = 0.0
        self.progress = self.pending_since = 0.0
        self.transfer_timeout = DEFAULT_TRANSFER_TIMEOUT

    def reset_parser(self):
        self.proto = None
        self.hdr = bytearray()
        self.payload = bytearray()
        self.need = 0

    def on_reset(self):
        self.gen += 1
        self.reset_parser()
        self.pending = None
        self.link.out.clear()
        self.link.sent = 0
        self.link.credits = 0

    def on_pa2(self, level):
        if level:                         # C64 beginnt eine neue Anfrage
            if self.pending is not None or self.link.out:
                log("Antwort abgebrochen, verwerfe Rest")
                self.gen += 1
                self.pending = None
                self.link.flush()
            self.reset_parser()

    def on_mark(self):
        if self.pending is not None:
            res = self.pending
            self.pending = None
            if res.on_delivered:
                res.on_delivered()

    def on_byte(self, b):
        now = time.monotonic()
        if self.proto is not None and now - self.last_byte > self.transfer_timeout:
            log("Zeitlimit beim Empfang, Anfrage verworfen")
            self.reset_parser()
        self.last_byte = now
        if self.busy:
            return
        if self.proto is None:
            if b in (0x57, 0x52, 0x45):   # W R E
                self.proto = chr(b)
                self.hdr = bytearray()
                self.need = {"W": 3, "R": 3, "E": 5}[self.proto]
                self.transfer_timeout = self.wic.next_transfer_timeout()
            return
        if self.need and len(self.hdr) < self.need:
            self.hdr.append(b)
            if len(self.hdr) == self.need:
                h = self.hdr
                if self.proto == "W":
                    self.cmd = h[2]
                    self.plen = max(0, (h[0] | h[1] << 8) - 4)
                elif self.proto == "R":
                    self.cmd = h[0]
                    self.plen = h[1] | h[2] << 8
                else:
                    self.cmd = h[0]
                    self.plen = struct.unpack("<I", bytes(h[1:5]))[0]
                self.payload = bytearray()
                if self.plen == 0:
                    self.dispatch()
            return
        self.payload.append(b)
        if len(self.payload) >= self.plen:
            self.dispatch()

    def dispatch(self):
        req = Request(self.proto, self.cmd, bytes(self.payload))
        self.reset_parser()
        self.busy = True
        gen = self.gen
        log("Anfrage %s $%02x, %d Bytes" % (req.protocol, req.cmd, len(req.payload)))

        def run():
            res = self.wic.execute(req)
            with self.lock:
                self.results.append((gen, req, res))
            os.write(self.wake_w, b"x")
        threading.Thread(target=run, daemon=True).start()

    def collect(self):
        try:
            os.read(self.wake_r, 64)
        except OSError:
            pass
        with self.lock:
            done, self.results = self.results, []
        for gen, req, res in done:
            self.busy = False
            if gen != self.gen:
                continue
            if self.wic.reboot_requested:
                self.wic.reboot_requested = False
                self.link.queue(b"\x11")
                self.reboot_at = time.monotonic() + 2.0
                continue
            if not res.send:
                continue
            size = res.size_to_report if res.size_to_report is not None else len(res.data)
            body = response_header(req, res.status, size) + res.data
            out = bytearray(b"\x11")      # Antwort bereit
            for i in range(0, len(body), 256):
                chunk = body[i:i + 256]
                out += bytes([0x10, len(chunk) & 255]) + chunk
            # Marke. Kein 13 (PB loslassen): das kaeme an, bevor der C64 das
            # letzte Byte gelesen hat. PB gibt die Bruecke beim naechsten PA2 frei.
            out += b"\x14"
            self.link.queue(out)
            self.pending = res
            self.pending_since = self.progress = time.monotonic()
            log("Antwort Status %d, %d Bytes" % (res.status, len(res.data)))


# ------------------------------------------------------------- Hauptschleife
def open_tty(path):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0                               # iflag
    a[1] = 0                               # oflag
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[3] = 0                               # lflag
    a[4] = a[5] = termios.B1500000         # 1 562 500 bei 100 MHz uartclk
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def dtr_toggle(fd):
    termios.tcdrain(fd)
    buf = bytearray(4)
    fcntl.ioctl(fd, termios.TIOCMGET, buf)
    v = struct.unpack("i", buf)[0] ^ termios.TIOCM_DTR
    fcntl.ioctl(fd, termios.TIOCMSET, struct.pack("i", v))


def core_active():
    try:
        name = open("/tmp/CORENAME").read().strip()
    except OSError:
        return False
    if name != "C64":
        return False
    return not glob.glob("/tmp/uartmode[1-9]")


def run_link(fd, flush_fn, wic, active=lambda: True, stop=None):
    """Bedient eine Leitung, bis die Bruecke weg ist oder stop gesetzt ist."""
    link = Link(fd, flush_fn)
    svc = Service(link, wic)
    svc.reboot_at = None
    link.flush()
    link.queue(b"\x12")                   # PING
    ping_sent = ping_out = time.monotonic()
    alive = False
    while stop is None or not stop.is_set():
        timeout = 0.2
        try:
            r, w, _ = select.select([fd, svc.wake_r], [fd] if link.out else [], [], timeout)
        except InterruptedError:
            continue
        if svc.wake_r in r:
            svc.collect()
        if fd in r:
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                data = b""
            for tag, v in link.events(data):
                if LOG_EVENTS and tag != 1:
                    log("Ereignis %02x %02x" % (tag, v))
                if tag == 1:
                    svc.on_byte(v)
                elif tag == 2:
                    svc.on_pa2(v)
                elif tag == 3:
                    if not link.wait_ack:
                        link.credits += 1
                        svc.progress = time.monotonic()
                elif tag == 4:
                    link.flushed()
                elif tag == 5:
                    log("Reset der Bruecke")
                    svc.on_reset()
                elif tag == 6:
                    if not alive:
                        log("Bruecke da, Version", v)
                    alive = True
                    ping_out = None
                elif tag == 7:
                    svc.on_mark()
        if link.out:
            try:
                link.pump_out()
            except BlockingIOError:
                pass
        now = time.monotonic()
        if svc.reboot_at and now >= svc.reboot_at:
            svc.reboot_at = None
            link.queue(b"\x11")
        if svc.pending is not None and now - max(svc.progress, svc.pending_since) > 5.0:
            log("C64 holt die Antwort nicht ab, verwerfe sie")
            svc.gen += 1
            svc.pending = None
            link.flush()
        if now - ping_sent > 2.0 and not svc.busy and svc.pending is None and not link.out:
            if not active():
                return
            link.queue(b"\x12")
            ping_sent = now
            if ping_out is None:
                ping_out = now
        if ping_out is not None and now - ping_out > 5.0:
            if alive:
                log("Bruecke antwortet nicht mehr")
            return


def main():
    settings = Settings(SETTINGS_FILE)
    wic = WiC64(settings)
    log("wic64d", VERSION_STRING)
    while True:
        if not core_active():
            time.sleep(1)
            continue
        try:
            fd = open_tty(TTY)
        except OSError as e:
            log("ttyS1:", e)
            time.sleep(2)
            continue
        try:
            run_link(fd, lambda: dtr_toggle(fd), wic, core_active)
        except OSError as e:
            log("Leitung:", e)
        finally:
            os.close(fd)
        time.sleep(1)


if __name__ == "__main__":
    main()
