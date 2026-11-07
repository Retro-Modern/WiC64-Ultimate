#ifndef P18_LOG_STREAM_H
#define P18_LOG_STREAM_H

namespace p18log {
// Dedicated WiC64 text log. Port 23 remains the Ultimate Telnet menu.
// PuTTY must use Raw, with local echo disabled. No SSH/Telnet negotiation.
enum { STREAM_PORT = 6464, STREAM_MAX_CLIENTS = 1 };
}

#endif
