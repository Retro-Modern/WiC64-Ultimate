# HTTPS trust anchors

`cacert.pem` contains 118 Mozilla CA root certificates from curl's
2026-10-20 certificate bundle. The attribution and source information are
preserved in the file header.

SHA256: `2037e15746f1b6340e51753a8acad8250c513fa1da0b73aef22949b845c0d749`

The build generates an indexed DER store for WiC64 HTTPS from this file.
mbedTLS receives all matching trusted CA candidates while building the chain;
it verifies signatures, key sizes, host names and certificate dates, including
the selected trust anchor. The immutable certificates stay in firmware flash;
only the matching CA structures are allocated during verification.
The ESP-IDF configuration also uses this file for its existing certificate
bundle. Replacing the trust anchors requires rebuilding the ESP app.

See `LICENSES/Mozilla-CA.txt` at the package root for the license notice.

Sources and licensing information:

- https://curl.se/docs/caextract.html
- https://www.mozilla.org/MPL/2.0/
