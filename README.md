# WiC64 for MiSTer – Downloader database

Database for the MiSTer Downloader / update_all. Add this to the end of
`/media/fat/downloader.ini`:

```ini
[retro-modern/wic64]
db_url = https://raw.githubusercontent.com/Retro-Modern/WiC64-Ultimate/db/db.json
```

Then run update_all (or downloader) and once `Scripts > wic64_einrichten`.
It installs the C64 core with WiC64 (`_Computer/C64_WiC64_*.rbf`), the
service (`Scripts/.config/wic64/wic64d.py`) and the setup scripts.

Documentation and sources: https://github.com/Retro-Modern/WiC64-Ultimate/tree/main/mister ·
https://retro-modern.net/downloads.html#wic64
