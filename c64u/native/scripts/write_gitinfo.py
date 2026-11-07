#!/usr/bin/env python3
"""Write upstream's version header from the exported source snapshot metadata."""
import datetime
import json
import os
from pathlib import Path
import platform
import sys

root = Path(__file__).resolve().parents[1]
revision = json.loads((root / 'source_revision.json').read_text())
epoch = os.environ.get('SOURCE_DATE_EPOCH')
date = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch else datetime.datetime.now(datetime.timezone.utc)
values = {
    'APP_VERSION_TAG': revision['tag'],
    'APP_VERSION_BRANCH': revision['branch'],
    'APP_VERSION_DATE': revision['commit_date'],
    'APP_VERSION_HASH': revision['commit'][:7],
    'APP_BUILD_DATE': date.strftime('%Y-%m-%d %H:%M'),
    'APP_BUILD_MACHINE': platform.node(),
}
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text('/* Generated from source_revision.json, not a Git checkout. */\n' + ''.join('#define %s %s\n' % (key, json.dumps(value)) for key, value in values.items()))
