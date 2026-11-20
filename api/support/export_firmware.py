#!/usr/bin/env python3
"""Exports catalog.json to the firmware: one <id>.sh and one <id>.json per Support Packet.

Usage: export_firmware.py DEST_DIR   (DEST is packages/ns-api/support-packets in the firmware tree)
catalog.json stays the single source; the firmware copy is generated, never edited by hand.
"""
import json, os, sys

src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'catalog.json')
dest = sys.argv[1]
os.makedirs(dest, exist_ok=True)
cat = json.load(open(src))
keep = set()
for e in cat:
    meta = {
        'id': e['id'], 'class': e['class'], 'timeout_sec': e['timeout_sec'], 'max_output': e['max_output'], 'cleanup': e.get('cleanup', ''),
        'params': [{k: p[k] for k in ('name', 'kind', 'required', 'default', 'min', 'max', 'enum') if k in p} for p in e['params']],
    }
    json.dump(meta, open(os.path.join(dest, e['id'] + '.json'), 'w'), indent=1, sort_keys=True)
    open(os.path.join(dest, e['id'] + '.json'), 'a').write('\n')
    open(os.path.join(dest, e['id'] + '.sh'), 'w').write('#!/bin/sh\n# Nexwall Support Packet: %s (class %s). Generated from the controller catalog.\n%s\n' % (e['id'], e['class'], e['script'].rstrip('\n')))
    keep |= {e['id'] + '.json', e['id'] + '.sh'}
for f in os.listdir(dest):
    if f not in keep:
        os.remove(os.path.join(dest, f))
print('exported', len(cat), 'packets to', dest)
