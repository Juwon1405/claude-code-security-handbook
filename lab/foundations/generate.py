#!/usr/bin/env python3
"""Create the deterministic Appendix C exercise in a new directory."""
import hashlib
import json
from pathlib import Path
import sys


def encoded(value, indent=None):
    return json.dumps(value, ensure_ascii=False, indent=indent)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: python3 generate.py NEW_DIRECTORY')
    target = Path(sys.argv[1])
    if target.exists():
        raise SystemExit('refusing to overwrite an existing directory')
    target.mkdir(parents=True)
    raw = target / 'raw'
    raw.mkdir()
    (target / 'out').mkdir()
    records = [
        dict(id='a1', ip='192.0.2.14', status=403, bytes=0,
             user='min', authenticated=False, tags=['login']),
        dict(id='a2', ip='192.0.2.140', status=200, bytes=128,
             user='lee', authenticated=True, tags=[]),
        dict(id='a3', ip='192.0.2.14', status=200, bytes=512,
             user=None, authenticated=True, tags=['download']),
        dict(id='a4', ip='198.51.100.20', status='200', bytes='64',
             authenticated=False, tags=[]),
        dict(id='a5', ip='203.0.113.9', status=500, bytes=None,
             user='ops', authenticated=False, tags=['error']),
        dict(id='a6', ip='192.0.2.14', status=200, bytes=256,
             user='민수', authenticated=True, tags=['download']),
    ]
    lines = '\n'.join(encoded(row) for row in records)
    fixtures = {
        'events.jsonl': lines + '\n',
        'events-array.json': encoded(records, indent=2) + '\n',
        'events-no-final-newline.jsonl': lines,
        'with-blank.jsonl': encoded(records[0]) + '\n\n'
                           + encoded(records[1]) + '\n',
        'spaces.json': ' \t\n \n',
        'broken.jsonl': encoded(records[0]) + '\n{"id":\n',
        'pattern-samples.txt': '192.0.2.14\n192.0.2.140\n'
                               '192x0x2x14\n192.0.2.14\n',
        'access sample.txt': 'alpha\nbeta\n',
        'ip-crlf.txt': '192.0.2.14\r\n198.51.100.20\r\n',
        'utf8.txt': '조사\n',
        'times.jsonl': '\n'.join(encoded(row) for row in [
            {'id': 'E1', 'ts': '2026-09-01T09:00:00+09:00'},
            {'id': 'E2', 'ts': '2026-09-01T00:01:00+00:00'},
            {'id': 'E3', 'ts': '2026-09-01T08:59:00+09:00'},
        ]) + '\n',
        'naive-time.jsonl': '{"id":"N1","ts":"2026-09-01T09:00:00"}\n',
    }
    hashes = {}
    for name, value in fixtures.items():
        data = value.encode('utf-8')
        (raw / name).write_bytes(data)
        hashes['raw/' + name] = hashlib.sha256(data).hexdigest()
    (target / 'input-sha256.json').write_text(
        encoded(hashes, indent=2) + '\n', encoding='utf-8')
    print('created=' + target.name)
    print('records=' + str(len(records)))
    print('raw_files=' + str(len(fixtures)))


if __name__ == '__main__':
    main()
