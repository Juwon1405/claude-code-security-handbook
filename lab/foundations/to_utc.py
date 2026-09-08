#!/usr/bin/env python3
"""Sort the exercise's explicit-offset ISO 8601 timestamps in UTC."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: python3 to_utc.py FILE')
    try:
        rows = []
        for line in Path(sys.argv[1]).read_text('utf-8').splitlines():
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError('record must be an object')
            if not isinstance(record.get('id'), str):
                raise ValueError('id must be a string')
            if not isinstance(record.get('ts'), str):
                raise ValueError('ts must be a string')
            stamp = record['ts']
            if stamp.endswith('Z'):
                stamp = stamp[:-1] + '+00:00'
            instant = datetime.fromisoformat(stamp)
            if instant.tzinfo is None or instant.utcoffset() is None:
                raise ValueError('timezone required: ' + record['id'])
            rows.append((instant.astimezone(timezone.utc), record['id']))
        rows.sort()
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    for instant, record_id in rows:
        print(record_id, instant.isoformat().replace('+00:00', 'Z'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
