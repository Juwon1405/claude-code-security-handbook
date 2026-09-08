#!/usr/bin/env python3
"""Validate UTF-8 and one JSON value per line; not an object schema."""
import json
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: python3 validate_jsonl.py FILE')
    try:
        data = Path(sys.argv[1]).read_bytes().decode('utf-8')
        if data.startswith('\ufeff'):
            raise ValueError('UTF-8 BOM is not accepted')
        lines = data.split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        for number, line in enumerate(lines, 1):
            if not line.strip():
                raise ValueError('blank line at ' + str(number))
            def reject_constant(value):
                raise ValueError('non-JSON constant: ' + value)
            json.loads(line, parse_constant=reject_constant)
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print('records=' + str(len(lines)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
