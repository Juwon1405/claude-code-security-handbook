#!/usr/bin/env python3
"""Compare original exercise input bytes with the generation manifest."""
import hashlib
import json
from pathlib import Path
import sys


def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    manifest = json.loads((base / 'input-sha256.json').read_text('utf-8'))
    changed = [name for name, digest in manifest.items()
               if not (base / name).is_file()
               or hashlib.sha256((base / name).read_bytes()).hexdigest()
               != digest]
    print('originals=unchanged' if not changed else 'originals=changed')
    if changed:
        print('\n'.join(changed), file=sys.stderr)
    return bool(changed)


if __name__ == '__main__':
    raise SystemExit(main())
