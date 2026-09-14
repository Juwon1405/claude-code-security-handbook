#!/usr/bin/env python3
"""Standalone deterministic tests; no model, network, or existing lab input."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SUPPORT = Path(__file__).resolve().parent


class FoundationsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='foundations-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        self.env = os.environ.copy()
        for key in ('BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'CDPATH'):
            self.env.pop(key, None)
        self.env['LC_ALL'] = 'C'
        self.assertEqual(self.tool('generate.py', str(self.work)).returncode, 0)

    def command(self, args, input=None):
        return subprocess.run(args, cwd=self.base, env=self.env, input=input,
                              text=True, encoding='utf-8', capture_output=True,
                              timeout=20)

    def tool(self, name, *args):
        return self.command([sys.executable, str(SUPPORT / name), *args])

    def jq(self, program, file, *options):
        return self.command(['jq', *options, program, str(self.work / file)])

    def test_generator_repeats_and_refuses_overwrite(self):
        before = (self.work / 'input-sha256.json').read_bytes()
        second = self.base / 'second'
        self.assertEqual(self.tool('generate.py', str(second)).returncode, 0)
        self.assertEqual(before, (second / 'input-sha256.json').read_bytes())
        self.assertNotEqual(self.tool('generate.py', str(self.work)).returncode, 0)
        self.assertEqual(self.tool('check_inputs.py', str(self.work)).returncode, 0)
        self.assertEqual(len(json.loads(before)), 12)

    def test_line_validation_not_schema_validation(self):
        for name in ('events.jsonl', 'events-no-final-newline.jsonl'):
            result = self.tool('validate_jsonl.py', str(self.work / 'raw' / name))
            self.assertEqual((result.returncode, result.stdout), (0, 'records=6\n'))
        invalid_values = [b'{}\n\n{}\n', b'NaN\n', b'\xef\xbb\xbf{}\n', b'\xff\n']
        for index, value in enumerate(invalid_values):
            path = self.base / ('invalid-' + str(index) + '.jsonl')
            path.write_bytes(value)
            self.assertEqual(self.tool('validate_jsonl.py', str(path)).returncode, 2)
        valid = self.base / 'values.jsonl'
        valid.write_bytes(b'null\r\ntrue\r\n123\r\n')
        result = self.tool('validate_jsonl.py', str(valid))
        self.assertEqual((result.returncode, result.stdout), (0, 'records=3\n'))

    def test_utc_and_unresolved_timezone(self):
        result = self.tool('to_utc.py', str(self.work / 'raw/times.jsonl'))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), [
            'E3 2026-08-31T23:59:00Z', 'E1 2026-09-01T00:00:00Z',
            'E2 2026-09-01T00:01:00Z'])
        naive = self.tool('to_utc.py', str(self.work / 'raw/naive-time.jsonl'))
        self.assertEqual((naive.returncode, naive.stdout), (2, ''))
        self.assertIn('timezone required', naive.stderr)
        invalid = self.base / 'bad-time.jsonl'
        invalid.write_text('{"id":"X","ts":123}\n', encoding='utf-8')
        self.assertEqual(self.tool('to_utc.py', str(invalid)).returncode, 2)

    @unittest.skipUnless(all(shutil.which(name) for name in ('bash', 'grep', 'sed')),
                         'Bash, grep and sed are required for the shell checks')
    def test_grep_boundaries_statuses_and_pipeline(self):
        path = str(self.work / 'raw/pattern-samples.txt')
        for options, count in [('-c', '4\n'), ('-Fc', '3\n'), ('-Fxc', '2\n')]:
            result = self.command(['grep', options, '192.0.2.14', path])
            self.assertEqual((result.returncode, result.stdout), (0, count))
        missing = str(self.work / 'raw/missing.txt')
        self.assertEqual(self.command(['grep', '-Fx', '203.0.113.99', path]).returncode, 1)
        self.assertGreater(self.command(['grep', '-Fx', 'x', missing]).returncode, 1)
        for option, expected in [('+o', 0), ('-o', 2)]:
            program = 'set ' + option + ' pipefail; grep x "$1" | sed -n 1p'
            result = self.command([shutil.which('bash'), '--noprofile', '--norc', '-c',
                                   program, 'test-pipeline', missing])
            self.assertEqual(result.returncode, expected)

    @unittest.skipUnless(shutil.which('jq'), 'jq is required for the JSON filter checks')
    def test_json_types_empty_input_and_partial_output(self):
        result = self.jq('select(.status == 200) | .id', 'raw/events.jsonl', '-r')
        self.assertEqual(result.stdout, 'a2\na3\na6\n')
        types = self.jq('select(.id == "a4") | has("user")', 'raw/events.jsonl')
        self.assertEqual(types.stdout, 'false\n')
        query = ('[.[] | select(.ip == "192.0.2.14" and .status == 200)] | '
                 '{records:length,bytes:(map(.bytes)|add),ids:map(.id)}')
        summary = self.jq(query, 'raw/events.jsonl', '-s')
        self.assertEqual(json.loads(summary.stdout),
                         {'records': 2, 'bytes': 768, 'ids': ['a3', 'a6']})
        self.assertEqual(self.jq('.', 'raw/spaces.json', '-e').returncode, 4)
        self.assertEqual(self.jq('.', 'raw/spaces.json', '-e', '-s').returncode, 0)
        nonempty = self.jq('length > 0 and all(.[];type == "object")',
                           'raw/spaces.json', '-e', '-s')
        self.assertEqual(nonempty.returncode, 1)
        partial = self.jq('.id', 'raw/broken.jsonl', '-r')
        self.assertGreater(partial.returncode, 1)
        self.assertEqual(partial.stdout, 'a1\n')
        self.assertTrue(partial.stderr)

    def test_original_digest_detects_changed_input(self):
        raw = self.work / 'raw/utf8.txt'
        previous = hashlib.sha256(raw.read_bytes()).hexdigest()
        raw.write_bytes(raw.read_bytes() + b'changed\n')
        self.assertNotEqual(hashlib.sha256(raw.read_bytes()).hexdigest(), previous)
        result = self.tool('check_inputs.py', str(self.work))
        self.assertEqual(result.returncode, 1)
        self.assertIn('raw/utf8.txt', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
