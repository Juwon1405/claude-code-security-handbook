#!/usr/bin/env python3
"""합성 데이터 보존과 감사 훅 오류 처리를 시험한다. 모델 호출은 없다."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
GEN = HERE / 'gen_lab_data.py'
if not GEN.is_file():
    GEN = HERE.parent / 'scripts' / 'gen_lab_data.py'


def hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file()}


class GeneratorSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='handbook-safety-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def generate(self, parent):
        return subprocess.run([sys.executable, str(GEN), str(parent / 'evidence')],
                              capture_output=True, timeout=30)

    def test_fresh_runs_are_identical_utf8_lf(self):
        a, b = self.root / 'a', self.root / 'b'
        self.assertEqual(self.generate(a).returncode, 0)
        self.assertEqual(self.generate(b).returncode, 0)
        self.assertEqual(hashes(a), hashes(b))
        manifest = (a / 'lab-manifest.txt').read_text(encoding='utf-8')
        self.assertLess(manifest.index('untrusted-sample/README.txt'),
                        manifest.index('untrusted-sample/notes.md'))
        self.assertEqual(len(list((a / 'evidence').glob('*.*'))), 8)
        for file in a.rglob('*'):
            if file.is_file():
                data = file.read_bytes()
                data.decode('utf-8')
                self.assertNotIn(b'\r\n', data)

    def test_existing_evidence_is_untouched(self):
        self.assertEqual(self.generate(self.root).returncode, 0)
        before = hashes(self.root)
        self.assertNotEqual(self.generate(self.root).returncode, 0)
        self.assertEqual(before, hashes(self.root))

    def test_existing_marker_is_untouched(self):
        (self.root / 'derived').mkdir()
        (self.root / 'derived/marker.txt').write_bytes(b'keep\n')
        before = hashes(self.root)
        self.assertNotEqual(self.generate(self.root).returncode, 0)
        self.assertEqual(before, hashes(self.root))
        self.assertFalse((self.root / 'evidence').exists())

    def test_existing_manifest_is_untouched(self):
        (self.root / 'lab-manifest.txt').write_bytes(b'keep\n')
        self.assertNotEqual(self.generate(self.root).returncode, 0)
        self.assertEqual((self.root / 'lab-manifest.txt').read_bytes(), b'keep\n')
        self.assertFalse((self.root / 'evidence').exists())

    def test_existing_empty_evidence_is_rejected(self):
        (self.root / 'evidence').mkdir()
        self.assertNotEqual(self.generate(self.root).returncode, 0)
        self.assertEqual(list((self.root / 'evidence').iterdir()), [])


@unittest.skipUnless(shutil.which('bash') and shutil.which('jq'), 'Bash and jq are required for hook tests')
class AuditSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='handbook-audit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'derived').mkdir()
        self.env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.root))

    def hook(self, payload):
        return subprocess.run(['bash', str(HERE / 'bin/audit.sh')], input=payload,
                              text=True, capture_output=True, env=self.env, timeout=5)

    def test_valid_input_records_one_line(self):
        self.assertEqual(self.hook('{"tool_name":"Bash"}').returncode, 0)
        rows=(self.root / 'derived/audit.log').read_text().splitlines()
        self.assertEqual(len(rows), 1)
        self.assertRegex(rows[0], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tBash$')

    def test_malformed_input_reports_failure(self):
        self.assertNotEqual(self.hook('{').returncode, 0)
        self.assertFalse((self.root / 'derived/audit.log').exists())

    def test_multiple_json_objects_report_failure(self):
        self.assertNotEqual(self.hook('{"tool_name":"Bash"}\n{"tool_name":"Read"}').returncode, 0)
        self.assertFalse((self.root / 'derived/audit.log').exists())

    @unittest.skipIf(os.name == 'nt', 'Unix symlink used to inject date failure')
    def test_date_failure_reports_failure(self):
        binaries = self.root / 'bin'
        binaries.mkdir()
        (binaries / 'date').symlink_to(shutil.which('false'))
        self.env['PATH'] = str(binaries) + os.pathsep + self.env['PATH']
        self.assertNotEqual(self.hook('{"tool_name":"Bash"}').returncode,0)
        self.assertFalse((self.root / 'derived/audit.log').exists())

    def test_invalid_names_report_failure(self):
        for value in ('', None, 5, 'Bash\nWrite', 'Bash\x00Write'):
            with self.subTest(value=repr(value)):
                self.assertNotEqual(self.hook(json.dumps({'tool_name':value})).returncode,0)
        self.assertFalse((self.root / 'derived/audit.log').exists())

    def test_missing_project_reports_failure(self):
        self.env.pop('CLAUDE_PROJECT_DIR',None)
        self.assertNotEqual(self.hook('{"tool_name":"Bash"}').returncode,0)

    def test_unwritable_target_reports_failure(self):
        (self.root / 'derived/audit.log').mkdir()
        self.assertNotEqual(self.hook('{"tool_name":"Bash"}').returncode,0)


@unittest.skipUnless(shutil.which('bash') and shutil.which('jq'), 'Bash and jq are required for hook tests')
class GuardSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='handbook-guard-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'derived').mkdir()
        self.env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.root))

    def hook(self, payload):
        return subprocess.run(['bash', str(HERE / 'bin/guard.sh')], input=payload,
                              text=True, capture_output=True, env=self.env,
                              cwd=self.root, timeout=5)

    def payload(self, command):
        return json.dumps({'session_id': 'synthetic-guard', 'tool_use_id': 'test-input',
                           'tool_name': 'Bash', 'tool_input': {'command': command}})

    def test_read_command_passes(self):
        self.assertEqual(self.hook(self.payload('grep Accepted evidence/auth.log')).returncode, 0)
        self.assertFalse((self.root / 'derived/guard-denials.jsonl').exists())

    def test_write_patterns_block_and_record(self):
        commands = ('echo probe > evidence/probe.log',
                    'echo probe >> evidence/probe.log',
                    'rm evidence/probe.log',
                    'mv evidence/probe.log derived/probe.log',
                    'truncate -s 0 evidence/probe.log')
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.hook(self.payload(command)).returncode, 2)
        rows = [json.loads(row) for row in
                (self.root / 'derived/guard-denials.jsonl').read_text().splitlines()]
        self.assertEqual([row['command'] for row in rows], list(commands))
        self.assertTrue(all(row['session_id'] == 'synthetic-guard' and
                            row['tool_use_id'] == 'test-input' for row in rows))

    def test_malformed_json_blocks(self):
        for payload in ('', '{', 'not json'):
            with self.subTest(payload=payload):
                self.assertEqual(self.hook(payload).returncode, 2)

    def test_wrong_input_types_block(self):
        for value in (None, 42, [], {}, {'tool_input': 'command'},
                      {'tool_input': []}, {'tool_input': {}},
                      {'tool_input': {'command': 42}},
                      {'tool_input': {'command': None}}):
            with self.subTest(value=value):
                self.assertEqual(self.hook(json.dumps(value)).returncode, 2)

    def test_multiple_json_objects_block(self):
        valid = self.payload('grep Accepted evidence/auth.log')
        invalid = self.payload(42)
        for payload in (valid + '\n' + valid, invalid + '\n' + valid,
                        valid + '\n' + invalid):
            with self.subTest(payload=payload):
                self.assertEqual(self.hook(payload).returncode, 2)
        self.assertFalse((self.root / 'derived/guard-denials.jsonl').exists())

    def test_nul_command_blocks_before_shell_conversion(self):
        for command in ('\x00grep evidence/auth.log', 'gr\x00ep evidence/auth.log',
                        'grep evidence/auth.log\x00'):
            with self.subTest(command=repr(command)):
                result = self.hook(self.payload(command))
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('ignored null byte', result.stderr)
        self.assertFalse((self.root / 'derived/guard-denials.jsonl').exists())

    def test_multiline_and_tab_commands_remain_strings(self):
        command = 'grep\tAccepted evidence/auth.log\nwc -l evidence/auth.log'
        self.assertEqual(self.hook(self.payload(command)).returncode, 0)

    def test_log_write_failure_still_blocks(self):
        (self.root / 'derived/guard-denials.jsonl').mkdir()
        result = self.hook(self.payload('echo probe >> evidence/probe.log'))
        self.assertEqual(result.returncode, 2)
        self.assertIn('저장에 실패', result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Unix symlink used to inject date failure')
    def test_date_failure_skips_record_and_still_blocks(self):
        binaries = self.root / 'bin'
        binaries.mkdir()
        (binaries / 'date').symlink_to(shutil.which('false'))
        self.env['PATH'] = str(binaries) + os.pathsep + self.env['PATH']
        result = self.hook(self.payload('echo probe >> evidence/probe.log'))
        self.assertEqual(result.returncode, 2)
        self.assertIn('기록 시각을 읽지 못해', result.stderr)
        self.assertFalse((self.root / 'derived/guard-denials.jsonl').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
