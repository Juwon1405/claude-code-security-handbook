#!/usr/bin/env python3
"""19장 복구 예제의 모의 회귀 시험. 실모델을 호출하지 않는다."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import recover


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="handbook-recovery-")
        self.root = Path(self.temp.name) / "demo"
        recover.make_demo(self.root)
        self.folder = self.root / "attempts" / "attempt-001"

    def tearDown(self):
        self.temp.cleanup()

    def change(self, name, **changes):
        path = self.folder / name
        value = json.loads(path.read_text())
        value.update(changes)
        path.write_text(json.dumps(value), encoding="utf-8")

    def state(self):
        return recover.audit(self.root)["attempts"][0]["state"]

    def test_exact_demo_states(self):
        self.assertEqual([x["state"] for x in recover.audit(self.root)["attempts"]], [
            "ready_for_review", "process_failed", "model_error",
            "invalid_json", "quote_mismatch", "incomplete"])

    def test_audit_does_not_write(self):
        def hashes():
            return {str(p.relative_to(self.root)):
                    hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in self.root.rglob("*") if p.is_file()}
        before = hashes()
        recover.audit(self.root)
        self.assertEqual(before, hashes())

    def test_create_refuses_existing_directory(self):
        with self.assertRaises(FileExistsError):
            recover.make_demo(self.root)

    def test_tampered_source_stops_before_processing(self):
        with (self.root / "evidence" / "access.jsonl").open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaisesRegex(ValueError, "무결성"):
            recover.audit(self.root)

    def test_different_input_attempt(self):
        self.change("run.json", source_sha256="0" * 64)
        self.assertEqual(self.state(), "input_mismatch")

    def test_boolean_exit_code_rejected(self):
        self.change("run.json", exit_code=False)
        self.assertEqual(self.state(), "invalid_record")

    def test_boolean_line_rejected(self):
        obj = json.loads((self.folder / "response.json").read_text())
        obj["structured_output"]["line"] = True
        self.change("response.json", structured_output=obj["structured_output"])
        self.assertEqual(self.state(), "invalid_response")

    def test_missing_response(self):
        (self.folder / "response.json").rename(self.folder / "saved-response.json")
        self.assertEqual(self.state(), "missing_response")

    def test_duplicate_keys_rejected(self):
        (self.folder / "response.json").write_text(
            '{"is_error":true,"is_error":false}', encoding="utf-8")
        self.assertEqual(self.state(), "invalid_json")

    def test_nonfinite_json_numbers_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self.change("response.json", extra=value)
                self.assertEqual(self.state(), "invalid_json")

    def test_multiline_quote_rejected(self):
        obj = json.loads((self.folder / "response.json").read_text())
        obj["structured_output"]["quote"] += "\nextra"
        self.change("response.json", structured_output=obj["structured_output"])
        self.assertEqual(self.state(), "quote_mismatch")

    def test_path_manifest_rejected(self):
        path = self.root / "input-manifest.json"
        obj = json.loads(path.read_text())
        obj["source"] = "../elsewhere.jsonl"
        path.write_text(json.dumps(obj), encoding="utf-8")
        with self.assertRaises(ValueError):
            recover.audit(self.root)

    def test_symlink_response_rejected(self):
        path = self.folder / "response.json"
        saved = self.folder / "response-saved.json"
        path.rename(saved)
        path.symlink_to(saved.name)
        self.assertEqual(self.state(), "invalid_json")

    def test_extra_attempt_not_silently_ignored(self):
        (self.root / "attempts" / "unrecorded").mkdir()
        with self.assertRaisesRegex(ValueError, "목록"):
            recover.audit(self.root)

    def test_semantic_overclaim_is_not_validated(self):
        obj = json.loads((self.folder / "response.json").read_text())
        obj["structured_output"]["statement"] = "실제 계정 주인이 확인되었다."
        self.change("response.json", structured_output=obj["structured_output"])
        self.assertEqual(self.state(), "ready_for_review")


if __name__ == "__main__":
    unittest.main(verbosity=2)
