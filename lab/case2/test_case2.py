#!/usr/bin/env python3
"""Independent hand-written fixtures and adversarial checks for case2/v1.

Tests do not import generate.py or its row-building functions. Integration
expectations are literal calculations from the documented scenario. A second
SQLite aggregation checks raw evidence without using the analysis functions.
"""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import analyze

ROOT = Path(__file__).resolve().parent


def fixture():
    # Deliberately different identifiers, date and byte sizes from the book data.
    start = {"schema": "case2/v1", "source": "case2-auth", "event_id": "start-x",
             "event_time": "2026-01-01T00:00:00Z", "realm": "r", "user": "u",
             "host": "h", "session_id": "s", "action": "session_start",
             "outcome": "allowed", "client_ip": "192.0.2.1"}
    end = dict(start, event_id="end-x", event_time="2026-01-01T00:10:00Z",
               action="session_end", outcome="closed")
    read = {"schema": "case2/v1", "source": "case2-file", "event_id": "read-x",
            "event_time": "2026-01-01T09:01:00+09:00", "realm": "r", "user": "u",
            "host": "h", "session_id": "s", "action": "read", "outcome": "allowed",
            "path": "/sample.txt", "bytes_returned": 7}
    transfer = {"schema": "case2/v1", "source": "case2-transfer", "event_id": "send-x",
                "event_time": "2026-01-01T00:02:00Z", "realm": "r", "user": "u",
                "host": "h", "session_id": "s", "transfer_id": "tx",
                "state": "interrupted", "destination_zone": "external",
                "destination": "target.example.com", "destination_ip": "198.51.100.1",
                "declared_bytes": 9, "bytes_sent": 3, "artifact": "sample.zip"}
    return {"auth.jsonl": [start, end], "file.jsonl": [read], "transfer.jsonl": [transfer]}


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case2-test-")
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, rows):
        for name, values in rows.items():
            (self.evidence / name).write_text("".join(json.dumps(x) + "\n" for x in values), encoding="utf-8")

    def compute(self, rows):
        self.write(rows)
        return analyze.compute(*analyze.read_evidence(self.evidence))[0]

    def test_manual_fixture_time_and_bytes(self):
        result = self.compute(fixture())
        self.assertEqual((result["physical_rows"], result["unique_events"], len(result["unlinked"])), (4, 4, 0))
        session = result["sessions"][0]
        self.assertEqual(session["returned_bytes_sum"], 7)
        self.assertEqual(session["external_known_sent_bytes"], 3)
        self.assertEqual(session["external_completed_sent_bytes"], 0)

    def test_duplicate_preserves_references(self):
        data = fixture()
        data["file.jsonl"].append(dict(data["file.jsonl"][0]))
        result = self.compute(data)
        self.assertEqual(result["duplicate_rows"], 1)
        self.assertEqual(result["sessions"][0]["returned_bytes_sum"], 7)
        self.assertEqual(result["duplicates"], [{"ref": "file.jsonl:2", "canonical_ref": "file.jsonl:1"}])

    def test_conflicting_duplicate_fails_without_output(self):
        data = fixture()
        data["file.jsonl"].append(dict(data["file.jsonl"][0], bytes_returned=8))
        self.write(data)
        with self.assertRaisesRegex(ValueError, "conflicting duplicate"):
            analyze.analyze(self.evidence, self.root / "out")
        self.assertFalse((self.root / "out").exists())

    def test_host_mismatch_is_unlinked(self):
        data = fixture()
        data["file.jsonl"][0]["host"] = "other"
        result = self.compute(data)
        self.assertEqual(result["unlinked"][0]["reason"], "no_matching_session_key")
        self.assertEqual(result["sessions"][0]["file_allowed"], 0)

    def test_end_boundary_excluded_start_included(self):
        data = fixture()
        data["file.jsonl"][0]["event_time"] = "2026-01-01T00:10:00Z"
        data["transfer.jsonl"][0]["event_time"] = "2026-01-01T00:00:00Z"
        result = self.compute(data)
        self.assertEqual([x["ref"] for x in result["unlinked"]], ["file.jsonl:1"])
        self.assertEqual(result["sessions"][0]["external_known_sent_bytes"], 3)

    def test_reused_session_id_has_distinct_windows(self):
        data = fixture()
        data["auth.jsonl"] += [dict(data["auth.jsonl"][0], event_id="start-y", event_time="2026-01-01T00:20:00Z"),
                                dict(data["auth.jsonl"][1], event_id="end-y", event_time="2026-01-01T00:30:00Z")]
        data["transfer.jsonl"][0]["event_time"] = "2026-01-01T00:21:00Z"
        result = self.compute(data)
        self.assertEqual([x["external_known_sent_bytes"] for x in result["sessions"]], [0, 3])

    def test_overlap_rejected(self):
        data = fixture()
        data["auth.jsonl"].append(dict(data["auth.jsonl"][0], event_id="start-y", event_time="2026-01-01T00:01:00Z"))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            self.compute(data)

    def test_offset_range_and_unknown_offset_rejected(self):
        for offset in ("+09:99", "+24:00", "-00:00", "-12:60"):
            data = fixture()
            data["file.jsonl"][0]["event_time"] = "2026-01-01T00:01:00" + offset
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "UTC offset"):
                    self.compute(data)

    def test_open_window_explicit(self):
        data = fixture()
        data["auth.jsonl"].pop()
        result = self.compute(data)
        self.assertEqual(result["open_session_windows"], 1)
        self.assertIsNone(result["sessions"][0]["end"])

    def test_unknown_bytes_not_zero_events(self):
        data = fixture()
        data["transfer.jsonl"][0].update(state="queued", bytes_sent=None)
        result = self.compute(data)["sessions"][0]
        self.assertEqual(result["external_known_sent_bytes"], 0)
        self.assertEqual(result["external_unknown_byte_events"], 1)

    def test_transfer_state_history_not_summed(self):
        data = fixture()
        data["transfer.jsonl"].append(dict(data["transfer.jsonl"][0], event_id="send-later", state="completed", bytes_sent=9))
        with self.assertRaisesRegex(ValueError, "state-history parser"):
            self.compute(data)

    def test_invalid_inputs(self):
        cases = [
            ("file.jsonl", "bytes_returned", True, "bytes_returned"),
            ("file.jsonl", "bytes_returned", -1, "bytes_returned"),
            ("file.jsonl", "event_time", "2026-01-01T00:01:00", "explicit offset"),
            ("transfer.jsonl", "state", "successful", "transfer state"),
            ("transfer.jsonl", "bytes_sent", 10, "within declared"),
            ("transfer.jsonl", "bytes_sent", None, "within declared"),
            ("auth.jsonl", "client_ip", 3221225985, "must be a string"),
        ]
        for name, key, value, message in cases:
            with self.subTest(key=key, value=value):
                data = fixture()
                data[name][0][key] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.compute(data)

    def test_denied_or_blocked_nonzero_rejected(self):
        for name, key, value, message in (("file.jsonl", "outcome", "denied", "zero returned"),
                                           ("transfer.jsonl", "state", "blocked", "zero bytes")):
            data = fixture()
            data[name][0][key] = value
            with self.assertRaisesRegex(ValueError, message):
                self.compute(data)

    def test_duplicate_json_keys_and_empty_line_rejected(self):
        self.write(fixture())
        path = self.evidence / "file.jsonl"
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace('"bytes_returned": 7', '"bytes_returned": 7, "bytes_returned": 8'), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            analyze.read_evidence(self.evidence)
        path.write_text(original + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "empty/oversized"):
            analyze.read_evidence(self.evidence)

    def test_extra_file_rejected(self):
        self.write(fixture())
        (self.evidence / "answer.txt").write_text("not evidence", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exactly"):
            analyze.read_evidence(self.evidence)

    def test_symlink_rejected(self):
        self.write(fixture())
        (self.evidence / "file.jsonl").rename(self.root / "saved.jsonl")
        try:
            (self.evidence / "file.jsonl").symlink_to(self.root / "saved.jsonl")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows user lacks the privilege to create a symbolic link")
            raise
        with self.assertRaisesRegex(ValueError, "regular file"):
            analyze.read_evidence(self.evidence)

    def test_output_refusal_and_source_preservation(self):
        self.write(fixture())
        before = {p.name: p.read_bytes() for p in self.evidence.iterdir()}
        out = self.root / "result"
        analyze.analyze(self.evidence, out)
        with self.assertRaisesRegex(ValueError, "already exists"):
            analyze.analyze(self.evidence, out)
        with self.assertRaisesRegex(ValueError, "inside evidence"):
            analyze.analyze(self.evidence, self.evidence / "result")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.evidence.iterdir()})


class GeneratedDataTests(unittest.TestCase):
    def test_generation_and_independent_sql(self):
        with tempfile.TemporaryDirectory(prefix="case2-integration-") as temp:
            root = Path(temp)
            for name in ("one", "two"):
                subprocess.run([sys.executable, str(ROOT / "generate.py"), "--out", str(root / name)], check=True, capture_output=True)
            evidence = root / "one" / "evidence"
            hashes = {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest() for name in analyze.NAMES}
            self.assertEqual(hashes, {name: hashlib.sha256((root / "two" / "evidence" / name).read_bytes()).hexdigest() for name in analyze.NAMES})
            # Existing nonempty AND empty targets both fail.
            (root / "empty").mkdir()
            for name in ("one", "empty"):
                run = subprocess.run([sys.executable, str(ROOT / "generate.py"), "--out", str(root / name)], capture_output=True)
                self.assertEqual(run.returncode, 2)
            summary = analyze.analyze(evidence, root / "analysis")
            self.assertEqual((summary["physical_rows"], summary["unique_events"], summary["duplicate_rows"]), (53, 48, 5))
            self.assertEqual(len(summary["sessions"]), 5)
            self.assertEqual([x["ref"] for x in summary["unlinked"]], ["file.jsonl:17", "file.jsonl:18", "file.jsonl:19", "transfer.jsonl:11"])
            target = next(x for x in summary["sessions"] if x["instance"] == "auth.jsonl:3")
            # Manual arithmetic: 32768 + 65536 + 8192 + 32768 = 139264;
            # two 65536 completed operations + 12288 partial = 143360.
            self.assertEqual((target["file_allowed"], target["file_denied"], target["allowed_unique_paths"],
                              target["returned_bytes_sum"], target["external_known_sent_bytes"],
                              target["external_unknown_byte_events"]), (4, 1, 3, 139264, 143360, 1))
            database = sqlite3.connect(":memory:")
            database.execute("CREATE TABLE e(source TEXT, id TEXT, realm TEXT, user TEXT, host TEXT, sid TEXT, ts TEXT, kind TEXT, outcome TEXT, zone TEXT, bytes INTEGER, PRIMARY KEY(source,id))")
            for name in ("auth.jsonl", "file.jsonl", "transfer.jsonl"):
                for line in (evidence / name).read_text(encoding="utf-8").splitlines():
                    row = json.loads(line)
                    # SQLite datetime() normalizes the explicit offset; neither
                    # generator timestamp helper nor analyzer parse_time is used.
                    database.execute("INSERT OR IGNORE INTO e VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                        row["source"], row["event_id"], row["realm"], row["user"], row["host"], row["session_id"],
                        row["event_time"], name, row.get("outcome", row.get("state")), row.get("destination_zone"),
                        row.get("bytes_returned", row.get("bytes_sent"))))
            result = database.execute("SELECT count(*),sum(bytes) FROM e WHERE kind='file.jsonl' AND realm='staff' AND user='account-a' AND host='work-b' AND sid='S-200' AND outcome='allowed' AND datetime(ts)>='2026-09-07 09:10:00' AND datetime(ts)<'2026-09-07 09:25:00'").fetchone()
            self.assertEqual(result, (4, 139264))
            result = database.execute("SELECT count(*),sum(bytes),sum(bytes IS NULL) FROM e WHERE kind='transfer.jsonl' AND realm='staff' AND user='account-a' AND host='work-b' AND sid='S-200' AND zone='external' AND datetime(ts)>='2026-09-07 09:10:00' AND datetime(ts)<'2026-09-07 09:25:00'").fetchone()
            self.assertEqual(result, (5, 143360, 1))
            database.close()
            self.assertEqual(hashes, {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest() for name in analyze.NAMES})


if __name__ == "__main__":
    unittest.main(verbosity=2)
