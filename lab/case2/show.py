#!/usr/bin/env python3
"""Display computed case2 results or original numbered lines without editing them."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    summary = sub.add_parser("summary")
    summary.add_argument("--analysis", required=True, type=Path)
    quote = sub.add_parser("quote")
    quote.add_argument("--evidence", required=True, type=Path)
    quote.add_argument("refs", nargs="+")
    naive = sub.add_parser("naive")
    naive.add_argument("--evidence", required=True, type=Path)
    naive.add_argument("--user", default="account-a")
    timeline = sub.add_parser("timeline")
    timeline.add_argument("--analysis", required=True, type=Path)
    timeline.add_argument("--instance", required=True)
    receipt = sub.add_parser("verify-receipt")
    receipt.add_argument("--case", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "summary":
            value = json.loads((args.analysis / "summary.json").read_text(encoding="utf-8"))
            print("rows=%d unique=%d duplicates=%d unlinked=%d" % (
                value["physical_rows"], value["unique_events"], value["duplicate_rows"], len(value["unlinked"])))
            for item in value["sessions"]:
                print("%s %s %s..%s allowed=%d denied=%d paths=%d read_bytes=%d external_known=%d external_unknown=%d" % (
                    item["instance"], "/".join(item["key"]), item["start"], item["end"],
                    item["file_allowed"], item["file_denied"], item["allowed_unique_paths"],
                    item["returned_bytes_sum"], item["external_known_sent_bytes"], item["external_unknown_byte_events"]))
            for item in value["unlinked"]:
                print("UNLINKED %s %s" % (item["ref"], item["reason"]))
        elif args.command == "quote":
            for ref in args.refs:
                match = re.fullmatch(r"(auth|file|transfer)\.jsonl:([1-9][0-9]*)", ref)
                if not match:
                    raise ValueError("expected documented filename:positive-line-number")
                path = args.evidence / (match.group(1) + ".jsonl")
                if path.is_symlink() or not path.is_file():
                    raise ValueError("quote input must be a regular file")
                lines = path.read_bytes().splitlines()
                number = int(match.group(2))
                if number > len(lines):
                    raise ValueError("line outside input: " + ref)
                print(ref + " " + lines[number - 1].decode("utf-8"))
        elif args.command == "verify-receipt":
            receipt = json.loads((args.case / "receipt.json").read_text(encoding="utf-8"))
            if set(receipt["files"]) != {"auth.jsonl", "file.jsonl", "transfer.jsonl"}:
                raise ValueError("unexpected receipt filenames")
            for name, record in sorted(receipt["files"].items()):
                data = (args.case / "evidence" / name).read_bytes()
                actual = {"bytes": len(data), "lines": len(data.splitlines()),
                          "sha256": hashlib.sha256(data).hexdigest()}
                if actual != record:
                    raise ValueError("receipt mismatch: " + name)
                print("MATCH %s lines=%d bytes=%d" % (name, actual["lines"], actual["bytes"]))
        elif args.command == "timeline":
            summary = json.loads((args.analysis / "summary.json").read_text(encoding="utf-8"))
            windows = [w for w in summary["sessions"] if w["instance"] == args.instance]
            if len(windows) != 1:
                raise ValueError("unknown session instance")
            window = windows[0]
            refs = set(window["start_refs"] + window["end_refs"] + window["file_refs"] + window["transfer_refs"])
            for line in (args.analysis / "timeline.jsonl").read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if refs.intersection(row["refs"]):
                    event = row["event"]
                    print("%s %s %s %s" % (row["utc"], row["refs"][0],
                          event.get("action", "transfer"), event.get("outcome", event.get("state"))))
        else:
            # Deliberately narrow comparison, not the production parser. Only
            # run after analyze.py has validated the same evidence hashes.
            rows = [json.loads(line) for line in (args.evidence / "transfer.jsonl")
                    .read_text(encoding="utf-8").splitlines()]
            rows = [row for row in rows if row["user"] == args.user
                    and row["destination_zone"] == "external"]
            unique = {(r["source"], r["event_id"]): r for r in rows}
            for label, records in (("physical_username_only", rows), ("deduplicated_username_only", list(unique.values()))):
                print("%s events=%d known_bytes=%d unknown_events=%d" % (
                    label, len(records), sum(r["bytes_sent"] for r in records if r["bytes_sent"] is not None),
                    sum(r["bytes_sent"] is None for r in records)))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
