#!/usr/bin/env python3
"""Validate case2/v1, deduplicate exact event identities, and correlate sessions.

Only local JSONL is read. This is a teaching parser, not a vendor parser or an
intrusion/exfiltration detector. Python 3.9+, standard library only.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

NAMES = ("auth.jsonl", "file.jsonl", "transfer.jsonl")
COMMON = {"schema", "source", "event_id", "event_time", "realm", "user", "host", "session_id"}
EXTRA = {
    "auth.jsonl": {"action", "outcome", "client_ip"},
    "file.jsonl": {"action", "path", "outcome", "bytes_returned"},
    "transfer.jsonl": {"transfer_id", "state", "destination_zone", "destination", "destination_ip",
                       "declared_bytes", "bytes_sent", "artifact"},
}


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def parse_time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})", value):
        raise ValueError("event_time requires seconds and an explicit offset")
    if not value.endswith("Z"):
        offset = value[-6:]
        if offset == "-00:00" or int(offset[1:3]) > 23 or int(offset[4:6]) > 59:
            raise ValueError("unsupported/unknown UTC offset")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def utc(value):
    return value.isoformat().replace("+00:00", "Z")


def positive_int(value):
    return type(value) is int and 0 <= value <= 2 ** 53 - 1


def validate(event, name):
    if type(event) is not dict or set(event) != COMMON | EXTRA[name]:
        raise ValueError("object fields do not match " + name)
    category = name.split(".")[0]
    if event["schema"] != "case2/v1" or event["source"] != "case2-" + category:
        raise ValueError("unsupported schema/source")
    for key in ("event_id", "realm", "user", "host", "session_id"):
        if not isinstance(event[key], str) or len(event[key]) > 96 or (
                not event[key] and key != "session_id"):
            raise ValueError("invalid identifier: " + key)
        if not re.fullmatch(r"[A-Za-z0-9_.-]*", event[key]):
            raise ValueError("invalid identifier characters: " + key)
    parse_time(event["event_time"])
    if name == "auth.jsonl":
        pair = (event["action"], event["outcome"])
        if pair not in (("login", "denied"), ("session_start", "allowed"), ("session_end", "closed")):
            raise ValueError("invalid auth action/outcome")
        if (pair == ("login", "denied")) != (event["session_id"] == ""):
            raise ValueError("denied login has no session; session events require an ID")
        if not isinstance(event["client_ip"], str):
            raise ValueError("client_ip must be a string")
        ipaddress.ip_address(event["client_ip"])
    elif name == "file.jsonl":
        if event["action"] != "read" or event["outcome"] not in ("allowed", "denied"):
            raise ValueError("invalid file action/outcome")
        if not isinstance(event["path"], str) or not event["path"].startswith("/") or len(event["path"]) > 1024:
            raise ValueError("invalid logged path")
        if not positive_int(event["bytes_returned"]):
            raise ValueError("invalid bytes_returned")
        if event["outcome"] == "denied" and event["bytes_returned"] != 0:
            raise ValueError("denied read must report zero returned bytes")
    else:
        if event["state"] not in ("completed", "blocked", "interrupted", "queued"):
            raise ValueError("invalid transfer state")
        if event["destination_zone"] not in ("internal", "external"):
            raise ValueError("invalid declared destination zone")
        for key in ("transfer_id", "destination", "artifact"):
            if not isinstance(event[key], str) or not event[key] or len(event[key]) > 1024:
                raise ValueError("invalid transfer text field: " + key)
        if not isinstance(event["destination_ip"], str):
            raise ValueError("destination_ip must be a string")
        ipaddress.ip_address(event["destination_ip"])
        size, sent = event["declared_bytes"], event["bytes_sent"]
        if not positive_int(size) or (sent is not None and not positive_int(sent)):
            raise ValueError("invalid transfer byte count")
        if event["state"] == "queued":
            if sent is not None:
                raise ValueError("queued transfer requires bytes_sent=null")
        elif sent is None or sent > size:
            raise ValueError("known bytes_sent must be within declared_bytes")
        elif event["state"] == "blocked" and sent != 0:
            raise ValueError("blocked transfer must report zero bytes_sent")
        elif event["state"] == "completed" and sent != size:
            raise ValueError("completed transfer requires bytes_sent=declared_bytes")
    if name != "auth.jsonl" and not event["session_id"]:
        raise ValueError("file/transfer event requires a session ID")


def read_evidence(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("evidence must be a real directory")
    if sorted(p.name for p in directory.iterdir()) != sorted(NAMES):
        raise ValueError("evidence must contain exactly the three documented JSONL files")
    events, inventory, duplicate_rows = [], {}, []
    seen = {}
    transfer_ids = set()
    for name in NAMES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("input is not a small regular file: " + name)
        data = path.read_bytes()
        lines = data.splitlines()
        if not lines or len(lines) > 100000:
            raise ValueError("empty/oversized event file: " + name)
        inventory[name] = {"bytes": len(data), "lines": len(lines),
                           "sha256": hashlib.sha256(data).hexdigest()}
        for number, line in enumerate(lines, 1):
            ref = "%s:%d" % (name, number)
            try:
                if not line or len(line) > 65536:
                    raise ValueError("empty/oversized line")
                event = json.loads(line.decode("utf-8"), object_pairs_hook=unique_keys,
                                   parse_constant=reject_constant)
                validate(event, name)
            except (ValueError, TypeError, UnicodeError) as exc:
                raise ValueError(ref + ": " + str(exc)) from exc
            key = (event["source"], event["event_id"])
            if key in seen:
                old = seen[key]
                if old["event"] != event:
                    raise ValueError(ref + ": conflicting duplicate event identity")
                old["refs"].append(ref)
                duplicate_rows.append({"ref": ref, "canonical_ref": old["refs"][0]})
            else:
                if name == "transfer.jsonl":
                    if event["transfer_id"] in transfer_ids:
                        raise ValueError(ref + ": repeated transfer_id requires a state-history parser")
                    transfer_ids.add(event["transfer_id"])
                item = {"event": event, "refs": [ref], "utc": utc(parse_time(event["event_time"]))}
                seen[key] = item
                events.append(item)
    return events, inventory, duplicate_rows


def key_for(event):
    return tuple(event[k] for k in ("realm", "user", "host", "session_id"))


def session_windows(events):
    by_key = defaultdict(list)
    for item in events:
        event = item["event"]
        if event["source"] == "case2-auth" and event["action"] != "login":
            by_key[key_for(event)].append(item)
    windows = []
    for key, items in sorted(by_key.items()):
        opened = None
        for item in sorted(items, key=lambda x: (x["utc"], x["refs"][0])):
            if item["event"]["action"] == "session_start":
                if opened is not None:
                    raise ValueError(item["refs"][0] + ": overlapping session starts")
                opened = {"instance": item["refs"][0], "key": list(key), "start": item["utc"],
                          "end": None, "start_refs": item["refs"], "end_refs": []}
            else:
                if opened is None or item["utc"] <= opened["start"]:
                    raise ValueError(item["refs"][0] + ": unmatched/nonpositive session end")
                opened["end"] = item["utc"]
                opened["end_refs"] = item["refs"]
                windows.append(opened)
                opened = None
        if opened is not None:
            windows.append(opened)
    return sorted(windows, key=lambda x: (x["start"], x["instance"]))


def compute(events, inventory, duplicate_rows):
    windows = session_windows(events)
    groups = {window["instance"]: [] for window in windows}
    links = []
    for item in events:
        event = item["event"]
        if event["source"] == "case2-auth":
            continue
        key = key_for(event)
        same_key = [w for w in windows if tuple(w["key"]) == key]
        matches = [w for w in same_key if w["start"] <= item["utc"]
                   and (w["end"] is None or item["utc"] < w["end"])]
        if len(matches) > 1:
            raise ValueError("ambiguous session window")
        instance = matches[0]["instance"] if matches else None
        links.append({"ref": item["refs"][0], "all_refs": item["refs"], "utc": item["utc"],
                      "instance": instance, "reason": "matched" if matches else
                      ("outside_session_window" if same_key else "no_matching_session_key")})
        if instance:
            groups[instance].append(item)
    for window in windows:
        items = groups[window["instance"]]
        reads = [i for i in items if i["event"]["source"] == "case2-file"]
        transfers = [i for i in items if i["event"]["source"] == "case2-transfer"]
        external = [i for i in transfers if i["event"]["destination_zone"] == "external"]
        allowed = [i for i in reads if i["event"]["outcome"] == "allowed"]
        window.update({
            "file_allowed": len(allowed), "file_denied": len(reads) - len(allowed),
            "allowed_unique_paths": len({i["event"]["path"] for i in allowed}),
            "returned_bytes_sum": sum(i["event"]["bytes_returned"] for i in allowed),
            "file_refs": [i["refs"][0] for i in reads],
            "transfer_refs": [i["refs"][0] for i in transfers],
            "external_states": dict(sorted(Counter(i["event"]["state"] for i in external).items())),
            "external_known_sent_bytes": sum(i["event"]["bytes_sent"] for i in external
                                              if i["event"]["bytes_sent"] is not None),
            "external_completed_sent_bytes": sum(i["event"]["bytes_sent"] for i in external
                                                  if i["event"]["state"] == "completed"),
            "external_unknown_byte_events": sum(i["event"]["bytes_sent"] is None for i in external),
            "internal_transfer_events": len(transfers) - len(external),
        })
    categories = Counter(i["event"]["source"] for i in events)
    summary = {
        "schema": "case2-analysis/v1", "input_files": inventory,
        "physical_rows": sum(v["lines"] for v in inventory.values()),
        "unique_events": len(events), "duplicate_rows": len(duplicate_rows),
        "unique_by_source": dict(sorted(categories.items())),
        "duplicates": duplicate_rows, "sessions": windows,
        "unlinked": [x for x in links if x["instance"] is None],
        "open_session_windows": sum(w["end"] is None for w in windows),
        "claim_limits": {
            "real_actor_identity": "not_established",
            "account_compromise": "not_established",
            "external_recipient_possession": "not_established",
            "unique_content_exfiltrated_bytes": None,
            "clock_accuracy": "not_independently_measured",
        },
    }
    timeline = sorted(events, key=lambda x: (x["utc"], x["refs"][0]))
    return summary, timeline, links


def analyze(evidence, out):
    evidence, out = Path(evidence).expanduser(), Path(out).expanduser().absolute()
    if out.exists() or out.is_symlink():
        raise ValueError("output already exists; choose a new directory")
    if not out.parent.is_dir() or out.parent.is_symlink():
        raise ValueError("output parent must be an existing real directory")
    if evidence.resolve() in out.resolve().parents:
        raise ValueError("analysis output cannot be inside evidence")
    events, inventory, duplicates = read_evidence(evidence)
    summary, timeline, links = compute(events, inventory, duplicates)
    # Abort if the second read differs. This cannot detect a change that was
    # reverted between reads, or one occurring after the second check.
    for name, expected in inventory.items():
        if hashlib.sha256((evidence / name).read_bytes()).hexdigest() != expected["sha256"]:
            raise ValueError("input changed during analysis: " + name)
    out.mkdir(mode=0o700)
    for name, value in (("summary.json", summary), ("claim-checks.json", summary["claim_limits"])):
        with (out / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    for name, values in (("timeline.jsonl", timeline), ("links.jsonl", links)):
        with (out / name).open("x", encoding="utf-8") as stream:
            for value in values:
                stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    print(json.dumps({k: summary[k] for k in ("physical_rows", "unique_events", "duplicate_rows",
                                             "open_session_windows")}, sort_keys=True))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        analyze(args.evidence, args.out)
    except (OSError, ValueError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
