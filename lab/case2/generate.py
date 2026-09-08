#!/usr/bin/env python3
"""Write the fixed, fictitious CASE-0907 teaching data to a new directory.

Python 3.9+, standard library only. No network, authentication or model calls.
The destination must not exist, including an existing empty directory.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys


def stamp(clock, local=False):
    value = datetime.fromisoformat("2026-09-07T" + clock + "+00:00")
    if local:
        return value.astimezone(timezone(timedelta(hours=9))).isoformat()
    return value.isoformat().replace("+00:00", "Z")


def rows():
    auth, files, transfers = [], [], []
    sessions = [
        ("staff", "account-a", "work-a", "S-100", "09:00:00", "09:30:00", "192.0.2.21"),
        ("staff", "account-a", "work-b", "S-200", "09:10:00", "09:25:00", "203.0.113.45"),
        ("service", "account-a", "build-a", "S-200", "09:05:00", "09:35:00", "192.0.2.30"),
        ("staff", "account-a", "work-b", "S-200", "10:10:00", "10:20:00", "198.51.100.61"),
        ("staff", "account-b", "work-c", "S-300", "09:07:00", "09:27:00", "192.0.2.22"),
    ]

    def common(category, event_id, clock, session, local=False):
        realm, user, host, sid = session[:4]
        return {"schema": "case2/v1", "source": "case2-" + category,
                "event_id": event_id, "event_time": stamp(clock, local),
                "realm": realm, "user": user, "host": host, "session_id": sid}

    for i, session in enumerate(sessions):
        for suffix, clock, action, outcome in (
                ("s", session[4], "session_start", "allowed"),
                ("e", session[5], "session_end", "closed")):
            row = common("auth", "a%d%s" % (i + 1, suffix), clock, session)
            row.update(action=action, outcome=outcome, client_ip=session[6])
            auth.append(row)
    for i in range(6):
        session = sessions[1] if i < 5 else sessions[0]
        row = common("auth", "deny-%d" % (i + 1),
                     "09:08:%02d" % i if i < 5 else "08:59:50", session)
        row.update(session_id="", action="login", outcome="denied", client_ip=session[6])
        auth.append(row)
    auth.extend([dict(auth[2]), dict(auth[10])])

    def read(session, clock, path, size, allowed=True, local=False):
        row = common("file", "f%03d" % (len(files) + 1), clock, session, local)
        row.update(action="read", path=path, outcome="allowed" if allowed else "denied",
                   bytes_returned=size)
        files.append(row)

    for i, size in enumerate((1024, 2048, 1024, 4096, 2048, 4096)):
        read(sessions[0], "09:0%d:00" % (i + 1),
             ("/docs/guide.txt", "/docs/schedule.csv", "/docs/catalog.csv")[i % 3], size)
    read(sessions[0], "09:09:00", "/restricted/payroll.csv", 0, False)
    for clock, path, size in (
        ("09:12:00", "/finance/budget.csv", 32768),
        ("09:13:00", "/finance/prices.csv", 65536),
        ("09:14:00", "/projects/plan.txt", 8192),
        ("09:15:00", "/finance/budget.csv", 32768)):
        read(sessions[1], clock, path, size, local=True)
    read(sessions[1], "09:16:00", "/restricted/payroll.csv", 0, False, True)
    for i, size in enumerate((1048576, 2097152, 4096)):
        read(sessions[2], "09:1%d:30" % i, "/maintenance/item-%d.bin" % i, size)
    read(sessions[3], "10:12:00", "/docs/notes.txt", 512)
    read(sessions[1], "09:09:30", "/docs/legacy.txt", 128)
    read(sessions[1], "09:26:00", "/docs/late.txt", 256)
    read(("staff", "account-a", "work-z", "S-200"), "09:14:30", "/docs/orphan.txt", 64)
    read(sessions[4], "09:12:30", "/docs/reference.txt", 8192)
    read(sessions[4], "09:13:30", "/docs/reference.txt", 8192)
    files.extend([dict(files[7]), dict(files[0])])

    def transfer(session, clock, tid, state, zone, size, sent, artifact):
        row = common("transfer", tid, clock, session)
        row.update(transfer_id=tid, state=state, destination_zone=zone,
                   destination="upload.example.com" if zone == "external" else "archive.example.net",
                   destination_ip="198.51.100.90" if zone == "external" else "192.0.2.80",
                   declared_bytes=size, bytes_sent=sent, artifact=artifact)
        transfers.append(row)

    transfer(sessions[0], "09:18:00", "t001", "completed", "internal", 14336, 14336, "docs.zip")
    transfer(sessions[1], "09:17:00", "t002", "completed", "external", 65536, 65536, "export-01.zip")
    transfer(sessions[1], "09:18:00", "t003", "completed", "external", 65536, 65536, "export-01.zip")
    transfer(sessions[1], "09:19:00", "t004", "blocked", "external", 65536, 0, "export-02.zip")
    transfer(sessions[1], "09:20:00", "t005", "interrupted", "external", 32768, 12288, "export-03.zip")
    transfer(sessions[1], "09:21:00", "t006", "queued", "external", 8192, None, "export-04.zip")
    transfer(sessions[1], "09:22:00", "t007", "completed", "internal", 32768, 32768, "internal-copy.zip")
    transfer(sessions[2], "09:23:00", "t008", "completed", "external", 524288, 524288, "backup.zip")
    transfer(sessions[3], "10:13:00", "t009", "completed", "external", 1024, 1024, "notes.zip")
    transfer(sessions[4], "09:24:00", "t010", "completed", "external", 4096, 4096, "reference.zip")
    transfer(sessions[1], "09:27:00", "t011", "completed", "external", 2048, 2048, "late.zip")
    transfers.append(dict(transfers[1]))
    return {"auth.jsonl": auth, "file.jsonl": files, "transfer.jsonl": transfers}


def generate(out):
    out = out.expanduser().absolute()
    # lexists equivalent also catches a broken symlink. Never reuse a folder.
    if out.exists() or out.is_symlink():
        raise ValueError("output already exists; choose a new directory")
    if not out.parent.is_dir() or out.parent.is_symlink():
        raise ValueError("output parent must be an existing real directory")
    out.mkdir(mode=0o700)
    evidence = out / "evidence"
    evidence.mkdir(mode=0o700)
    receipt = {"case": "CASE-0907", "synthetic": True, "schema": "case2/v1", "files": {}}
    for name, events in rows().items():
        data = "".join(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                       + "\n" for event in events).encode("utf-8")
        with (evidence / name).open("xb") as stream:
            stream.write(data)
        receipt["files"][name] = {"bytes": len(data), "lines": len(events),
                                  "sha256": hashlib.sha256(data).hexdigest()}
    with (out / "receipt.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"case": "CASE-0907", "files": {k: v["lines"]
          for k, v in receipt["files"].items()}, "synthetic": True}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        generate(args.out)
    except (OSError, ValueError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
