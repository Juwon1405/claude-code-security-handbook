#!/usr/bin/env python3
"""19장의 오프라인 오류 분류 실습. 모델이나 네트워크를 호출하지 않는다."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

LIMIT = 1024 * 1024
ATTEMPTS = tuple("attempt-%03d" % n for n in range(1, 7))
EVIDENCE = (
    '{"id":"R01","src":"203.0.113.41","action":"login",'
    '"outcome":"denied"}\n'
    '{"id":"R02","src":"203.0.113.41","action":"login",'
    '"outcome":"allowed"}\n'
).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       indent=2) + "\n").encode("utf-8")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("중복 JSON 키")
        result[key] = value
    return result


def read_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("일반 파일이 아닌 입력")
    if path.stat().st_size > LIMIT:
        raise ValueError("실습 입력 크기 제한 초과")
    return path.read_bytes()


def read_json(path):
    def reject_constant(value):
        raise ValueError("JSON에 허용되지 않는 숫자: " + value)

    return json.loads(read_bytes(path).decode("utf-8"),
                      object_pairs_hook=no_duplicates,
                      parse_constant=reject_constant)


def put(path, value):
    data = value if isinstance(value, bytes) else json_bytes(value)
    with path.open("xb") as stream:
        stream.write(data)


def new_directory(path):
    # mkdir(exist_ok=False)로 기존 파일·폴더·심볼릭 링크를 거부한다.
    path.mkdir(parents=False, exist_ok=False)


def make_demo(root):
    new_directory(root)
    (root / "evidence").mkdir()
    (root / "attempts").mkdir()
    put(root / "evidence" / "access.jsonl", EVIDENCE)
    put(root / "input-manifest.json", {
        "format": "recovery-demo-v1", "source": "access.jsonl",
        "sha256": digest(EVIDENCE), "bytes": len(EVIDENCE),
    })
    good = {
        "is_error": False,
        "structured_output": {
            "line": 2, "quote": EVIDENCE.decode().splitlines()[1],
            "statement": "R02에는 접속 허용이 기록되어 있다.",
        },
    }
    for number, attempt in enumerate(ATTEMPTS, 1):
        folder = root / "attempts" / attempt
        folder.mkdir()
        record = {"attempt_id": attempt, "finished": number != 6,
                  "exit_code": 1 if number == 2 else 0,
                  "source_sha256": digest(EVIDENCE)}
        if number == 6:
            record["exit_code"] = None
        put(folder / "run.json", record)
        if number == 2:
            put(folder / "stderr.txt", b"simulated process failure\n")
        elif number == 3:
            put(folder / "response.json", {"is_error": True,
                "error": "simulated turn limit"})
        elif number == 4:
            put(folder / "response.json", b'{"is_error": false,\n')
        elif number == 5:
            changed = json.loads(json.dumps(good))
            changed["structured_output"]["quote"] = "R99: no such line"
            put(folder / "response.json", changed)
        elif number == 1:
            put(folder / "response.json", good)
    return {"created": True, "attempts": len(ATTEMPTS),
            "model_calls": 0, "source_sha256": digest(EVIDENCE)}


def validate_root(root):
    for path in (root, root / "evidence", root / "attempts"):
        if path.is_symlink() or not path.is_dir():
            raise ValueError("실습 폴더가 없거나 심볼릭 링크이다")
    manifest = read_json(root / "input-manifest.json")
    if not isinstance(manifest, dict):
        raise ValueError("매니페스트 형식 오류")
    if (manifest.get("format") != "recovery-demo-v1"
            or manifest.get("source") != "access.jsonl"):
        raise ValueError("지원하지 않는 매니페스트")
    evidence = read_bytes(root / "evidence" / "access.jsonl")
    if (type(manifest.get("bytes")) is not int
            or manifest["bytes"] != len(evidence)
            or manifest.get("sha256") != digest(evidence)):
        raise ValueError("원문 무결성 불일치")
    lines = evidence.decode("utf-8").splitlines()
    for line in lines:
        if not isinstance(json.loads(line), dict):
            raise ValueError("원문 레코드 형식 오류")
    return digest(evidence), lines


def classify(folder, source_sha, lines):
    if folder.is_symlink() or not folder.is_dir():
        return "invalid_record"
    try:
        record = read_json(folder / "run.json")
        if (not isinstance(record, dict)
                or record.get("attempt_id") != folder.name
                or type(record.get("finished")) is not bool):
            return "invalid_record"
        if record.get("source_sha256") != source_sha:
            return "input_mismatch"
        if not record["finished"]:
            return "incomplete"
        if type(record.get("exit_code")) is not int:
            return "invalid_record"
        if record["exit_code"] != 0:
            return "process_failed"
        response_path = folder / "response.json"
        if not response_path.exists() and not response_path.is_symlink():
            return "missing_response"
        try:
            response = read_json(response_path)
        except (ValueError, UnicodeError):
            return "invalid_json"
        if not isinstance(response, dict):
            return "invalid_response"
        if type(response.get("is_error")) is not bool:
            return "invalid_response"
        if response["is_error"]:
            return "model_error"
        value = response.get("structured_output")
        if (not isinstance(value, dict)
                or set(value) != {"line", "quote", "statement"}
                or type(value["line"]) is not int
                or not isinstance(value["quote"], str)
                or not isinstance(value["statement"], str)
                or not value["statement"].strip()):
            return "invalid_response"
        number = value["line"]
        if not 1 <= number <= len(lines):
            return "quote_mismatch"
        if value["quote"] != lines[number - 1]:
            return "quote_mismatch"
        return "ready_for_review"
    except (ValueError, UnicodeError, OSError):
        return "invalid_record"


def audit(root):
    source_sha, lines = validate_root(root)
    folders = sorted((root / "attempts").iterdir())
    if {p.name for p in folders} != set(ATTEMPTS):
        raise ValueError("실습 실행 항목 목록 불일치")
    rows = [{"attempt_id": folder.name,
             "state": classify(folder, source_sha, lines)}
            for folder in folders]
    return {"format": "recovery-audit-v1", "model_calls": 0,
            "source_sha256": source_sha, "attempts": rows,
            "ready_for_review": sum(
                item["state"] == "ready_for_review" for item in rows),
            "total": len(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["make-demo", "audit"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        result = (make_demo(args.directory) if args.operation == "make-demo"
                  else audit(args.directory))
    except (ValueError, UnicodeError, OSError) as exc:
        # 실제 입력의 내용이나 인증 정보는 오류 메시지에 포함하지 않는다.
        print("중단: %s" % type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
