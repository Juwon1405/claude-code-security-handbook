#!/usr/bin/env python3
"""응답 상태, 판정 스키마와 인용 원문의 일치를 검사한다."""
import json
from pathlib import Path
import sys

import jsonschema


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("중복된 JSON 키가 있습니다.")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("JSON 표준에 없는 숫자 상수가 있습니다.")


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object,
                         parse_constant=reject_constant)


def validate(response_path, schema_path, evidence_path):
    reply = load_json(response_path)
    if not isinstance(reply, dict):
        raise ValueError("응답이 단일 JSON 객체가 아닙니다.")
    if (reply.get("type") != "result"
            or reply.get("is_error") is not False
            or reply.get("subtype") != "success"):
        raise ValueError("응답이 정상 실행을 보고하지 않습니다.")
    if "structured_output" not in reply:
        raise ValueError("structured_output이 없습니다.")
    schema = load_json(schema_path)
    jsonschema.Draft202012Validator.check_schema(schema)
    verdict = reply["structured_output"]
    if not isinstance(verdict, dict):
        raise ValueError("판정이 JSON 객체가 아닙니다.")
    jsonschema.Draft202012Validator(schema).validate(verdict)
    evidence = verdict.get("evidence_line")
    if (not isinstance(evidence, str) or not evidence
            or any(c in evidence for c in "\r\n\x00")):
        raise ValueError("인용은 CR·LF·NUL이 없는 비어 있지 않은 한 줄이어야 합니다.")
    with Path(evidence_path).open(encoding="utf-8", newline="") as stream:
        for number, line in enumerate(stream, 1):
            if line.endswith("\r\n"):
                line = line[:-2]
            elif line.endswith(("\r", "\n")):
                line = line[:-1]
            if evidence == line:
                return number
    raise ValueError("인용과 정확히 일치하는 원문 행이 없습니다.")


def main():
    if len(sys.argv) != 4:
        print("사용법: validate_verdict.py 응답.json 스키마.json 원본.log",
              file=sys.stderr)
        return 1
    try:
        number = validate(*sys.argv[1:])
    except (OSError, UnicodeError, ValueError,
            jsonschema.ValidationError, jsonschema.SchemaError) as error:
        print(f"검사 실패: {error}", file=sys.stderr)
        return 1
    print(f"{sys.argv[3]}:{number}: 인용 원문 일치")
    return 0


if __name__ == "__main__":
    sys.exit(main())
