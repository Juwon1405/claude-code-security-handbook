#!/usr/bin/env python3
"""Read-only, offline preparation inventory; never certifies a lab as passed.

Only explicitly named, regular lab files are read. No credential/configuration
file, process, network endpoint, or recursive directory tree is inspected.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys

MAX_BYTES = 2 * 1024 * 1024
EVIDENCE = (
    "access.log", "auth.log", "winlog.jsonl", "conn.log", "dns.log",
    "processes.csv", "suspicious.ps1", "iocs_messy.txt",
)
SCRIPTS = ("gen_lab_data.py", "bin/guard.sh", "bin/audit.sh")
TOOLS = ("bash", "python3", "jq", "sha256sum", "unzip", "bwrap", "socat", "claude")


def regular_local_file(root: Path, relative: str) -> tuple[Path | None, str]:
    """Reject links before opening, including any intermediate directory link."""
    path = root
    for part in Path(relative).parts:
        path = path / part
        try:
            item_stat = path.lstat()
        except FileNotFoundError:
            return None, "missing"
        except OSError:
            return None, "unreadable"
        if stat.S_ISLNK(item_stat.st_mode):
            return None, "symlink_not_read"
    if not stat.S_ISREG(item_stat.st_mode):
        return None, "not_regular_file"
    if item_stat.st_size > MAX_BYTES:
        return None, "too_large_not_read"
    return path, "regular_file"


def inspect_script(root: Path, relative: str) -> dict:
    path, status = regular_local_file(root, relative)
    result = {"status": status}
    if path is None:
        return result
    try:
        content = path.read_bytes()
        result.update({
            "crlf_present": b"\r\n" in content,
            "utf8_bom_present": content.startswith(b"\xef\xbb\xbf"),
            "owner_execute_bit": bool(path.stat().st_mode & stat.S_IXUSR),
        })
        content.decode("utf-8")
        result["utf8_decodable"] = True
    except UnicodeDecodeError:
        result["utf8_decodable"] = False
    except OSError:
        result = {"status": "unreadable"}
    return result


def command_state(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        return "not_found_on_path"
    normalized = executable.replace("\\", "/").lower()
    if normalized.endswith(".exe"):
        return "windows_executable_on_path"
    if normalized.startswith("/mnt/"):
        return "mounted_path_candidate"
    return "present_not_executed"


def inspect(root: Path) -> dict:
    # resolve only the caller-selected root; never print it or crawl it.
    root = root.absolute()
    result = {
        "report_kind": "preparation_inventory_only",
        "lab_verification": "not_performed",
        "network_access": "not_attempted",
        "credentials": "not_read",
        "platform_family": platform.system(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "python_virtual_environment": sys.prefix != sys.base_prefix,
        "root_path_disclosed": False,
        "selected_root_under_mnt": str(root).startswith("/mnt/"),
        "commands": {name: command_state(name) for name in TOOLS},
    }
    if hasattr(os, "geteuid"):
        result["running_as_root"] = os.geteuid() == 0
    if root.is_symlink() or not root.is_dir():
        result["selected_root"] = "invalid_or_symlink"
        return result
    result["selected_root"] = "directory"
    result["evidence_files"] = {
        name: regular_local_file(root, "evidence/" + name)[1] for name in EVIDENCE
    }
    result["scripts"] = {name: inspect_script(root, name) for name in SCRIPTS}
    try:
        result["jsonschema_module"] = (
            "discoverable_not_imported" if importlib.util.find_spec("jsonschema")
            else "not_found_in_current_python"
        )
    except (ImportError, ValueError):
        result["jsonschema_module"] = "not_found_in_current_python"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True,
                        help="Prepared synthetic lab directory; never an incident directory")
    args = parser.parse_args()
    result = inspect(args.root)
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    # Zero means inventory completed, never that preparation or labs passed.
    return 2 if result["selected_root"] == "invalid_or_symlink" else 0


if __name__ == "__main__":
    raise SystemExit(main())
