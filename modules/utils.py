from __future__ import annotations

import json
import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any


def run_command(command: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or "Command timed out"


def read_plist(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return plistlib.load(f)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def find_tool(name: str) -> str | None:
    return shutil.which(name)
