from __future__ import annotations

from pathlib import Path
from .utils import run_command


def collect_binary_metadata(binary_path: Path | None) -> str:
    lines = ["Binary Metadata", "=" * 80, ""]
    if not binary_path or not binary_path.exists():
        lines.append("Main executable not found.")
        return "\n".join(lines) + "\n"
    lines.append(f"Binary: {binary_path}")
    lines.append("")
    for label, cmd in [
        ("file", ["file", str(binary_path)]),
        ("otool headers", ["otool", "-hv", str(binary_path)]),
        ("linked libraries", ["otool", "-L", str(binary_path)]),
    ]:
        rc, out, err = run_command(cmd, timeout=30)
        lines.append(f"[{label}]")
        lines.append(out or err or "No output")
        lines.append("")
    return "\n".join(lines) + "\n"
