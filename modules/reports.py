from __future__ import annotations

from pathlib import Path
from typing import Any
from .utils import write_text, write_json

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def normalize_severity(value: str) -> str:
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "informational": "Info"}
    return mapping.get(str(value).lower(), "Info")


def write_module_status(path: Path, statuses: list[tuple[str, str, str]]) -> None:
    lines = ["iOSAssess Module Status", "=" * 80, ""]
    for name, status, detail in statuses:
        lines.append(f"{name:<30} {status}")
        if detail:
            lines.append(f"  {detail}")
    write_text(path, "\n".join(lines) + "\n")


def write_findings_summary(path: Path, metadata: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[normalize_severity(f.get("severity", "Info"))] += 1
    lines = [
        "iOSAssess Findings Summary", "=" * 80,
        f"iOSAssess Version: {metadata.get('version')}",
        f"IPA Path: {metadata.get('ipa_path')}",
        f"Bundle ID: {metadata.get('bundle_id')}",
        f"Application Name: {metadata.get('display_name')}", "",
        f"Total Findings: {len(findings)}", "",
    ]
    for sev in SEVERITIES:
        lines.append(f"{sev}: {counts[sev]}")
    lines.append("")
    for sev in SEVERITIES:
        items = [f for f in findings if normalize_severity(f.get("severity", "Info")) == sev]
        if not items:
            continue
        lines.append(sev)
        lines.append("-" * len(sev))
        for item in items:
            lines.append(f"- {item.get('title')}")
        lines.append("")
    write_text(path, "\n".join(lines))


def write_findings(path: Path, findings: list[dict[str, Any]]) -> None:
    lines = ["iOSAssess Findings", "=" * 80, ""]
    for idx, f in enumerate(findings, 1):
        lines.append(f"[F-{idx:03d}] {normalize_severity(f.get('severity'))}: {f.get('title')}")
        lines.append("-" * 80)
        lines.append(f"Evidence: {f.get('evidence', '')}")
        lines.append(f"Recommendation: {f.get('recommendation', '')}")
        lines.append("")
    write_text(path, "\n".join(lines))


def write_metadata(path: Path, metadata: dict[str, Any]) -> None:
    write_json(path, metadata)
