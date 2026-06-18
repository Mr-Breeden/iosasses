from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

from .utils import run_command


def extract_entitlements(app_path: Path) -> tuple[dict[str, Any], str]:
    rc, stdout, stderr = run_command(["codesign", "-d", "--entitlements", ":-", str(app_path)], timeout=30)
    output = stdout or stderr
    if not output:
        return {}, "No entitlements output returned by codesign."
    start = output.find("<?xml")
    if start == -1:
        start = output.find("<plist")
    if start == -1:
        return {}, output
    plist_text = output[start:].encode("utf-8", errors="ignore")
    try:
        return plistlib.loads(plist_text), output
    except Exception:
        return {}, output


def review_entitlements(entitlements: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    if entitlements.get("get-task-allow") is True:
        findings.append({
            "severity": "High",
            "title": "Debug Entitlement Enabled",
            "evidence": "get-task-allow=true",
            "recommendation": "Disable get-task-allow for production builds.",
        })
    if entitlements.get("com.apple.security.application-groups"):
        findings.append({
            "severity": "Info",
            "title": "App Groups Entitlement Present",
            "evidence": ", ".join(entitlements.get("com.apple.security.application-groups", [])),
            "recommendation": "Review shared container usage for sensitive data exposure.",
        })
    if entitlements.get("keychain-access-groups"):
        findings.append({
            "severity": "Info",
            "title": "Keychain Access Groups Present",
            "evidence": ", ".join(entitlements.get("keychain-access-groups", [])),
            "recommendation": "Review whether keychain access groups are required and scoped appropriately.",
        })
    return findings
