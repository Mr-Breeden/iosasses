from __future__ import annotations

from typing import Any


def get_bundle_metadata(plist: dict[str, Any]) -> dict[str, Any]:
    return {
        "bundle_id": plist.get("CFBundleIdentifier"),
        "display_name": plist.get("CFBundleDisplayName") or plist.get("CFBundleName"),
        "bundle_name": plist.get("CFBundleName"),
        "version": plist.get("CFBundleShortVersionString"),
        "build": plist.get("CFBundleVersion"),
        "minimum_os": plist.get("MinimumOSVersion"),
        "executable": plist.get("CFBundleExecutable"),
    }


def get_url_schemes(plist: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for entry in plist.get("CFBundleURLTypes", []) or []:
        results.append({
            "name": entry.get("CFBundleURLName", ""),
            "schemes": entry.get("CFBundleURLSchemes", []) or [],
            "role": entry.get("CFBundleTypeRole", ""),
        })
    return results


def get_associated_domains(plist: dict[str, Any], entitlements: dict[str, Any] | None = None) -> list[str]:
    domains = []
    if entitlements:
        domains.extend(entitlements.get("com.apple.developer.associated-domains", []) or [])
    domains.extend(plist.get("com.apple.developer.associated-domains", []) or [])
    return sorted(set(domains))


def review_plist(plist: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    if plist.get("UIFileSharingEnabled") is True:
        findings.append({
            "severity": "Medium",
            "title": "iTunes File Sharing Enabled",
            "evidence": "UIFileSharingEnabled=true",
            "recommendation": "Disable file sharing unless users require direct access to app documents.",
        })
    if plist.get("LSSupportsOpeningDocumentsInPlace") is True:
        findings.append({
            "severity": "Low",
            "title": "Documents May Open In Place",
            "evidence": "LSSupportsOpeningDocumentsInPlace=true",
            "recommendation": "Confirm sensitive documents are not exposed to other document-provider workflows.",
        })
    return findings
