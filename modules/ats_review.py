from __future__ import annotations

from typing import Any


def review_ats(plist: dict[str, Any]) -> tuple[list[dict[str, str]], str]:
    ats = plist.get("NSAppTransportSecurity", {}) or {}
    findings = []
    lines = ["App Transport Security Review", "=" * 80, ""]
    if not ats:
        lines.append("NSAppTransportSecurity not present. Default ATS protections may apply.")
        return findings, "\n".join(lines) + "\n"

    lines.append("NSAppTransportSecurity present.")
    lines.append("")
    for key, value in ats.items():
        lines.append(f"{key}: {value}")

    if ats.get("NSAllowsArbitraryLoads") is True:
        findings.append({
            "severity": "High",
            "title": "ATS Allows Arbitrary Loads",
            "evidence": "NSAllowsArbitraryLoads=true",
            "recommendation": "Disable arbitrary loads and define limited domain exceptions only where required.",
        })

    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        findings.append({
            "severity": "Medium",
            "title": "ATS Allows Arbitrary Loads In Web Content",
            "evidence": "NSAllowsArbitraryLoadsInWebContent=true",
            "recommendation": "Review WebView traffic requirements and restrict insecure content where possible.",
        })

    exceptions = ats.get("NSExceptionDomains", {}) or {}
    for domain, config in exceptions.items():
        if isinstance(config, dict) and config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            findings.append({
                "severity": "Medium",
                "title": f"ATS Domain Exception Allows Insecure HTTP: {domain}",
                "evidence": f"{domain}: NSExceptionAllowsInsecureHTTPLoads=true",
                "recommendation": "Use HTTPS for all domain traffic unless a documented business requirement exists.",
            })
    return findings, "\n".join(lines) + "\n"
