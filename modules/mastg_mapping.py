from __future__ import annotations
from pathlib import Path
from .utils import write_text

MASTG_ROWS = [
    ("App Architecture / Info.plist Review", "Automated + Manual", "inventory/info_plist_review.txt, assessment_metadata.json", "Bundle metadata, URL schemes, Universal Links, and platform configuration are extracted from the IPA."),
    ("Platform Interaction", "Automated + Manual", "inventory/url_schemes.txt, test_cases.txt", "Custom URL schemes and Associated Domains are discovered automatically; abuse testing remains manual."),
    ("Network Communication", "Automated + Manual", "inventory/ats_review.txt, test_cases.txt", "ATS settings are reviewed automatically. Proxy/API testing is tester-driven. Certificate pinning is context only, not a finding."),
    ("Data Storage and Privacy", "Guided Manual", "test_cases.txt, storage_review/keychain_review.txt, storage_review/local_storage_review.txt, storage_review/application_container_review.txt", "The tool generates local storage and Keychain review guidance. Direct extraction and validation is performed by the tester."),
    ("Authentication and Session Handling", "Guided Manual", "test_cases.txt, static_triage/potential_secrets_or_credentials.txt", "The tool supports authentication testing through URL handling, logging, network review, and runtime instrumentation guidance."),
    ("Cryptography", "Static Triage + Manual", "static_triage/cryptography_indicators.txt", "Static indicators are collected from binary strings and resources. Correctness and exploitability require analyst review."),
    ("WebView / In-App Browser", "Static Triage + Manual", "static_triage/webview_indicators.txt, test_cases.txt", "WebView-related strings and APIs are triaged; URL loading, JavaScript bridge behavior, and session exposure are manually validated."),
    ("Code Quality / Secrets", "Static Triage", "static_triage/potential_secrets_or_credentials.txt", "Potential secrets are identified from static strings/resources. False positives must be manually reviewed."),
    ("Reverse Engineering and Runtime Analysis", "Guided Manual", "inventory/binary_metadata.txt, test_cases.txt", "Binary metadata and Frida/Objection/r2frida/LLDB guidance are generated. Runtime validation remains tester-driven."),
    ("Anti-Tampering / Resilience", "Static Triage + Manual", "static_triage/jailbreak_detection_indicators.txt, test_cases.txt", "Jailbreak/root detection indicators are identified; bypass and tampering validation are manual."),
    ("Logging and Error Handling", "Static Triage + Manual", "static_triage/logging_indicators.txt, test_cases.txt", "Logging indicators are collected and device/simulator log review commands are generated."),
    ("Dependencies / Third-Party Components", "Limited", "inventory/binary_metadata.txt", "Linked libraries are collected, but full SBOM/dependency vulnerability review is not yet implemented."),
    ("Memory Analysis", "Guided Manual", "test_cases.txt, memory_analysis/memory_analysis_workflow.txt, memory_analysis/memory_evidence_checklist.txt", "Memory analysis workflows and evidence guidance are generated. Runtime validation remains tester-driven."),
    ("Biometric Controls", "Guided Manual", "test_cases.txt", "Biometric enforcement, session expiration, and re-authentication test cases are generated. Runtime validation remains tester-driven."),
]

def write_mastg_mapping(path: Path) -> None:
    lines = [
        "iOSAssess MASTG Coverage Matrix",
        "=" * 80,
        "",
        "Purpose",
        "-" * 80,
        "This matrix maps iOSAssess output artifacts to common OWASP MASTG-style mobile testing areas.",
        "Coverage labels describe whether the tool automates the activity, guides the tester manually,",
        "or currently provides limited/planned support.",
        "",
        "Coverage Labels",
        "-" * 80,
        "Automated: The tool directly extracts or evaluates the item.",
        "Static Triage: The tool identifies patterns that require manual validation.",
        "Guided Manual: The tool generates tester instructions and evidence guidance.",
        "Limited: Basic support exists but does not provide full assessment coverage.",
        "Planned: Not currently implemented beyond general guidance or roadmap notes.",
        "",
        "Coverage Matrix",
        "-" * 80,
        "",
    ]
    for idx, (area, coverage, artifacts, notes) in enumerate(MASTG_ROWS, 1):
        lines.append(f"[MASTG-{idx:03d}] {area}")
        lines.append(f"Coverage: {coverage}")
        lines.append(f"Artifacts: {artifacts}")
        lines.append(f"Notes: {notes}")
        lines.append("")
    write_text(path, "\n".join(lines).rstrip() + "\n")

def write_evidence_checklist(path: Path) -> None:
    lines = [
        "iOSAssess Evidence Collection Checklist",
        "=" * 80,
        "",
        "Use this checklist while validating test cases and preparing report evidence.",
        "",
        "General Evidence",
        "-" * 80,
        "- Assessment name and timestamp",
        "- IPA filename and hash if collected externally",
        "- Bundle identifier",
        "- Application version and build number",
        "- Testing environment: physical device or simulator",
        "- Device model and iOS version when relevant",
        "",
        "Static Analysis Evidence",
        "-" * 80,
        "- Relevant Info.plist keys",
        "- Entitlements output",
        "- ATS configuration entries",
        "- URL schemes and Associated Domains",
        "- Binary metadata or linked framework evidence",
        "- Static triage report and matched string/pattern",
        "",
        "Runtime Evidence",
        "-" * 80,
        "- Test case ID",
        "- Commands or manual steps performed",
        "- Screenshot or screen recording where appropriate",
        "- Device/simulator log output",
        "- Proxy request/response evidence",
        "- Frida/Objection/r2frida/LLDB command output when used",
        "",
        "Finding Validation Evidence",
        "-" * 80,
        "- Expected result",
        "- Actual result",
        "- Impact explanation",
        "- Affected user/data/functionality",
        "- Reproduction steps",
        "- Remediation recommendation",
        "",
    ]
    write_text(path, "\n".join(lines).rstrip() + "\n")
