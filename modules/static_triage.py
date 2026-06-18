from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import run_command, write_text


TRIAGE_RULES = [
    {
        "category": "Potential Secrets or Credentials",
        "risk": "Medium",
        "confidence": "Medium",
        "patterns": [
            "api_key", "apikey", "client_secret", "secret", "password", "passwd",
            "authorization", "bearer", "jwt", "token", "access_token", "refresh_token"
        ],
        "guidance": "Review whether secrets, tokens, credentials, or authorization material are embedded in the app binary or resources.",
    },
    {
        "category": "Jailbreak Detection Indicators",
        "risk": "Medium",
        "confidence": "Medium",
        "patterns": [
            "jailbreak", "cydia", "substrate", "frida", "MobileSubstrate",
            "/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd", "canOpenURL"
        ],
        "guidance": "Review whether jailbreak/root detection is present and whether bypass testing is in scope.",
    },
    {
        "category": "WebView Indicators",
        "risk": "Medium",
        "confidence": "Medium",
        "patterns": [
            "WKWebView", "UIWebView", "loadHTMLString", "loadRequest", "javaScriptEnabled",
            "WKScriptMessageHandler", "addScriptMessageHandler"
        ],
        "guidance": "Review whether WebViews load untrusted content, expose JavaScript bridges, or process attacker-controlled URLs.",
    },
    {
        "category": "Keychain Usage Indicators",
        "risk": "Medium",
        "confidence": "Medium",
        "patterns": [
            "SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete",
            "kSecAttrAccessible", "kSecClassGenericPassword", "Keychain"
        ],
        "guidance": "Review keychain item accessibility classes, access groups, and whether sensitive data is protected appropriately.",
    },
    {
        "category": "Local Storage Indicators",
        "risk": "Medium",
        "confidence": "Medium",
        "patterns": [
            "NSUserDefaults", "UserDefaults", "SQLite", ".sqlite", ".db",
            "NSFileManager", "FileManager", "Library/Caches", "Documents"
        ],
        "guidance": "Review local storage for sensitive data in preferences, caches, databases, documents, and temporary files.",
    },
    {
        "category": "Logging Indicators",
        "risk": "Low",
        "confidence": "Medium",
        "patterns": [
            "NSLog", "print(", "os_log", "OSLog", "debugPrint"
        ],
        "guidance": "Review whether sensitive values are written to device logs during normal app use.",
    },
    {
        "category": "Cryptography Indicators",
        "risk": "Medium",
        "confidence": "Medium",
        "patterns": [
            "CCCrypt", "CommonCrypto", "CryptoKit", "AES", "DES", "3DES", "RC4",
            "MD5", "SHA1", "ECB", "CBC", "kCCOptionECBMode"
        ],
        "guidance": "Review cryptographic usage for deprecated algorithms, insecure modes, hardcoded keys, and missing authentication.",
    },
]


def _safe_filename(value: str) -> str:
    return (
        value.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace(":", "")
        .replace("__", "_")
    ) + ".txt"


def _collect_strings(binary_path: Path | None) -> list[str]:
    if not binary_path or not binary_path.exists():
        return []
    rc, out, err = run_command(["strings", "-a", str(binary_path)], timeout=60)
    if rc != 0:
        return []
    return out.splitlines()


def _search_files(app_path: Path, patterns: list[str], max_hits: int = 50) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    text_exts = {".plist", ".json", ".txt", ".xml", ".html", ".js", ".css", ".strings"}
    for file_path in app_path.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in text_exts:
            continue
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            lower = line.lower()
            for pattern in patterns:
                if pattern.lower() in lower:
                    hits.append({
                        "pattern": pattern,
                        "source": str(file_path),
                        "line": str(lineno),
                        "example": line.strip()[:220],
                    })
                    if len(hits) >= max_hits:
                        return hits
    return hits


def run_static_triage(app_path: Path, binary_path: Path | None, out_dir: Path) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    string_lines = _collect_strings(binary_path)
    lower_strings = [(idx + 1, s, s.lower()) for idx, s in enumerate(string_lines)]
    summary: list[dict[str, Any]] = []

    for rule in TRIAGE_RULES:
        matches: list[dict[str, str]] = []

        for line_no, original, lowered in lower_strings:
            for pattern in rule["patterns"]:
                if pattern.lower() in lowered:
                    matches.append({
                        "pattern": pattern,
                        "source": str(binary_path) if binary_path else "binary",
                        "line": str(line_no),
                        "example": original.strip()[:220],
                    })
                    break
            if len(matches) >= 40:
                break

        matches.extend(_search_files(app_path, rule["patterns"], max_hits=max(0, 60 - len(matches))))

        report_name = _safe_filename(rule["category"])
        report_path = out_dir / report_name

        lines = [
            rule["category"],
            "=" * 80,
            "",
            f"Category: {rule['category']}",
            "",
            "Purpose",
            "-" * 80,
            "Identify static indicators that require manual validation by the tester.",
            "",
            "What to Review",
            "-" * 80,
            rule["guidance"],
            "",
            "Pattern Matches",
            "-" * 80,
        ]

        if matches:
            for m in matches:
                lines.append(f"Pattern: {m['pattern']}")
                lines.append(f"Source: {m['source']}")
                lines.append(f"Line: {m['line']}")
                lines.append(f"Example: {m['example']}")
                lines.append("")
        else:
            lines.append("No matches identified.")
            lines.append("")

        write_text(report_path, "\n".join(lines))

        if matches:
            summary.append({
                "category": rule["category"],
                "risk": rule["risk"],
                "confidence": rule["confidence"],
                "matches": len(matches),
                "report_file": report_name,
                "guidance": rule["guidance"],
            })

    return summary


def write_static_triage_summary(path: Path, summary: list[dict[str, Any]], triage_dir: Path) -> None:
    lines = [
        "iOS Static Triage Summary",
        "=" * 80,
        "",
        f"Static triage reports directory: {triage_dir}",
        "",
        "Category | Report File",
        "-" * 80,
    ]

    if not summary:
        lines.append("No static triage indicators identified.")
    else:
        for item in summary:
            category = item.get("category", "")
            report_file = item.get("report_file", "")
            lines.append(f"{category} | static_triage/{report_file}")

    write_text(path, "\n".join(lines).rstrip() + "\n")
