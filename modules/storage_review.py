from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import write_text


SENSITIVE_EXTENSIONS = [
    ".sqlite", ".sqlite3", ".db", ".plist", ".json", ".txt", ".log", ".realm", ".cookies", ".localstorage"
]

STORAGE_KEYWORDS = [
    "password", "passwd", "token", "jwt", "bearer", "authorization", "secret", "api_key",
    "client_secret", "refresh_token", "access_token", "session", "cookie", "credential"
]


def _safe_rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except Exception:
        return str(path)


def _inventory_app_storage_files(app_path: Path) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for p in app_path.rglob("*"):
        if not p.is_file():
            continue
        suffix = p.suffix.lower()
        if suffix in SENSITIVE_EXTENSIONS or any(part.lower() in {"webkit", "preferences", "caches"} for part in p.parts):
            try:
                size = p.stat().st_size
            except Exception:
                size = 0
            results.append({
                "path": _safe_rel(p, app_path),
                "extension": suffix or "<none>",
                "size": str(size),
            })
    return sorted(results, key=lambda x: x["path"])


def _search_packaged_resources(app_path: Path, max_hits: int = 100) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    text_exts = {".plist", ".json", ".txt", ".xml", ".html", ".js", ".strings", ".config"}
    for p in app_path.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in text_exts:
            continue
        try:
            content = p.read_text(errors="ignore")
        except Exception:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            lower = line.lower()
            for keyword in STORAGE_KEYWORDS:
                if keyword in lower:
                    hits.append({
                        "keyword": keyword,
                        "path": _safe_rel(p, app_path),
                        "line": str(lineno),
                        "example": line.strip()[:220],
                    })
                    break
            if len(hits) >= max_hits:
                return hits
    return hits


def write_storage_review_reports(out_dir: Path, app_path: Path, metadata: dict[str, Any], environment: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_id = metadata.get("bundle_id") or "<bundle_id>"
    display_name = metadata.get("display_name") or metadata.get("bundle_name") or "<appname>"
    app_keyword = str(display_name).replace(" ", "")

    files = _inventory_app_storage_files(app_path)
    hits = _search_packaged_resources(app_path)

    inventory_lines = [
        "iOSAssess Local Storage Review",
        "=" * 80,
        "",
        f"Bundle ID: {bundle_id}",
        f"Application Name: {display_name}",
        "",
        "Purpose",
        "-" * 80,
        "This report inventories packaged resources that may be relevant during local storage review.",
        "Runtime storage must still be reviewed manually on the simulator or physical test device.",
        "",
        "Storage Type | Path | What to Review",
        "-" * 80,
    ]

    if files:
        for item in files:
            storage_type = {
                ".plist": "Preferences (.plist)",
                ".sqlite": "SQLite Database",
                ".sqlite3": "SQLite Database",
                ".db": "Database",
                ".realm": "Realm Database",
                ".json": "JSON Resource",
                ".txt": "Text Resource",
                ".log": "Log File"
            }.get(item["extension"], "Storage Artifact")
            review = "Review for tokens, account identifiers, cached responses, sensitive values, and logout persistence."
            inventory_lines.append(f"{storage_type} | {item['path']} | {review}")
    else:
        inventory_lines.append("No packaged storage-like resources were identified.")

    write_text(out_dir / "local_storage_review.txt", "\n".join(inventory_lines).rstrip() + "\n")

    keyword_lines = [
        "iOSAssess Storage Keyword Review",
        "=" * 80,
        "",
        f"Bundle ID: {bundle_id}",
        "",
        "Purpose",
        "-" * 80,
        "This report identifies packaged text resources that contain storage/security-related keywords.",
        "These are triage indicators and require manual validation.",
        "",
        "Keyword Matches",
        "-" * 80,
    ]

    if hits:
        for hit in hits:
            keyword_lines.append(f"Keyword: {hit['keyword']}")
            keyword_lines.append(f"Path: {hit['path']}")
            keyword_lines.append(f"Line: {hit['line']}")
            keyword_lines.append(f"Example: {hit['example']}")
            keyword_lines.append("")
    else:
        keyword_lines.append("No packaged resource keyword matches identified.")
        keyword_lines.append("")

    write_text(out_dir / "storage_keyword_review.txt", "\n".join(keyword_lines).rstrip() + "\n")

    keychain_lines = [
        "iOSAssess Keychain Review Guidance",
        "=" * 80,
        "",
        f"Bundle ID: {bundle_id}",
        "",
        "Purpose",
        "-" * 80,
        "Use this guide to validate whether sensitive values are stored in the iOS Keychain appropriately.",
        "",
        "Recommended Manual Workflow",
        "-" * 80,
        "1. Log in to the application with a test account.",
        "2. Exercise workflows that create or update tokens, credentials, MFA state, or session material.",
        "3. Review Keychain usage through approved runtime tooling.",
        "4. Validate item accessibility, account/service names, and whether data persists after logout.",
        "",
        "Objection Examples",
        "-" * 80,
        f"objection -g {bundle_id} explore",
        "ios keychain dump",
        "",
        "Frida Template",
        "-" * 80,
        "runtime_templates/frida_keychain_monitor.js",
        "",
        "What to Look For",
        "-" * 80,
        "- Tokens or credentials that remain after logout.",
        "- Sensitive values with overly permissive accessibility classes.",
        "- Unexpected shared keychain access groups.",
        "- Secrets stored outside the Keychain when platform storage should be used.",
        "",
        "Evidence to Capture",
        "-" * 80,
        "- Test case ID.",
        "- Workflow performed.",
        "- Keychain command output.",
        "- Item attributes and accessibility class.",
        "- Logout/reinstall behavior when relevant.",
    ]
    write_text(out_dir / "keychain_review.txt", "\n".join(keychain_lines).rstrip() + "\n")

    if environment == "simulator":
        container_steps = [
            "Environment: iOS Simulator",
            "",
            "Identify App Container",
            "-" * 80,
            "find ~/Library/Developer/CoreSimulator/Devices -path '*Containers/Data/Application*' -type d",
            f"find ~/Library/Developer/CoreSimulator/Devices -path '*Containers/Data/Application*' -type d | grep -i '{app_keyword}'",
        ]
    else:
        container_steps = [
            "Environment: Physical iPhone/iPad",
            "",
            "Identify App Container",
            "-" * 80,
            "ls /var/mobile/Containers/Data/Application/",
            f"ls /var/mobile/Containers/Data/Application/* | grep -i '{app_keyword}'",
        ]

    checklist_lines = [
        "iOSAssess Application Container Review Checklist",
        "=" * 80,
        "",
        f"Bundle ID: {bundle_id}",
        f"Application Name: {display_name}",
        "",
        *container_steps,
        "",
        "Review Commands",
        "-" * 80,
        "APP_CONTAINER='<application_container_path>'",
        'find "$APP_CONTAINER" -type f',
        'grep -RiE "password|token|jwt|authorization|bearer|secret|api_key|client_secret|session|cookie" "$APP_CONTAINER"',
        "",
        "Locations to Review",
        "-" * 80,
        "- Library/Preferences",
        "- Documents",
        "- Library/Caches",
        "- tmp",
        "- WebKit storage",
        "- SQLite databases",
        "- Realm databases",
        "- LocalStorage / IndexedDB",
        "",
        "Evidence to Capture",
        "-" * 80,
        "- Container path.",
        "- File path containing sensitive data.",
        "- Command used.",
        "- Sanitized evidence snippet.",
        "- App workflow that created the data.",
        "- Whether logout clears the data.",
    ]
    write_text(out_dir / "application_container_review.txt", "\n".join(checklist_lines).rstrip() + "\n")
