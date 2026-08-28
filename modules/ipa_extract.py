from __future__ import annotations

import shutil
import zipfile
from pathlib import Path


def validate_ipa(ipa_path: Path) -> tuple[bool, str]:
    if not ipa_path.exists():
        return False, f"IPA not found: {ipa_path}"
    if not ipa_path.is_file():
        return False, f"IPA path is not a file: {ipa_path}"
    if ipa_path.suffix.lower() != ".ipa":
        return False, "Input file does not have .ipa extension"
    if not zipfile.is_zipfile(ipa_path):
        return False, "IPA is not a valid ZIP archive"
    return True, "IPA validated"


def extract_ipa(ipa_path: Path, extract_dir: Path) -> Path:
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(extract_dir)
    return extract_dir


def find_app_bundle(extract_dir: Path) -> Path:
    payload = extract_dir / "Payload"
    if not payload.exists():
        raise FileNotFoundError("Payload directory not found in IPA")
    apps = sorted(payload.glob("*.app"))
    if not apps:
        raise FileNotFoundError("No .app bundle found under Payload/")
    return apps[0]


def find_main_executable(app_path: Path, info_plist: dict) -> Path | None:
    exe_name = info_plist.get("CFBundleExecutable")
    if not exe_name:
        return None
    candidate = app_path / exe_name
    return candidate if candidate.exists() else None
