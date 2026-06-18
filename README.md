# iOSAssess v1.0.0

iOSAssess is an iOS application security assessment framework designed for static IPA review and tester-facing manual test guidance.

This version expands the stable IPA-focused workflow with static triage reporting for common iOS mobile assessment areas.

## Current Features

- Interactive mode
- CLI mode
- IPA validation and extraction
- `Payload/*.app` discovery
- `Info.plist` parsing
- Bundle metadata extraction
- URL scheme discovery
- Universal Link / Associated Domains discovery
- App Transport Security (ATS) review
- Entitlements extraction using `codesign`
- Basic binary metadata collection
- Static triage reporting
- Report folder generation
- Tester-facing `test_cases.txt`
- Inventory reports

## Static Triage Categories

iOSAssess v1.0.0 adds static triage for:

- Potential Secrets or Credentials
- Jailbreak Detection Indicators
- WebView Indicators
- Keychain Usage Indicators
- Local Storage Indicators
- Logging Indicators
- Cryptography Indicators

Static triage confidence reflects pattern confidence, not confirmed exploitability. Certificate pinning is not treated as a finding or issue; it is only used as network testing context.

## Requirements

Recommended platform:

- macOS
- Xcode
- Xcode Command Line Tools
- Python 3.11+

Install Command Line Tools:

```bash
xcode-select --install
```

Recommended Homebrew tools:

```bash
brew install python libimobiledevice ideviceinstaller ios-deploy jq
```

Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Interactive mode:

```bash
python3 iosassess.py
```

CLI mode:

```bash
python3 iosassess.py -i Application.ipa
```

Custom output directory:

```bash
python3 iosassess.py -i Application.ipa -o ./assessments
```

Assessment name:

```bash
python3 iosassess.py -i Application.ipa -n client_app_test
```

Testing environment selection:

```bash
python3 iosassess.py -i Application.ipa --environment physical
python3 iosassess.py -i Application.ipa --environment simulator
```

Version:

```bash
python3 iosassess.py --version
```

## Report Structure

Each run creates:

```text
assessments/
└── YYYYMMDD_HHMMSS/
    ├── extracted/
    └── reports/
        ├── findings_summary.txt
        ├── findings.txt
        ├── assessment_metadata.json
        ├── module_status.txt
        ├── test_cases.txt
        ├── static_triage_summary.txt
        ├── inventory/
        │   ├── ats_review.txt
        │   ├── binary_metadata.txt
        │   ├── entitlements_review.txt
        │   ├── info_plist_review.txt
        │   └── url_schemes.txt
        └── static_triage/
            ├── potential_secrets_or_credentials.txt
            ├── jailbreak_detection_indicators.txt
            ├── webview_indicators.txt
            ├── keychain_usage_indicators.txt
            ├── local_storage_indicators.txt
            ├── logging_indicators.txt
            └── cryptography_indicators.txt
```

## Notes

This tool provides assessment guidance and static triage. Findings should be manually validated before being reported to a client.

For jailbroken-device IPA extraction workflows, ensure the IPA has this structure:

```text
Application.ipa
└── Payload/
    └── Application.app/
        ├── Info.plist
        └── <main executable>
```

## Roadmap

Future versions may add:

- Frida / Objection test case generation
- Biometric bypass testing guidance
- Keychain review guidance
- Local container review helpers


## Test Case Formatting

`test_cases.txt` is generated as plain UTF-8 text with normalized LF line endings and shorter wrapped sections so it opens cleanly in macOS TextEdit, VS Code, Sublime, terminal pagers, and other common editors.

Physical-device reports do not include simulator-only `xcrun simctl openurl booted` commands.


## v1.0.0 Release Notes

This release establishes the stable iOSAssess baseline.

Primary execution artifact:

- `test_cases.txt`

Supporting artifacts include:

- `mastg_mapping.txt`
- `static_triage/*`
- `runtime_templates/*`
- `storage_review/*`
- `memory_analysis/*`
- `evidence_checklist.txt`