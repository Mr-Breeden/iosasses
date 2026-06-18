from pathlib import Path
from .utils import write_text

def write_runtime_evidence_template(path: Path)->None:
    text = """# iOSAssess Runtime Evidence Template

## Naming Convention

- Screenshots: `TC-XXX-###_<description>.png`
- Command output: `TC-XXX-###_<description>.txt`
- Videos: `TC-XXX-###_<description>.mp4`

Examples:

- `TC-RI-001_frida_url_monitor.png`
- `TC-ST-002_keychain_dump.txt`
- `TC-MA-001_memory_search.txt`

## Per-Test-Case Evidence

Test Case ID:
Tool Used:
Command:
Application State:
Expected Result:
Actual Result:
Evidence Files:
Assessment Notes:

## Command Output Example

```text
$ objection -g com.example.app explore
ios keychain dump
```

Capture:
- Exact command used
- Relevant output
- Timestamp
- Associated screenshot(s)
"""
    write_text(path, text)
