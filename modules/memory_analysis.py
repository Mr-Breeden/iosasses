from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import write_text


def write_memory_analysis_workflows(out_dir: Path, metadata: dict[str, Any], environment: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_id = metadata.get("bundle_id") or "<bundle_id>"

    overview = f"""iOSAssess Memory Analysis Workflow
================================================================================

Bundle ID:
{bundle_id}

Testing Environment:
{environment}

Purpose:
This workflow helps testers identify whether sensitive data remains in process memory during or after sensitive workflows.

Sensitive values to test with:
- Test username
- Test password
- Session token
- Access token
- Refresh token
- Account number
- Email address
- Known unique marker string

Recommended process:
1. Start the application.
2. Authenticate with a test account.
3. Perform a sensitive workflow.
4. Search memory for known test values.
5. Log out or clear application state.
6. Search memory again.
7. Compare expected and actual results.

Important:
Memory findings require careful validation. A value appearing briefly in memory during active use may be expected. A stronger issue exists when sensitive values persist longer than necessary, remain after logout, or are exposed in an avoidable location.
"""
    write_text(out_dir / "memory_analysis_workflow.txt", overview)

    frida = f"""iOSAssess Frida Memory Search Guidance
================================================================================

Bundle ID:
{bundle_id}

Start application with Frida:
  frida -U -f {bundle_id} --no-pause

Attach to running process:
  frida -U {bundle_id}

Suggested Frida commands/scripts:
  frida -U -f {bundle_id} -l runtime_templates/frida_basic_hooks.js --no-pause

Manual memory validation approach:
1. Use a unique test value during login or sensitive workflow.
2. Search memory using approved tooling or custom Frida scripts.
3. Repeat after logout.
4. Document whether the value remains accessible.

Evidence:
- Command used
- Test value searched
- App workflow performed
- Whether value was found before logout
- Whether value was found after logout
- Screenshot or command output
"""
    write_text(out_dir / "frida_memory_search.txt", frida)

    objection = f"""iOSAssess Objection Memory Search Guidance
================================================================================

Bundle ID:
{bundle_id}

Start Objection:
  objection -g {bundle_id} explore

Useful commands:
  memory list modules
  memory list exports <module>
  memory search <sensitive_test_value>

Suggested workflow:
1. Start Objection.
2. Authenticate to the app.
3. Search for a known test value.
4. Log out.
5. Search again.
6. Document persistence or cleanup behavior.

Evidence:
- Objection command output
- Application state
- Test case ID
- Sanitized sensitive value or marker string
"""
    write_text(out_dir / "objection_memory_search.txt", objection)

    lldb = f"""iOSAssess LLDB Memory Analysis Guidance
================================================================================

Bundle ID:
{bundle_id}

Start LLDB:
  lldb

Attach:
  process attach --name {bundle_id}

Useful commands:
  image list
  thread backtrace
  memory region <address>
  memory read <address>
  expression -- <expression>

Suggested use:
- LLDB memory testing is more advanced and should be used when Frida/Objection do not provide enough detail.
- Capture symbol, breakpoint, and memory-read evidence only when authorized and necessary.

Evidence:
- Attach success
- Command used
- Memory region or symbol reviewed
- Runtime state
- Result observed
"""
    write_text(out_dir / "lldb_memory_analysis.txt", lldb)

    checklist = """iOSAssess Memory Analysis Evidence Checklist
================================================================================

For each memory test, capture:

- Test Case ID
- Tool used
- Device/simulator environment
- Application workflow
- Test value or unique marker
- Command used
- Whether value was found during active session
- Whether value remained after logout
- Whether value remained after app background/foreground
- Whether value remained after app termination/relaunch
- Evidence file name
- Analyst conclusion

Suggested evidence names:

- TC-MA-001_memory_token_search.txt
- TC-MA-002_memory_credential_search.txt
- TC-MA-003_sensitive_data_cleanup.txt
"""
    write_text(out_dir / "memory_evidence_checklist.txt", checklist)
