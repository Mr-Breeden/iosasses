
from __future__ import annotations

from pathlib import Path
from textwrap import wrap
from typing import Any

from .utils import write_text


WRAP_WIDTH = 100


def _normalize_environment(value: str | None) -> str:
    value = (value or "physical").strip().lower()
    if value in {"2", "sim", "simulator"}:
        return "simulator"
    return "physical"


def _line(lines: list[str], value: str = "") -> None:
    lines.append(value.rstrip())


def _section(lines: list[str], title: str) -> None:
    _line(lines, "")
    _line(lines, title)
    _line(lines, "=" * len(title))
    _line(lines, "")


def _case(lines: list[str], case_id: str, title: str) -> None:
    header = f"[ ] [{case_id}] {title}"
    _line(lines, "")
    _line(lines, header)
    _line(lines, "-" * min(len(header), 100))


def _paragraph(lines: list[str], label: str, text: str) -> None:
    _line(lines, f"{label}:")
    for part in wrap(text, width=WRAP_WIDTH):
        _line(lines, f"  {part}")
    _line(lines, "")


def _bullets(lines: list[str], label: str, values: list[str]) -> None:
    _line(lines, f"{label}:")
    for value in values:
        wrapped = wrap(value, width=WRAP_WIDTH - 4) or [""]
        _line(lines, f"  - {wrapped[0]}")
        for extra in wrapped[1:]:
            _line(lines, f"    {extra}")
    _line(lines, "")


def _commands(lines: list[str], label: str, values: list[str]) -> None:
    _line(lines, f"{label}:")
    for value in values:
        _line(lines, f"  {value}")
    _line(lines, "")


def _values(lines: list[str], label: str, values: list[str]) -> None:
    _line(lines, f"{label}:")
    for value in values:
        _line(lines, f"  {value}")
    _line(lines, "")


def _write_plain_text(path: Path, lines: list[str]) -> None:
    content = "\n".join(lines).rstrip() + "\n"
    write_text(path, content)


def _add_log_review(lines: list[str], bundle_id: str, executable: str, environment: str) -> None:
    _case(lines, "TC-RT-001", "Device Log Review")
    _paragraph(
        lines,
        "Objective",
        "Monitor application logs while exercising authentication, account, payment, profile, logout, and other sensitive workflows.",
    )

    if environment == "simulator":
        _line(lines, "Environment: iOS Simulator")
        _commands(
            lines,
            "Commands",
            [
                f"log stream --predicate 'process CONTAINS \"{executable}\"' --info",
                "log stream --info | grep -Ei 'password|token|jwt|authorization|bearer|secret|exception|error|crash'",
            ],
        )
    else:
        _line(lines, "Environment: Physical iPhone/iPad")
        _commands(
            lines,
            "Commands",
            [
                f"idevicesyslog | grep -i '{bundle_id}'",
                "idevicesyslog | grep -Ei 'password|token|jwt|authorization|bearer|secret|exception|error|crash'",
            ],
        )
        _paragraph(
            lines,
            "Note",
            "Keep the device unlocked and trusted by the Mac while collecting logs.",
        )

    _bullets(
        lines,
        "Look For",
        [
            "Passwords, tokens, authorization headers, PII, stack traces, debug output, or sensitive business data.",
            "Unexpected exceptions or crashes when testing links, authentication, storage, or WebView behavior.",
        ],
    )


def _add_screenshot_review(lines: list[str]) -> None:
    _case(lines, "TC-RT-002", "Screenshot and App Switcher Protection Review")
    _paragraph(
        lines,
        "Objective",
        "Check whether sensitive screens expose information through screenshots or the iOS app switcher.",
    )
    _bullets(
        lines,
        "Steps",
        [
            "Navigate to login, MFA, account profile, payment, healthcare, financial, or other sensitive screens.",
            "Attempt a screenshot.",
            "Send the app to the background and review the app switcher preview.",
        ],
    )
    _bullets(
        lines,
        "Look For",
        [
            "Sensitive data visible in screenshots.",
            "Sensitive data visible in the app switcher preview.",
            "Screens that should be masked, blurred, or protected but are not.",
        ],
    )


def _add_url_scheme_case(lines: list[str], counter: int, scheme: str, environment: str) -> None:
    payloads = [
        f"{scheme}://",
        f"{scheme}://callback?code=TEST&state=TEST",
        f"{scheme}://callback?redirect=https://example.com",
        f"{scheme}://callback?redirect=javascript:alert(1)",
    ]

    _case(lines, f"TC-URL-{counter:03d}", f"Custom URL Scheme Review: {scheme}://")
    _paragraph(
        lines,
        "Objective",
        "Determine whether the URL scheme handler exposes sensitive actions, authentication bypasses, unsafe redirects, token leakage, or untrusted URL loading.",
    )

    if environment == "simulator":
        _line(lines, "Environment: iOS Simulator")
        _commands(
            lines,
            "Commands",
            [f"xcrun simctl openurl booted '{payload}'" for payload in payloads],
        )
        _paragraph(
            lines,
            "Expected",
            "The URL opens in the booted simulator if the application is installed and registered for the scheme.",
        )
    else:
        _line(lines, "Environment: Physical iPhone/iPad")
        _values(lines, "Physical Device Test URLs", payloads)
        _bullets(
            lines,
            "How to Open on Physical Device",
            [
                "Paste the URL into Safari on the device and attempt to open it.",
                "Send the URL to the device using Notes, Messages, Mail, AirDrop, or a local HTML test page.",
                "Tap the URL on the device and observe whether the application handles it.",
            ],
        )
        _paragraph(
            lines,
            "Expected",
            "The application may open if it is installed and registered for the scheme.",
        )

    _bullets(
        lines,
        "Look For",
        [
            "Unsafe redirects to attacker-controlled destinations.",
            "Token, code, or state leakage.",
            "Authentication bypass or access to sensitive screens.",
            "WebView loading of untrusted URLs.",
            "Crashes, verbose errors, or sensitive data in logs.",
        ],
    )


def _add_universal_links(lines: list[str], associated_domains: list[str], environment: str) -> None:
    if not associated_domains:
        return

    _case(lines, "TC-UL-001", "Universal Links and Associated Domains Review")
    _paragraph(
        lines,
        "Objective",
        "Validate whether associated domains and Universal Links behave as expected and do not expose sensitive flows.",
    )
    _values(lines, "Associated Domains", associated_domains)

    if environment == "simulator":
        _commands(
            lines,
            "Simulator Options",
            [
                "Open the HTTPS URL directly in Safari inside the simulator.",
                "xcrun simctl openurl booted '<https_url>'",
            ],
        )
    else:
        _bullets(
            lines,
            "Physical Device Options",
            [
                "Open the HTTPS link directly in Safari on the device.",
                "Send the link through Notes, Messages, Mail, AirDrop, or a local HTML test page.",
                "Tap the link and observe whether the application or browser handles it.",
            ],
        )

    _bullets(
        lines,
        "Look For",
        [
            "Password reset or account recovery flows that can be manipulated.",
            "Open redirect behavior.",
            "Weak domain/path validation.",
            "Sensitive actions triggered from links without authentication or confirmation.",
        ],
    )




def _add_local_storage(lines: list[str], environment: str, bundle_id: str) -> None:
    _case(lines, "TC-ST-001", "Local Storage Review")
    _paragraph(
        lines,
        "Objective",
        "Review application storage locations for sensitive information at rest where authorized.",
    )

    if environment == "simulator":
        _line(lines, "Environment: iOS Simulator")
        _commands(
            lines,
            "Identify App Container",
            [
                "find ~/Library/Developer/CoreSimulator/Devices -path '*Containers/Data/Application*' -type d",
                "find ~/Library/Developer/CoreSimulator/Devices -path '*Containers/Data/Application*' -type d | grep -i '<appname>'",
            ],
        )
        _paragraph(
            lines,
            "Note",
            "Use the application name or bundle identifier to identify the correct simulator application container.",
        )
    else:
        _line(lines, "Environment: Physical iPhone/iPad")
        _commands(
            lines,
            "Identify App Container",
            [
                "ls /var/mobile/Containers/Data/Application/",
                "ls /var/mobile/Containers/Data/Application/* | grep -i '<appname>'",
            ],
        )
        _paragraph(
            lines,
            "Note",
            "Use the application name to identify the correct container directory. Container UUIDs change after reinstallations.",
        )

    _commands(
        lines,
        "Review Commands",
        [
            "APP_CONTAINER='<application_container_path>'",
            'find "$APP_CONTAINER" -type f',
            'grep -RiE \'password|token|jwt|authorization|bearer|secret|api_key|client_secret\' "$APP_CONTAINER"',
        ],
    )

    _bullets(
        lines,
        "Review",
        [
            "Library/Preferences",
            "Documents",
            "Library/Caches",
            "SQLite databases",
            "WebKit storage",
            "Temporary files",
        ],
    )

    _bullets(
        lines,
        "Look For",
        [
            "Tokens, credentials, PII, session identifiers, cached API responses, or sensitive documents.",
            "Sensitive values stored without platform protection or appropriate access controls.",
        ],
    )



def _add_network_review(lines: list[str], environment: str) -> None:
    _case(lines, "TC-NW-001", "Network Proxy Review")
    _paragraph(
        lines,
        "Objective",
        "Capture and review application traffic using Burp Suite or another approved proxy workflow.",
    )

    if environment == "simulator":
        _paragraph(
            lines,
            "Environment Notes",
            "Configure proxy settings for the simulator or the macOS network path used by the simulator.",
        )
    else:
        _paragraph(
            lines,
            "Environment Notes",
            "Configure the physical device Wi-Fi proxy to point to Burp Suite and install the Burp CA certificate where authorized.",
        )

    _paragraph(
        lines,
        "Certificate Pinning Note",
        "Certificate pinning is not reported as a finding. If pinning is present, attempt an approved bypass or alternative traffic analysis workflow to support application and API testing. If interception remains unavailable, document the coverage limitation.",
    )
    _bullets(
        lines,
        "Look For",
        [
            "Authentication and authorization issues.",
            "API exposure.",
            "Sensitive data in transit.",
            "Weak TLS behavior.",
            "Requests that should be included in API testing scope.",
        ],
    )




def _add_runtime_integration(lines: list[str], bundle_id: str) -> None:
    _case(lines, "TC-RI-001", "Frida Runtime Instrumentation")
    _values(lines, "Generated Runtime Templates", [
        "runtime_templates/frida_basic_hooks.js",
        "runtime_templates/frida_url_monitor.js",
        "runtime_templates/frida_keychain_monitor.js",
        "runtime_templates/frida_webview_monitor.js",
        "runtime_templates/frida_jailbreak_indicator_monitor.js",
    ])

    _commands(lines, "Frida Commands", [
        f"frida -U -f {bundle_id} --no-pause",
        f"frida -U -f {bundle_id} -l ssl_bypass.js",
    ])
    _paragraph(lines, "Objective", "Use Frida to validate static findings and observe runtime behavior.")

    _case(lines, "TC-RI-002", "Objection Runtime Exploration")
    _commands(lines, "Objection Commands", [
        f"objection -g {bundle_id} explore",
        "env",
        "memory list modules"
    ])

    _case(lines, "TC-RI-003", "r2frida Analysis")
    _commands(lines, "r2frida Commands", [
        f"r2 frida://usb//{bundle_id}",
        "i",
        "iE",
        "iS",
        "afl",
        ":objc.classes",
        ":objc.methods"
    ])
    _bullets(lines, "Evidence to Capture", [
        "Attached process evidence.",
        "Interesting classes or methods.",
        "Exported functions.",
        "Runtime observations tied to the test case."
    ])

    _case(lines, "TC-RI-004", "LLDB Debugging")
    _commands(lines, "LLDB Commands", [
        "lldb",
        f"process attach --name {bundle_id}",
        "image list",
        "image lookup -n <symbol>",
        "breakpoint set -n <function_or_method>",
        "continue",
        "thread backtrace"
    ])
    _bullets(lines, "Evidence to Capture", [
        "Attach success.",
        "Breakpoints set.",
        "Backtrace or symbol evidence.",
        "Runtime behavior observed."
    ])
    _paragraph(lines, "Note", "Debugger attachment may require a suitable build, entitlements, or jailbroken test device.")

def _add_static_triage_followup(lines: list[str]) -> None:
    _case(lines, "TC-SR-001", "Static Triage Follow-Up")
    _paragraph(
        lines,
        "Objective",
        "Review static triage reports for security-relevant patterns that require manual validation.",
    )
    _values(
        lines,
        "Reports",
        [
            "static_triage_summary.txt",
            "static_triage/",
        ],
    )
    _bullets(
        lines,
        "Look For",
        [
            "Hardcoded secrets or credentials.",
            "Jailbreak detection patterns.",
            "WebView usage.",
            "Keychain usage.",
            "Local storage indicators.",
            "Logging indicators.",
            "Cryptographic indicators.",
        ],
    )
    _bullets(
        lines,
        "Evidence",
        [
            "Affected file or binary string.",
            "Related app behavior.",
            "Runtime validation result.",
            "Screenshot, log, or command output where applicable.",
        ],
    )


def generate_test_cases(
    path: Path,
    metadata: dict[str, Any],
    url_schemes: list[dict[str, Any]],
    associated_domains: list[str],
    testing_environment: str | None = "physical",
) -> None:
    environment = _normalize_environment(testing_environment)
    bundle_id = metadata.get("bundle_id") or "<bundle_id>"
    executable = metadata.get("executable") or "<app_keyword>"

    lines: list[str] = [
        "iOSAssess Manual Test Cases",
        "=" * 80,
        "",
        f"Bundle ID: {bundle_id}",
        f"Testing Environment: {environment}",
        "",
        "Purpose",
        "-" * 80,
        "This file is the primary tester-facing manual test plan generated by iOSAssess.",
        "Only commands and instructions relevant to the selected testing environment are included.",
    ]

    _section(lines, "Runtime Review")
    _add_log_review(lines, bundle_id, executable, environment)
    _add_screenshot_review(lines)

    _section(lines, "URL Handling")
    counter = 1
    for entry in url_schemes:
        for scheme in entry.get("schemes", []):
            _add_url_scheme_case(lines, counter, scheme, environment)
            counter += 1
    if counter == 1:
        _line(lines, "No custom URL schemes were identified.")
        _line(lines, "")

    _add_universal_links(lines, associated_domains, environment)

    _section(lines, "Storage")
    _add_local_storage(lines, environment, bundle_id)


    _case(lines, "TC-ST-002", "Keychain Review")
    _paragraph(lines, "Objective", "Validate whether sensitive values are stored in the iOS Keychain appropriately and whether they persist after logout.")
    _values(lines, "Reports", ["storage_review/keychain_review.txt", "runtime_templates/frida_keychain_monitor.js"])
    _commands(lines, "Suggested Commands", [f"objection -g {bundle_id} explore", "ios keychain dump"])
    _bullets(lines, "Look For", [
        "Tokens or credentials that remain after logout.",
        "Sensitive values with overly permissive accessibility classes.",
        "Unexpected shared keychain access groups.",
        "Secrets stored outside the Keychain when platform storage should be used."
    ])

    _case(lines, "TC-ST-003", "WebKit Storage Review")
    _paragraph(lines, "Objective", "Review WebKit storage locations for cached sensitive values, session artifacts, or API responses.")
    _values(lines, "Reports", ["storage_review/application_container_review.txt", "static_triage/webview_indicators.txt"])
    _bullets(lines, "Look For", [
        "Sensitive values in WebKit cache, LocalStorage, IndexedDB, or cookies.",
        "Session cookies or tokens available outside expected storage boundaries.",
        "Cached API responses containing sensitive user data."
    ])

    _case(lines, "TC-ST-004", "NSUserDefaults and Preferences Review")
    _paragraph(lines, "Objective", "Review preferences and NSUserDefaults-backed storage for sensitive values.")
    _values(lines, "Reports", ["storage_review/application_container_review.txt", "storage_review/storage_keyword_review.txt"])
    _bullets(lines, "Look For", [
        "Tokens, account identifiers, feature flags, or sensitive user settings in plist preference files.",
        "Values that remain after logout or account removal."
    ])

    _case(lines, "TC-ST-005", "SQLite and Database Review")
    _paragraph(lines, "Objective", "Review SQLite, Realm, and local database files for sensitive data at rest.")
    _values(lines, "Reports", ["storage_review/local_storage_review.txt", "storage_review/application_container_review.txt"])
    _bullets(lines, "Look For", [
        "Cached API responses.",
        "Authentication/session artifacts.",
        "PII, financial, health, or customer data.",
        "Data that should be encrypted or removed after logout."
    ])


    _section(lines, "Network")
    _add_network_review(lines, environment)

    _section(lines, "Runtime Integration")
    _add_runtime_integration(lines, bundle_id)


    _section(lines, "Memory Analysis")

    _case(lines, "TC-MA-001", "Search Memory for Tokens")
    _paragraph(lines, "Objective", "Determine whether access tokens, refresh tokens, JWTs, or session identifiers are present in memory during sensitive workflows and whether they remain after logout.")
    _values(lines, "Reports", ["memory_analysis/memory_analysis_workflow.txt", "memory_analysis/frida_memory_search.txt", "memory_analysis/objection_memory_search.txt"])
    _commands(lines, "Suggested Commands", [
        f"objection -g {bundle_id} explore",
        "memory search <known_token_or_marker>",
        f"frida -U -f {bundle_id} --no-pause"
    ])
    _bullets(lines, "Expected Results", [
        "Sensitive tokens may exist briefly during active authenticated use.",
        "Tokens should not remain accessible after logout or session termination unless there is a justified platform or business reason."
    ])
    _bullets(lines, "Evidence to Capture", [
        "Test value or marker used.",
        "Command output showing whether the value was found.",
        "Application state when memory was searched.",
        "Result before and after logout."
    ])

    _case(lines, "TC-MA-002", "Search Memory for Credentials")
    _paragraph(lines, "Objective", "Determine whether passwords, PINs, MFA codes, or other credential material remain in memory longer than necessary.")
    _values(lines, "Reports", ["memory_analysis/memory_analysis_workflow.txt", "memory_analysis/objection_memory_search.txt"])
    _commands(lines, "Suggested Commands", [
        f"objection -g {bundle_id} explore",
        "memory search <known_password_or_marker>"
    ])
    _bullets(lines, "Expected Results", [
        "Credential material should not remain accessible after authentication is complete.",
        "Credential values should not persist after logout, backgrounding, or app restart."
    ])
    _bullets(lines, "Evidence to Capture", [
        "Known test credential or marker.",
        "Command output.",
        "Workflow step when value was found.",
        "Cleanup behavior after logout or app restart."
    ])

    _case(lines, "TC-MA-003", "Validate Sensitive Data Cleanup")
    _paragraph(lines, "Objective", "Validate whether sensitive values are cleared from memory after logout, account switching, timeout, backgrounding, or app termination.")
    _values(lines, "Reports", ["memory_analysis/memory_evidence_checklist.txt", "test_cases.txt"])
    _bullets(lines, "Steps", [
        "Authenticate to the application with a test account.",
        "Perform sensitive workflows using a known marker value.",
        "Search memory during active use.",
        "Log out or terminate the session.",
        "Search memory again.",
        "Background and foreground the application if relevant.",
        "Terminate and relaunch the application if relevant."
    ])
    _bullets(lines, "Expected Results", [
        "Sensitive values should be cleared when they are no longer needed.",
        "Sensitive values should not remain accessible after logout or session termination."
    ])
    _bullets(lines, "Evidence to Capture", [
        "Before and after command output.",
        "Application state.",
        "Screenshots or logs showing logout/session termination.",
        "Analyst conclusion."
    ])



    _section(lines, "Authentication and Biometric Testing")

    _case(lines, "TC-AU-001", "Biometric Enforcement")
    _paragraph(lines, "Objective", "Validate whether Face ID, Touch ID, or LocalAuthentication-protected workflows enforce authentication appropriately and cannot be bypassed through normal app navigation or approved runtime testing.")
    _bullets(lines, "Steps", [
        "Identify workflows protected by biometric authentication.",
        "Cancel biometric prompts and observe app behavior.",
        "Background and foreground the app during biometric prompts.",
        "Where authorized, use runtime tooling to observe LAContext-related behavior."
    ])
    _bullets(lines, "Expected Results", [
        "Sensitive workflows should remain unavailable when biometric authentication is cancelled or fails.",
        "The app should require the expected authentication path before exposing sensitive data or actions."
    ])
    _bullets(lines, "Evidence to Capture", [
        "Workflow tested.",
        "Screenshots or screen recording of prompt behavior.",
        "Result after cancel/failure/backgrounding.",
        "Runtime output if Frida, Objection, r2frida, or LLDB was used."
    ])

    _case(lines, "TC-AU-002", "Session Expiration")
    _paragraph(lines, "Objective", "Validate whether sessions expire appropriately after logout, timeout, app backgrounding, app termination, or token invalidation.")
    _bullets(lines, "Steps", [
        "Authenticate with a test account.",
        "Log out and attempt to reuse protected workflows.",
        "Leave the app idle until timeout conditions are met.",
        "Background, foreground, terminate, and relaunch the app where applicable.",
        "Review proxy traffic and device logs for token/session reuse."
    ])
    _bullets(lines, "Expected Results", [
        "Protected workflows should require a valid session.",
        "Logout should invalidate local and server-side session state where applicable.",
        "Expired or invalid tokens should not continue to authorize sensitive actions."
    ])
    _bullets(lines, "Evidence to Capture", [
        "Timeline of session actions.",
        "Request/response evidence for protected endpoints.",
        "Screenshots of logout and re-access attempts.",
        "Observed token/session behavior."
    ])

    _case(lines, "TC-AU-003", "Re-authentication Requirements")
    _paragraph(lines, "Objective", "Validate whether sensitive actions require re-authentication or appropriate confirmation before completion.")
    _bullets(lines, "Sensitive Actions to Review", [
        "Password or email change.",
        "Payment or transfer activity.",
        "Viewing sensitive account information.",
        "Changing MFA or recovery options.",
        "Exporting or deleting data."
    ])
    _bullets(lines, "Expected Results", [
        "High-impact actions should require appropriate confirmation or re-authentication.",
        "Sensitive actions should not be completed solely through stale sessions, deep links, or backgrounded app state."
    ])
    _bullets(lines, "Evidence to Capture", [
        "Action tested.",
        "Authentication state.",
        "Screenshots or proxy evidence.",
        "Whether re-authentication was required."
    ])


    _section(lines, "Static Triage")
    _add_static_triage_followup(lines)

    _write_plain_text(path, lines)
