from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import write_text


def _bundle(metadata: dict[str, Any]) -> str:
    return metadata.get("bundle_id") or "<bundle_id>"


def write_runtime_templates(out_dir: Path, metadata: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_id = _bundle(metadata)
    basic_hooks_path = out_dir / "frida_basic_hooks.js"
    url_monitor_path = out_dir / "frida_url_monitor.js"
    keychain_monitor_path = out_dir / "frida_keychain_monitor.js"
    webview_monitor_path = out_dir / "frida_webview_monitor.js"
    jailbreak_monitor_path = out_dir / "frida_jailbreak_indicator_monitor.js"

    write_text(out_dir / "frida_basic_hooks.js", f"""/*
iOSAssess Runtime Template: Basic Objective-C Runtime Discovery
Bundle ID: {bundle_id}

Usage:
  frida -U -f {bundle_id} -l {basic_hooks_path} --no-pause
*/

if (ObjC.available) {{
  console.log("[+] Objective-C runtime is available");
  console.log("[+] Bundle ID: {bundle_id}");
  ["NSURLSession", "WKWebView", "LAContext", "NSUserDefaults", "UIApplication"].forEach(function(name) {{
    if (ObjC.classes[name]) {{
      console.log("[+] Class available: " + name);
    }} else {{
      console.log("[-] Class not found: " + name);
    }}
  }});
}} else {{
  console.log("[-] Objective-C runtime is not available");
}}
""")

    write_text(out_dir / "frida_url_monitor.js", f"""/*
iOSAssess Runtime Template: URL Handling Monitor
Bundle ID: {bundle_id}

Usage:
  frida -U -f {bundle_id} -l {url_monitor_path} --no-pause
*/

if (ObjC.available) {{
  var UIApplication = ObjC.classes.UIApplication;
  if (UIApplication && UIApplication["- openURL:"]) {{
    Interceptor.attach(UIApplication["- openURL:"].implementation, {{
      onEnter: function(args) {{
        try {{
          var url = new ObjC.Object(args[2]);
          console.log("[openURL:] " + url.toString());
        }} catch (e) {{
          console.log("[openURL:] parse error: " + e);
        }}
      }}
    }});
  }}
  if (UIApplication && UIApplication["- openURL:options:completionHandler:"]) {{
    Interceptor.attach(UIApplication["- openURL:options:completionHandler:"].implementation, {{
      onEnter: function(args) {{
        try {{
          var url = new ObjC.Object(args[2]);
          console.log("[openURL:options:completionHandler:] " + url.toString());
        }} catch (e) {{
          console.log("[openURL options] parse error: " + e);
        }}
      }}
    }});
  }}
}}
""")

    write_text(out_dir / "frida_keychain_monitor.js", f"""/*
iOSAssess Runtime Template: Keychain API Monitor
Bundle ID: {bundle_id}

Usage:
  frida -U -f {bundle_id} -l {keychain_monitor_path} --no-pause
*/

["SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete"].forEach(function(name) {{
  var ptr = Module.findExportByName("Security", name);
  if (ptr) {{
    Interceptor.attach(ptr, {{
      onEnter: function(args) {{
        console.log("[Keychain] " + name + " called");
      }},
      onLeave: function(retval) {{
        console.log("[Keychain] " + name + " returned: " + retval);
      }}
    }});
    console.log("[+] Hooked " + name);
  }} else {{
    console.log("[-] Could not find " + name);
  }}
}});
""")

    write_text(out_dir / "frida_webview_monitor.js", f"""/*
iOSAssess Runtime Template: WebView Monitor
Bundle ID: {bundle_id}

Usage:
  frida -U -f {bundle_id} -l {webview_monitor_path} --no-pause
*/

if (ObjC.available) {{
  var WKWebView = ObjC.classes.WKWebView;
  if (WKWebView && WKWebView["- loadRequest:"]) {{
    Interceptor.attach(WKWebView["- loadRequest:"].implementation, {{
      onEnter: function(args) {{
        try {{
          var request = new ObjC.Object(args[2]);
          console.log("[WKWebView loadRequest:] " + request.toString());
        }} catch (e) {{
          console.log("[WKWebView] parse error: " + e);
        }}
      }}
    }});
    console.log("[+] Hooked WKWebView loadRequest:");
  }} else {{
    console.log("[-] WKWebView loadRequest: not found");
  }}
}}
""")

    write_text(out_dir / "frida_jailbreak_indicator_monitor.js", f"""/*
iOSAssess Runtime Template: Jailbreak Indicator Monitor
Bundle ID: {bundle_id}

Usage:
  frida -U -f {bundle_id} -l {jailbreak_monitor_path} --no-pause
*/

var accessPtr = Module.findExportByName(null, "access");
if (accessPtr) {{
  Interceptor.attach(accessPtr, {{
    onEnter: function(args) {{
      var path = Memory.readUtf8String(args[0]);
      if (path && (
        path.indexOf("Cydia") >= 0 ||
        path.indexOf("Substrate") >= 0 ||
        path.indexOf("/bin/bash") >= 0 ||
        path.indexOf("/usr/sbin/sshd") >= 0 ||
        path.indexOf("frida") >= 0
      )) {{
        console.log("[jailbreak-path-check] access(" + path + ")");
      }}
    }}
  }});
  console.log("[+] Hooked access()");
}}
""")

    write_text(out_dir / "objection_workflow.txt", f"""iOSAssess Objection Runtime Workflow
================================================================================

Bundle ID:
{bundle_id}

Start Objection:
  objection -g {bundle_id} explore

Useful Commands:
  env
  ios plist cat
  ios bundles list_bundles
  memory list modules
  ios keychain dump
  ios cookies get
  ios nsuserdefaults get

Evidence to Capture:
  - Command used
  - Application state/workflow
  - Output showing relevant behavior
  - Screenshot or screen recording where appropriate
""")

    write_text(out_dir / "r2frida_workflow.txt", f"""iOSAssess r2frida Runtime Workflow
================================================================================

Bundle ID:
{bundle_id}

Start r2frida:
  r2 frida://usb//{bundle_id}

Useful Commands:
  i
  iE
  iS
  afl
  :objc.classes
  :objc.methods
""")

    write_text(out_dir / "lldb_workflow.txt", f"""iOSAssess LLDB Runtime Workflow
================================================================================

Bundle ID:
{bundle_id}

Start LLDB:
  lldb

Attach:
  process attach --name {bundle_id}

Useful Commands:
  image list
  image lookup -n <symbol>
  breakpoint set -n <function_or_method>
  continue
  thread backtrace
""")


def write_runtime_evidence_notes(path: Path, metadata: dict[str, Any]) -> None:
    bundle_id = _bundle(metadata)
    lines = [
        "iOSAssess Runtime Evidence Notes",
        "=" * 80,
        "",
        f"Bundle ID: {bundle_id}",
        "",
        "Recommended Evidence Format",
        "-" * 80,
        "Test Case ID:",
        "Tool Used:",
        "Command:",
        "Application State:",
        "Expected Result:",
        "Actual Result:",
        "Evidence File(s):",
        "Assessment Notes:",
        "",
        "Runtime Tooling Artifacts",
        "-" * 80,
        "- runtime_templates/frida_basic_hooks.js",
        "- runtime_templates/frida_url_monitor.js",
        "- runtime_templates/frida_keychain_monitor.js",
        "- runtime_templates/frida_webview_monitor.js",
        "- runtime_templates/frida_jailbreak_indicator_monitor.js",
        "- runtime_templates/objection_workflow.txt",
        "- runtime_templates/r2frida_workflow.txt",
        "- runtime_templates/lldb_workflow.txt",
        "",
    ]
    write_text(path, "\n".join(lines).rstrip() + "\n")
