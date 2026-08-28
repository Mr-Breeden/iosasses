#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

from modules.ipa_extract import validate_ipa, extract_ipa, find_app_bundle, find_main_executable
from modules.utils import read_plist, write_text
from modules.plist_review import get_bundle_metadata, get_url_schemes, get_associated_domains, review_plist
from modules.ats_review import review_ats
from modules.entitlements import extract_entitlements, review_entitlements
from modules.binary_metadata import collect_binary_metadata
from modules.reports import write_findings_summary, write_findings, write_metadata, write_module_status
from modules.test_cases import generate_test_cases
from modules.mastg_mapping import write_mastg_mapping, write_evidence_checklist
from modules.runtime_templates import write_runtime_templates, write_runtime_evidence_notes
from modules.storage_review import write_storage_review_reports
from modules.runtime_evidence import write_runtime_evidence_template
from modules.memory_analysis import write_memory_analysis_workflows
from modules.static_triage import run_static_triage, write_static_triage_summary

VERSION = "1.0.1"
console = Console()


def banner() -> None:
    console.print(Panel.fit(f"[bold]iOSAssess v{VERSION}[/bold]\niOS Security Assessment Framework"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="iOSAssess iOS Security Assessment Framework")
    parser.add_argument("-i", "--ipa", help="Path to IPA file")
    parser.add_argument("-o", "--output", default=None, help="Output directory. Default: ./assessments")
    parser.add_argument("-n", "--assessment-name", help="Assessment folder name. Default: timestamp")
    parser.add_argument("-e", "--environment", choices=["physical", "simulator", "1", "2"], help="Testing environment: physical/1 or simulator/2. Default: physical.")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    return parser.parse_args()


def get_inputs(args: argparse.Namespace) -> tuple[Path, Path, str, str]:
    if args.ipa:
        ipa_path = Path(os.path.expanduser(args.ipa)).resolve()
    else:
        ipa_input = prompt("IPA Path: ", completer=PathCompleter(expanduser=True))
        ipa_path = Path(os.path.expanduser(ipa_input)).resolve()

    default_name = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    assessment_name = args.assessment_name
    if not assessment_name:
        entered = prompt(f"Assessment Name [{default_name}]: ")
        assessment_name = entered.strip() or default_name

    if args.output:
        output_dir = Path(os.path.expanduser(args.output)).resolve()
    else:
        default_output = "./assessments"
        output_input = prompt(f"Assessment Output Directory [{default_output}]: ").strip() or default_output
        output_dir = Path(os.path.expanduser(output_input)).resolve()

    environment = args.environment
    if environment:
        environment = environment.strip().lower()
    else:
        console.print()
        console.print("Testing Environment")
        console.print("1. Physical iPhone/iPad")
        console.print("2. iOS Simulator")
        selected = prompt("Select testing environment [1]: ").strip() or "1"
        environment = selected.lower()

    environment_map = {
        "1": "physical",
        "physical": "physical",
        "device": "physical",
        "iphone": "physical",
        "ipad": "physical",
        "2": "simulator",
        "simulator": "simulator",
        "sim": "simulator",
    }
    environment = environment_map.get(environment, "physical")

    return ipa_path, output_dir, assessment_name, environment


def add_status(statuses: list[tuple[str, str, str]], name: str, status: str, detail: str = "") -> None:
    statuses.append((name, status, detail))
    color = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}.get(status, "white")
    console.print(f"{name:.<28}[{color}]{status}[/]")


def write_info_plist_review(path: Path, metadata: dict, url_schemes: list, associated_domains: list) -> None:
    lines = ["Info.plist Review", "=" * 80, ""]
    for key, value in metadata.items():
        lines.append(f"{key}: {value}")
    lines += ["", "URL Schemes", "-" * 80]
    if url_schemes:
        for entry in url_schemes:
            lines.append(f"Name: {entry.get('name')}")
            lines.append(f"Role: {entry.get('role')}")
            lines.append(f"Schemes: {', '.join(entry.get('schemes', []))}")
            lines.append("")
    else:
        lines.append("No custom URL schemes identified.")
        lines.append("")
    lines += ["Associated Domains / Universal Links", "-" * 80]
    if associated_domains:
        for domain in associated_domains:
            lines.append(f"- {domain}")
    else:
        lines.append("No associated domains identified.")
    write_text(path, "\n".join(lines) + "\n")


def write_entitlements_review(path: Path, entitlements: dict, raw_output: str) -> None:
    lines = ["Entitlements Review", "=" * 80, ""]
    if entitlements:
        for key, value in sorted(entitlements.items()):
            lines.append(f"{key}: {value}")
    else:
        lines += ["No parsed entitlements were recovered.", "", "Raw codesign output:", raw_output or "No output"]
    write_text(path, "\n".join(lines) + "\n")


def write_url_schemes(path: Path, url_schemes: list, associated_domains: list) -> None:
    lines = ["URL Schemes and Associated Domains", "=" * 80, "", "Custom URL Schemes", "-" * 80]
    if url_schemes:
        for entry in url_schemes:
            schemes = entry.get("schemes", [])
            lines.append(f"{entry.get('name') or '<unnamed>'}: {', '.join(schemes)}")
    else:
        lines.append("None identified.")
    lines += ["", "Associated Domains", "-" * 80]
    if associated_domains:
        for d in associated_domains:
            lines.append(f"- {d}")
    else:
        lines.append("None identified.")
    write_text(path, "\n".join(lines) + "\n")


def print_summary(metadata: dict, url_schemes: list, associated_domains: list) -> None:
    table = Table(title="iOS Application Summary")
    table.add_column("Field")
    table.add_column("Value")
    for key in ["display_name", "bundle_id", "version", "build", "minimum_os", "executable"]:
        table.add_row(key, str(metadata.get(key) or ""))
    console.print(table)

    if url_schemes or associated_domains:
        link_table = Table(title="URL / Link Entry Points")
        link_table.add_column("Type")
        link_table.add_column("Value")
        for entry in url_schemes:
            for scheme in entry.get("schemes", []):
                link_table.add_row("URL Scheme", f"{scheme}://")
        for domain in associated_domains:
            link_table.add_row("Associated Domain", domain)
        console.print(link_table)


def main() -> None:
    args = parse_args()
    if args.version:
        print(VERSION)
        return

    banner()
    ipa_path, output_dir, assessment_name, testing_environment = get_inputs(args)
    statuses: list[tuple[str, str, str]] = []
    findings: list[dict] = []

    ok, message = validate_ipa(ipa_path)
    if not ok:
        console.print(f"[red][!] {message}[/]")
        raise SystemExit(1)
    console.print(f"[green][+] {message}[/]")

    project_dir = output_dir / assessment_name
    reports_dir = project_dir / "reports"
    inventory_dir = reports_dir / "inventory"
    extract_dir = project_dir / "extracted"
    inventory_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green][+] Project Directory:[/] {project_dir}")
    console.print(f"[green][+] Testing Environment:[/] {testing_environment}")

    try:
        extract_ipa(ipa_path, extract_dir)
        app_path = find_app_bundle(extract_dir)
        add_status(statuses, "IPA Extraction", "PASS", str(app_path))
    except Exception as exc:
        add_status(statuses, "IPA Extraction", "FAIL", str(exc))
        write_module_status(reports_dir / "module_status.txt", statuses)
        raise

    info_path = app_path / "Info.plist"
    if not info_path.exists():
        add_status(statuses, "Info.plist Review", "FAIL", "Info.plist not found")
        raise SystemExit(1)

    plist = read_plist(info_path)
    metadata = get_bundle_metadata(plist)
    url_schemes = get_url_schemes(plist)

    entitlements, raw_entitlements = extract_entitlements(app_path)
    associated_domains = get_associated_domains(plist, entitlements)

    findings.extend(review_plist(plist))
    write_info_plist_review(inventory_dir / "info_plist_review.txt", metadata, url_schemes, associated_domains)
    write_url_schemes(inventory_dir / "url_schemes.txt", url_schemes, associated_domains)
    add_status(statuses, "Info.plist Review", "PASS")

    ats_findings, ats_report = review_ats(plist)
    findings.extend(ats_findings)
    write_text(inventory_dir / "ats_review.txt", ats_report)
    add_status(statuses, "ATS Review", "PASS")

    ent_findings = review_entitlements(entitlements)
    findings.extend(ent_findings)
    write_entitlements_review(inventory_dir / "entitlements_review.txt", entitlements, raw_entitlements)
    add_status(statuses, "Entitlements Review", "PASS" if entitlements else "WARN", "No parsed entitlements" if not entitlements else "")

    binary_path = find_main_executable(app_path, plist)
    write_text(inventory_dir / "binary_metadata.txt", collect_binary_metadata(binary_path))
    add_status(statuses, "Binary Metadata", "PASS" if binary_path else "WARN", "Main executable not found" if not binary_path else str(binary_path))

    static_triage_dir = reports_dir / "static_triage"
    static_triage_summary = run_static_triage(app_path, binary_path, static_triage_dir)
    write_static_triage_summary(reports_dir / "static_triage_summary.txt", static_triage_summary, static_triage_dir)
    add_status(statuses, "Static Triage", "PASS" if static_triage_summary else "WARN", "No static triage indicators identified" if not static_triage_summary else "")

    metadata_out = {
        "tool": "iOSAssess",
        "tool_version": VERSION,
        "ipa_path": str(ipa_path),
        "project_dir": str(project_dir),
        "app_path": str(app_path),
        **metadata,
        "url_scheme_count": sum(len(e.get("schemes", [])) for e in url_schemes),
        "associated_domains": associated_domains,
        "testing_environment": testing_environment,
        "static_triage_count": len(static_triage_summary),
    }

    print_summary(metadata, url_schemes, associated_domains)
    generate_test_cases(reports_dir / "test_cases.txt", metadata, url_schemes, associated_domains, testing_environment)
    add_status(statuses, "Test Case Generation", "PASS")

    write_findings_summary(reports_dir / "findings_summary.txt", metadata_out, findings)
    write_findings(reports_dir / "findings.txt", findings)
    write_metadata(reports_dir / "assessment_metadata.json", metadata_out)
    write_storage_review_reports(reports_dir / "storage_review", app_path, metadata, testing_environment)
    add_status(statuses, "Storage Review", "PASS")

    write_memory_analysis_workflows(reports_dir / "memory_analysis", metadata, testing_environment)
    add_status(statuses, "Memory Analysis Workflows", "PASS")

    write_runtime_templates(reports_dir / "runtime_templates", metadata)
    write_runtime_evidence_notes(reports_dir / "runtime_templates" / "runtime_evidence_notes.txt", metadata)
    write_runtime_evidence_template(reports_dir / "runtime_templates" / "runtime_evidence_template.txt")
    add_status(statuses, "Runtime Templates", "PASS")

    write_mastg_mapping(reports_dir / "mastg_mapping.txt")
    write_evidence_checklist(reports_dir / "evidence_checklist.txt")
    add_status(statuses, "MASTG Mapping", "PASS")
    write_module_status(reports_dir / "module_status.txt", statuses)

    console.print("[green][+] Assessment completed[/]")
    console.print(f"[green][+] Reports:[/] {reports_dir}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
