import argparse
import sys
from datetime import datetime
from pathlib import Path

from .checks import run_all_checks, system_info
from .report import build_payload, write_json, write_markdown


def parse_args():
    parser = argparse.ArgumentParser(
        prog="secureops-audit",
        description="Read-only macOS security configuration audit.",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Directory for JSON and Markdown reports (default: reports)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Print summary only; do not write report files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        findings = run_all_checks()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    payload = build_payload(system_info(), findings)
    summary = payload["summary"]

    print("SecureOps macOS Security Audit v0.1.0")
    print("-------------------------------------")
    print(f"Host:   {payload['system']['hostname']}")
    print(f"macOS:  {payload['system']['macos_version']} ({payload['system']['macos_build']})")
    score_text = f"{summary['score']}/100" if summary['score'] is not None else "Unavailable"
    print(f"Score:  {score_text} — {summary['rating']}")
    print(f"Coverage: {summary['coverage']}%")
    print()

    for finding in findings:
        points = "INFO" if finding.weight == 0 else f"{finding.points}/{finding.weight}"
        print(f"[{finding.status:7}] {finding.id} {finding.title} ({points})")

    if not args.no_report:
        output_dir = Path(args.output_dir).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = f"macos-security-audit-{stamp}"
        json_path = output_dir / f"{base}.json"
        md_path = output_dir / f"{base}.md"
        write_json(payload, json_path)
        write_markdown(payload, md_path)
        print()
        print(f"JSON report:     {json_path}")
        print(f"Markdown report: {md_path}")

    return 0
