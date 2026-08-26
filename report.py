import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from .models import Finding


def score_findings(findings: List[Finding]) -> Tuple[int, int, int]:
    total_possible = sum(f.weight for f in findings if f.weight > 0)
    evaluated = [f for f in findings if f.weight > 0 and f.status != "UNKNOWN"]
    evaluated_possible = sum(f.weight for f in evaluated)
    earned = sum(f.points for f in evaluated)
    return earned, evaluated_possible, total_possible


def rating(earned: int, possible: int) -> str:
    if possible <= 0:
        return "Unknown"
    pct = round((earned / possible) * 100)
    if pct >= 90:
        return "Strong"
    if pct >= 75:
        return "Good"
    if pct >= 60:
        return "Needs Improvement"
    return "High Risk"


def build_payload(system: Dict[str, str], findings: List[Finding]) -> Dict:
    earned, evaluated_possible, total_possible = score_findings(findings)
    score = round((earned / evaluated_possible) * 100) if evaluated_possible else None
    coverage = round((evaluated_possible / total_possible) * 100) if total_possible else None
    return {
        "tool": "SecureOps macOS Security Audit",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "system": system,
        "summary": {
            "score": score,
            "earned_points": earned,
            "evaluated_points": evaluated_possible,
            "total_possible_points": total_possible,
            "coverage": coverage,
            "rating": rating(earned, evaluated_possible),
            "pass": sum(1 for f in findings if f.status == "PASS"),
            "fail": sum(1 for f in findings if f.status == "FAIL"),
            "warn": sum(1 for f in findings if f.status == "WARN"),
            "unknown": sum(1 for f in findings if f.status == "UNKNOWN"),
            "info": sum(1 for f in findings if f.status == "INFO"),
        },
        "findings": [f.to_dict() for f in findings],
        "disclaimer": (
            "This tool performs a point-in-time, read-only configuration review. "
            "It does not prove that a system is secure, compliant, compromise-free, or suitable for a specific regulatory requirement."
        ),
    }


def write_json(payload: Dict, path: Path) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_markdown(payload: Dict, path: Path) -> None:
    s = payload["system"]
    summary = payload["summary"]
    findings = payload["findings"]

    lines = [
        "# macOS Security Audit Report",
        "",
        f"**Generated:** {payload['generated_at']}  ",
        f"**Tool version:** {payload['version']}  ",
        f"**Read-only audit:** Yes",
        "",
        "## Executive Summary",
        "",
        f"**Security score:** {summary['score']}/100  ",
        f"**Rating:** {summary['rating']}  ",
        f"**Audit coverage:** {summary['coverage']}%  ",
        f"**Results:** {summary['pass']} pass, {summary['fail']} fail, {summary['warn']} warning, {summary['unknown']} unknown",
        "",
        "## System",
        "",
        f"- Hostname: `{s['hostname']}`",
        f"- Current user: `{s['current_user']}`",
        f"- macOS: `{s['macos_version']}` (`{s['macos_build']}`)",
        f"- Architecture: `{s['architecture']}`",
        f"- Model: `{s['model']}`",
        f"- Chip/CPU: `{s['chip']}`",
        "",
        "## Findings",
        "",
        "| ID | Control | Category | Result | Severity | Points |",
        "|---|---|---|---|---|---:|",
    ]

    for f in findings:
        points = "Info" if f["weight"] == 0 else f"{f['points']}/{f['weight']}"
        lines.append(f"| {f['id']} | {f['title']} | {f['category']} | **{f['status']}** | {f['severity']} | {points} |")

    lines.extend(["", "## Detailed Findings", ""])

    for f in findings:
        lines.extend([
            f"### {f['id']} — {f['title']}",
            "",
            f"**Result:** {f['status']}  ",
            f"**Severity:** {f['severity']}  ",
            f"**Observed:** {f['observed']}",
            "",
            f"**Recommendation:** {f['recommendation']}",
            "",
        ])
        if f.get("evidence"):
            safe_evidence = str(f["evidence"]).replace("```", "`` `")
            lines.extend(["**Evidence:**", "", "```text", safe_evidence, "```", ""])

    lines.extend([
        "## Important Limitations",
        "",
        payload["disclaimer"],
        "",
        "A managed configuration profile can override settings that are not obvious from a user's local preferences. "
        "Future versions should correlate configuration profiles and MDM state before making stronger policy conclusions.",
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")
