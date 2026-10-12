import html
import json
from typing import Optional
from strikeprobe import __version__, __masvs_version__
from strikeprobe.models import ScanReport

# ANSI Colors for Developer Terminal Output
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
BLUE = "\033[38;2;66;133;244m"      # Google Antigravity Blue (#4285F4)
RED = "\033[38;2;255;59;48m"        # Apple Destructive Red (#FF3B30)
ORANGE = "\033[38;2;249;115;22m"
YELLOW = "\033[38;2;234;179;8m"
GREEN = "\033[38;2;34;197;94m"
CYAN = "\033[38;2;56;189;248m"
WHITE = "\033[97m"

SEVERITY_COLORS = {
    "Critical": RED,
    "High": ORANGE,
    "Medium": YELLOW,
    "Low": CYAN,
}


def print_banner():
    banner = f"""{BLUE}{BOLD}
   _____ __       _ __        ____             __        
  / ___// /______(_) /_____  / __ \\_________  / /_  ___  
  \\__ \\/ __/ ___/ / //_/ _ \\/ /_/ / ___/ __ \\/ __ \\/ _ \\ 
 ___/ / /_/ /  / / ,< /  __/ ____/ /  / /_/ / /_/ /  __/ 
/____/\\__/_/  /_/_/|_|\\___/_/   /_/   \\____/_.___/\\___/  
{RESET}{DIM}  StrikeProbe Developer CLI v{__version__} | OWASP MASVS v{__masvs_version__} | Zero-Retention SAST{RESET}
"""
    print(banner)


def render_terminal_report(report: ScanReport, min_severity: Optional[str] = None):
    print_banner()
    score_color = GREEN if report.security_score >= 80 else (YELLOW if report.security_score >= 55 else RED)

    print(f"{BOLD}{WHITE}+------------------------------------------------------------------------------+{RESET}")
    print(f"{BOLD}{WHITE}| TARGET METADATA & EPHEMERAL AUDIT SUMMARY                                    |{RESET}")
    print(f"{BOLD}{WHITE}+------------------------------------------------------------------------------+{RESET}")
    print(f"  {DIM}Target File     :{RESET} {BOLD}{report.target_name}{RESET} ({report.target_type.upper()})")
    print(f"  {DIM}SHA-256 Digest  :{RESET} {report.sha256}")
    print(f"  {DIM}Package Name    :{RESET} {report.package_name}")
    print(f"  {DIM}Version         :{RESET} {report.version_name} (Code: {report.version_code})")
    print(f"  {DIM}SDK Levels      :{RESET} minSdk={report.min_sdk} | targetSdk={report.target_sdk}")
    print(f"  {DIM}Scan Duration   :{RESET} {report.scan_duration_sec}s (Volatile RAM | Zero Database Storage)")
    print(
        f"  {DIM}Security Score  :{RESET} {score_color}{BOLD}{report.security_score}/100 (Grade {report.grade}){RESET}"
    )

    counts = report.severity_counts
    print(
        f"  {DIM}Findings Summary:{RESET} "
        f"{RED}{BOLD}Critical: {counts['Critical']}{RESET} | "
        f"{ORANGE}{BOLD}High: {counts['High']}{RESET} | "
        f"{YELLOW}Medium: {counts['Medium']}{RESET} | "
        f"{CYAN}Low: {counts['Low']}{RESET}"
    )
    print()

    # OWASP MASVS v2.0 Compliance Matrix
    print(f"{BOLD}{WHITE}+------------------------------------------------------------------------------+{RESET}")
    print(f"{BOLD}{WHITE}| OWASP MASVS v2.0 COMPLIANCE MATRIX                                           |{RESET}")
    print(f"{BOLD}{WHITE}+------------------------------------------------------------------------------+{RESET}")
    for cat, info in report.masvs_summary.items():
        status = info["status"]
        st_color = GREEN if status == "PASS" else (YELLOW if status == "WARN" else RED)
        badge = f"[{status:^4}]"
        print(f"  {st_color}{BOLD}{badge}{RESET}  {cat:<20} {DIM}({info['findings_count']} findings){RESET}")
    print()

    # Filter findings if requested
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold = sev_order.get(min_severity.lower(), 3) if min_severity else 3
    filtered = [
        f for f in report.findings if sev_order.get(f.severity.lower(), 3) <= threshold
    ]

    print(f"{BOLD}{WHITE}+------------------------------------------------------------------------------+{RESET}")
    print(f"{BOLD}{WHITE}| VULNERABILITY FINDINGS ({len(filtered):<3} shown)                                            |{RESET}")
    print(f"{BOLD}{WHITE}+------------------------------------------------------------------------------+{RESET}")

    if not filtered:
        print(f"  {GREEN}{BOLD}[OK] No vulnerabilities matching the selected severity threshold.{RESET}\n")
        return

    for idx, f in enumerate(filtered, 1):
        sc = SEVERITY_COLORS.get(f.severity, WHITE)
        loc = f"{f.affected_file}:{f.affected_line}" if f.affected_line else f.affected_file
        cwe_tag = f" | {f.cwe}" if f.cwe else ""
        print(
            f"  {BOLD}{idx:02d}. {sc}[{f.severity.upper()}]{RESET} {BOLD}{f.title}{RESET} "
            f"{DIM}({f.rule_id} | {f.masvs_category}{cwe_tag}){RESET}"
        )
        print(f"      {DIM}Location   :{RESET} {loc}")
        print(f"      {DIM}Evidence   :{RESET} {f.evidence}")
        print(f"      {DIM}Description:{RESET} {f.description}")
        if f.remediation:
            print(f"      {BLUE}Remediation:{RESET} {f.remediation}")
        print()


def to_json_report(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown_report(report: ScanReport) -> str:
    counts = report.severity_counts
    lines = [
        f"# 🛡️ StrikeProbe Developer Security Audit Report",
        "",
        f"- **Target**: `{report.target_name}` (`{report.target_type}`)",
        f"- **Package**: `{report.package_name}` (`v{report.version_name}`)",
        f"- **SHA-256**: `{report.sha256}`",
        f"- **Security Score**: **{report.security_score}/100 (Grade {report.grade})**",
        f"- **Findings**: Critical: `{counts['Critical']}` | High: `{counts['High']}` | Medium: `{counts['Medium']}` | Low: `{counts['Low']}`",
        "",
        "## OWASP MASVS v2.0 Compliance Summary",
        "| Category | Status | Findings |",
        "| :--- | :---: | :---: |",
    ]
    for cat, info in report.masvs_summary.items():
        lines.append(f"| `{cat}` | **{info['status']}** | {info['findings_count']} |")

    lines.extend(["", "## Detailed Vulnerability Findings", ""])
    if not report.findings:
        lines.append("_No security vulnerabilities detected._")
    else:
        for idx, f in enumerate(report.findings, 1):
            loc = f"{f.affected_file}:{f.affected_line}" if f.affected_line else f.affected_file
            lines.extend([
                f"### {idx}. [{f.severity.upper()}] {f.title}",
                f"- **Rule ID**: `{f.rule_id}` | **MASVS**: `{f.masvs_category}` | **CWE**: `{f.cwe or 'N/A'}`",
                f"- **Location**: `{loc}`",
                f"- **Evidence**: `{f.evidence}`",
                f"- **Description**: {f.description}",
                f"- **Remediation**: {f.remediation or 'Follow OWASP MASTG remediation guidance.'}",
                "",
            ])
    return "\n".join(lines)


def to_sarif_report(report: ScanReport) -> str:
    """Export findings in GitHub Code Scanning SARIF v2.1.0 format."""
    sarif_level = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    rules_map = {}
    results = []

    for f in report.findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation or f.description},
                "properties": {"tags": ["security", f.masvs_category, f.cwe] if f.cwe else ["security", f.masvs_category]},
            }
        results.append({
            "ruleId": f.rule_id,
            "level": sarif_level.get(f.severity, "warning"),
            "message": {"text": f"{f.description} (Evidence: {f.evidence})"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.affected_file},
                        "region": {"startLine": f.affected_line or 1},
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "StrikeProbe Developer CLI",
                        "version": __version__,
                        "informationUri": "https://github.com/ARASAN011/strikeprobe-cli",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def to_html_report(report: ScanReport) -> str:
    counts = report.severity_counts
    rows = []
    for f in report.findings:
        loc = f"{f.affected_file}:{f.affected_line}" if f.affected_line else f.affected_file
        rows.append(
            f"""
            <div class="card">
                <div class="row">
                    <span class="badge sev-{f.severity.lower()}">{html.escape(f.severity.upper())}</span>
                    <strong>{html.escape(f.title)}</strong>
                    <span class="meta">{html.escape(f.rule_id)} &bull; {html.escape(f.masvs_category)} {(' &bull; ' + html.escape(f.cwe)) if f.cwe else ''}</span>
                </div>
                <p>{html.escape(f.description)}</p>
                <div class="code"><strong>Location:</strong> {html.escape(loc)}<br/><strong>Evidence:</strong> {html.escape(f.evidence)}</div>
                {f'<p class="rem"><strong>Remediation:</strong> {html.escape(f.remediation)}</p>' if f.remediation else ''}
            </div>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>StrikeProbe Audit Report — {html.escape(report.target_name)}</title>
<style>
  body {{ background:#050507; color:#F5F5F7; font-family:-apple-system,BlinkMacSystemFont,'Inter',sans-serif; max-width:960px; margin:40px auto; padding:0 24px; }}
  h1, h2 {{ font-weight:700; letter-spacing:-0.02em; }}
  .hero {{ background:#0D0E12; border:1px solid rgba(255,255,255,0.08); border-radius:18px; padding:24px; margin-bottom:28px; }}
  .score {{ font-size:36px; font-weight:800; color:#4285F4; }}
  .card {{ background:#0D0E12; border:1px solid rgba(255,255,255,0.08); border-radius:14px; padding:18px; margin-bottom:14px; }}
  .row {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .meta {{ color:#71717A; font-size:12px; margin-left:auto; font-family:monospace; }}
  .badge {{ padding:3px 10px; border-radius:999px; font-size:11px; font-weight:700; }}
  .sev-critical {{ background:rgba(255,59,48,0.18); color:#FF3B30; border:1px solid rgba(255,59,48,0.4); }}
  .sev-high {{ background:rgba(249,115,22,0.18); color:#F97316; border:1px solid rgba(249,115,22,0.4); }}
  .sev-medium {{ background:rgba(234,179,8,0.18); color:#EAB308; border:1px solid rgba(234,179,8,0.4); }}
  .sev-low {{ background:rgba(56,189,248,0.18); color:#38BDF8; border:1px solid rgba(56,189,248,0.4); }}
  .code {{ background:rgba(255,255,255,0.03); padding:10px 12px; border-radius:8px; font-family:monospace; font-size:12px; color:#A1A1AA; }}
  .rem {{ color:#8AB4F8; font-size:13px; margin-bottom:0; }}
</style>
</head>
<body>
  <div class="hero">
    <h1>StrikeProbe Developer Security Audit</h1>
    <p><strong>Target:</strong> {html.escape(report.target_name)} &bull; <strong>Package:</strong> {html.escape(report.package_name)} &bull; <strong>SHA-256:</strong> <code>{report.sha256[:24]}...</code></p>
    <div class="score">{report.security_score}/100 (Grade {report.grade})</div>
    <p>Critical: {counts['Critical']} | High: {counts['High']} | Medium: {counts['Medium']} | Low: {counts['Low']}</p>
  </div>
  <h2>Findings ({len(report.findings)})</h2>
  {''.join(rows) if rows else '<p>No security findings detected.</p>'}
</body>
</html>"""
