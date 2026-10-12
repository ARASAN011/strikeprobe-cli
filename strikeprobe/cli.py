import argparse
import os
import sys
from strikeprobe import __version__, __masvs_version__
from strikeprobe.analyzer import StrikeProbeAnalyzer, load_rules
from strikeprobe.reporter import (
    print_banner,
    render_terminal_report,
    to_html_report,
    to_json_report,
    to_markdown_report,
    to_sarif_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strikeprobe",
        description="StrikeProbe Developer CLI — Zero-Retention Android APK & Source Code SAST Scanner (OWASP MASVS v2.0)",
    )
    subparsers = parser.add_subparsers(dest="command")

    # `strikeprobe scan <target>`
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a local, zero-retention OWASP MASVS security audit on an .apk, .zip, or source folder",
    )
    scan_parser.add_argument(
        "target",
        help="Path to Android .apk binary, .zip source archive, or project directory",
    )
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["terminal", "json", "markdown", "sarif", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to save the exported report (.json, .md, .sarif, .html)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Minimum severity level to display in terminal output",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
        help="Exit with non-zero code (1) if findings at or above this severity exist (for CI/CD pipelines)",
    )

    # `strikeprobe rules`
    subparsers.add_parser(
        "rules",
        help="List all loaded OWASP MASVS v2.0 static analysis rules",
    )

    # `strikeprobe version`
    subparsers.add_parser(
        "version",
        help="Display StrikeProbe CLI and OWASP MASVS version information",
    )

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    analyzer = StrikeProbeAnalyzer()
    try:
        report = analyzer.scan_target(args.target)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "terminal" or not args.output:
        if args.format == "terminal":
            render_terminal_report(report, min_severity=args.severity)
        elif args.format == "json":
            print(to_json_report(report))
        elif args.format == "markdown":
            print(to_markdown_report(report))
        elif args.format == "sarif":
            print(to_sarif_report(report))
        elif args.format == "html":
            print(to_html_report(report))

    if args.output:
        out_path = os.path.abspath(args.output)
        ext = os.path.splitext(out_path)[1].lower()
        if args.format == "json" or ext == ".json":
            payload = to_json_report(report)
        elif args.format == "sarif" or ext == ".sarif":
            payload = to_sarif_report(report)
        elif args.format == "html" or ext == ".html":
            payload = to_html_report(report)
        else:
            payload = to_markdown_report(report)

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(payload)

        if args.format == "terminal":
            print(f"  [+] Exported developer report to: {out_path}\n")

    # CI/CD Gate check (--fail-on)
    if args.fail_on and args.fail_on != "none":
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        gate_level = rank[args.fail_on.lower()]
        breaches = [
            f for f in report.findings if rank.get(f.severity.lower(), 4) <= gate_level
        ]
        if breaches:
            print(
                f"  [!] CI/CD Security Gate Failed: {len(breaches)} finding(s) at or above '{args.fail_on.upper()}' severity.",
                file=sys.stderr,
            )
            return 1

    return 0


def cmd_rules() -> int:
    print_banner()
    rules = load_rules()
    print(f"Loaded {len(rules)} OWASP MASVS v{__masvs_version__} SAST Rules:\n")
    for r in rules:
        print(
            f"  * [{r.get('id')}] ({r.get('severity')}) {r.get('title')} - {r.get('category')} ({r.get('cwe', 'N/A')})"
        )
    print()
    return 0


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "rules":
        return cmd_rules()
    elif args.command == "version":
        print(f"StrikeProbe Developer CLI v{__version__} (OWASP MASVS v{__masvs_version__})")
        return 0
    else:
        print_banner()
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
