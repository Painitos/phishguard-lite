from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import AnalysisResult, analyze_many, analyze_url
from .report import render_html_report
from .server import run_server


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Analyze URLs for phishing-like risk signals.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single URL")
    analyze_parser.add_argument("url")
    analyze_parser.add_argument("--json", action="store_true", help="Print JSON output")

    batch_parser = subparsers.add_parser("batch", help="Analyze URLs from a text file")
    batch_parser.add_argument("file", type=Path)
    batch_parser.add_argument("--json", action="store_true", help="Print JSON output")

    report_parser = subparsers.add_parser("report", help="Create an HTML report")
    report_parser.add_argument("file", type=Path)
    report_parser.add_argument("--output", "-o", type=Path, default=Path("report.html"))

    serve_parser = subparsers.add_parser("serve", help="Start the local web interface")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    if args.command == "analyze":
        result = analyze_url(args.url)
        _print_result(result, as_json=args.json)
        return 0

    if args.command == "batch":
        results = analyze_many(args.file.read_text(encoding="utf-8").splitlines())
        _print_many(results, as_json=args.json)
        return 0

    if args.command == "report":
        results = analyze_many(args.file.read_text(encoding="utf-8").splitlines())
        args.output.write_text(render_html_report(results), encoding="utf-8")
        print(f"Report written to {args.output}")
        return 0

    if args.command == "serve":
        run_server(args.host, args.port)
        return 0

    parser.error("Unknown command")
    return 2


def _print_result(result: AnalysisResult, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    print(f"URL: {result.normalized_url}")
    print(f"Risk score: {result.score}/100")
    print(f"Risk level: {result.risk_level}")
    if not result.findings:
        print("No phishing-like indicators found.")
        return

    print()
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.message}")


def _print_many(results: list[AnalysisResult], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps([result.to_dict() for result in results], indent=2))
        return

    for result in results:
        print(f"{result.score:3}/100 {result.risk_level:6} {result.normalized_url}")


if __name__ == "__main__":
    raise SystemExit(main())
