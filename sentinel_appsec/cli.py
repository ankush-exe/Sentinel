import argparse
import asyncio
import json
import sys

import httpx

from sentinel_appsec.scan import scan_target


def print_report(report: dict) -> None:
    print("\nSentinel Security Scan")
    print(f"Target: {report['target_url']}")
    print(f"Endpoints scanned: {report['scanned_endpoints']}\n")

    for finding in report["findings"]:
        print(f"[!] {finding['risk']} RISK - {finding['title']}")
        print(f"    Endpoint: {finding['method']} {finding['endpoint']}")
        print(f"    Issue: {finding['violating_user']} accessed {finding['owner']}'s resource")
        print(f"    Evidence: {finding['evidence_summary']}")
        print(f"    Suggestion: {finding['suggestion']}")
        print(f"    Regression test: {finding['regression_test_path']}\n")

    clean_count = report["scanned_endpoints"] - report["vulnerability_count"]
    print(
        f"Summary: {report['vulnerability_count']} high-risk findings, "
        f"{clean_count} endpoints clean"
    )


def run_scan(url: str, json_output: bool = False) -> int:
    try:
        report = asyncio.run(scan_target(url))
    except (httpx.HTTPError, ValueError) as exc:
        print(f"sentinel: scan failed: {exc}", file=sys.stderr)
        return 1
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel", description="Scan an OpenAPI service for BOLA/IDOR")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a target URL")
    scan_parser.add_argument("url", help="base URL of the target service")
    scan_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(run_scan(args.url, json_output=args.json))