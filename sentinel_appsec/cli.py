import argparse
import asyncio
import json
import sys

import httpx

from sentinel_appsec.scan import scan_target


def run_scan(url: str) -> int:
    try:
        report = asyncio.run(scan_target(url))
    except (httpx.HTTPError, ValueError) as exc:
        print(f"sentinel: scan failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel", description="Scan an OpenAPI service for BOLA/IDOR")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a target URL")
    scan_parser.add_argument("url", help="base URL of the target service")
    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(run_scan(args.url))