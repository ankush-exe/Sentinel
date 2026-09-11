import argparse
import asyncio
import json

from sentinel_appsec.scan import scan_target


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel", description="Scan an OpenAPI service for BOLA/IDOR")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a target URL")
    scan_parser.add_argument("url", help="base URL of the target service")
    args = parser.parse_args()

    if args.command == "scan":
        report = asyncio.run(scan_target(args.url))
        print(json.dumps(report, indent=2))