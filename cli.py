import argparse
import json
import sys
from .core import HarSanitizer
from .scanner import HarSecurityScanner

def main():
    parser = argparse.ArgumentParser(
        prog="harguard",
        description="HarGuard: Enterprise HTTP Archive (HAR) Security Sanitizer and Session Guard"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Sanitize Command
    san_parser = subparsers.add_parser("sanitize", help="Sanitize a HAR file and remove session tokens")
    san_parser.add_argument("input_file", help="Path to input .har file")
    san_parser.add_argument("-o", "--output", help="Path to output sanitized .har file", required=False)
    san_parser.add_argument("--strip-all-cookies", action="store_true", help="Redact all cookies, not just session cookies")
    san_parser.add_argument("--salt", help="Custom salt for deterministic token hashing", default=None)

    # Scan / Audit Command
    scan_parser = subparsers.add_parser("scan", help="Audit a HAR file for exposed credentials and session risk")
    scan_parser.add_argument("input_file", help="Path to input .har file")
    scan_parser.add_argument("--json", action="store_true", help="Output audit results in JSON format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "sanitize":
        try:
            with open(args.input_file, "r", encoding="utf-8") as f:
                har_data = json.load(f)
        except Exception as e:
            print(f"Error reading {args.input_file}: {e}", file=sys.stderr)
            sys.exit(1)

        sanitizer = HarSanitizer(salt=args.salt, redact_all_cookies=args.strip_all_cookies)
        cleaned = sanitizer.sanitize_har(har_data)

        out_path = args.output or args.input_file.replace(".har", ".sanitized.har")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(cleaned, f, indent=2)

        print(f"[✓] Sanitization complete: {out_path}")
        print(f"[✓] Redacted {len(sanitizer.redaction_log)} sensitive artifacts (Session tokens, Cookies, Auth headers)")

    elif args.command == "scan":
        try:
            with open(args.input_file, "r", encoding="utf-8") as f:
                har_data = json.load(f)
        except Exception as e:
            print(f"Error reading {args.input_file}: {e}", file=sys.stderr)
            sys.exit(1)

        scanner = HarSecurityScanner()
        report = scanner.scan(har_data)

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("==================================================")
            print("         HARGUARD SECURITY SCAN REPORT           ")
            print("==================================================")
            print(f"Risk Rating:    {report['risk_score']}")
            print(f"Total Findings: {report['total_findings']}")
            print("Breakdown by Category:")
            for cat, count in report['findings_by_type'].items():
                print(f"  - {cat:25s}: {count}")
            print("==================================================")
            if report['total_findings'] > 0:
                print("WARNING: This HAR file contains sensitive tokens that could permit session hijacking!")
                print("Execute 'harguard sanitize' before uploading or sharing this file.")
                sys.exit(2)
            else:
                print("Status: CLEAN. No obvious credentials or session cookies identified.")
                sys.exit(0)

if __name__ == "__main__":
    main()
