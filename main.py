"""
main.py
-------
Basic Antivirus Simulation (Signature Scanner) -- SOC-relevant edition

Scans a target folder, hashes every file, compares against a local
signature database and (optionally) VirusTotal, logs every scan,
writes JSON alert reports, sends email/Slack notifications on
detection, and can generate a static HTML dashboard summarizing all
scans to date.

Usage:
    python main.py <target_folder> [--quarantine] [--sig-db signatures.json]
                    [--vt-check] [--api-key YOUR_KEY]
                    [--notify-email] [--notify-slack]
                    [--dashboard]

Example:
    python main.py ./test_files --quarantine --vt-check --dashboard
"""

import argparse
import json
import os
import sys
import time

from scanner import scan_directory
from quarantine import quarantine_file
from logger import setup_logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_signatures(sig_db_path):
    """Load the known-malware signature database from a JSON file."""
    if not os.path.exists(sig_db_path):
        print(f"[!] Signature database not found: {sig_db_path}")
        sys.exit(1)

    with open(sig_db_path, "r") as f:
        data = json.load(f)

    return {k: v for k, v in data.items() if not k.startswith("_")}


def load_config():
    """Load config.json if present, else return an empty dict."""
    config_path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def load_api_key(cli_api_key, config):
    if cli_api_key:
        return cli_api_key
    key = config.get("virustotal_api_key", "").strip()
    return key or None


def run_scan(target_dir, signatures, do_quarantine, quarantine_dir,
             logger, vt_enabled, api_key):
    total_scanned = 0
    matches = []

    logger.info(f"Scan started on target: {target_dir}")
    print(f"\n[*] Scanning: {target_dir}")
    print(f"[*] Loaded {len(signatures)} known signatures\n")

    vt_check_hash = None
    if vt_enabled:
        from vt_checker import check_hash_virustotal
        vt_check_hash = check_hash_virustotal
        if not api_key:
            print("[!] --vt-check was passed but no API key was found. "
                  "VirusTotal checks will be skipped.\n")

    for file_path, file_hash in scan_directory(target_dir):
        total_scanned += 1

        if file_hash in signatures:
            label = signatures[file_hash]
            matches.append({
                "file": file_path,
                "hash": file_hash,
                "source": "local_signature_db",
                "label": label,
            })
            print(f"  [MALICIOUS]  {file_path}")
            print(f"               hash:  {file_hash}")
            print(f"               match: {label} (local signature DB)")
            logger.warning(
                f"MALICIOUS (local DB) | file={file_path} | hash={file_hash} | label={label}"
            )

            if do_quarantine:
                new_path = quarantine_file(file_path, quarantine_dir)
                if new_path:
                    print(f"               -> quarantined to: {new_path}")
                    logger.info(f"Quarantined | {file_path} -> {new_path}")
            continue

        if vt_enabled and api_key:
            vt_result = vt_check_hash(file_hash, api_key)
            if vt_result["checked"] and vt_result["found"] and vt_result["malicious_count"] > 0:
                label = f"VirusTotal: {vt_result['message']}"
                matches.append({
                    "file": file_path,
                    "hash": file_hash,
                    "source": "virustotal",
                    "label": label,
                })
                print(f"  [MALICIOUS]  {file_path}")
                print(f"               hash:  {file_hash}")
                print(f"               match: {label}")
                logger.warning(
                    f"MALICIOUS (VirusTotal) | file={file_path} | hash={file_hash} | {vt_result['message']}"
                )

                if do_quarantine:
                    new_path = quarantine_file(file_path, quarantine_dir)
                    if new_path:
                        print(f"               -> quarantined to: {new_path}")
                        logger.info(f"Quarantined | {file_path} -> {new_path}")
                continue
            elif not vt_result["checked"]:
                print(f"  [clean]      {file_path}  (VT check skipped: {vt_result['message']})")
                logger.info(f"clean | {file_path} | VT skipped: {vt_result['message']}")
                continue

        print(f"  [clean]      {file_path}")
        logger.info(f"clean | {file_path} | hash={file_hash}")

    print("\n" + "=" * 60)
    print(f"Scan complete: {total_scanned} file(s) scanned, "
          f"{len(matches)} match(es) found")
    if do_quarantine and matches:
        print(f"Flagged files moved to: {quarantine_dir}")
    print("=" * 60 + "\n")

    logger.info(f"Scan finished | scanned={total_scanned} | matches={len(matches)}")

    return matches


def write_alert_report(matches, report_dir):
    if not matches:
        return None

    os.makedirs(report_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_path = os.path.join(report_dir, f"alert_report_{timestamp}.json")

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts": len(matches),
        "alerts": matches,
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return report_path


def send_notifications(matches, target_dir, config, logger, notify_email, notify_slack):
    if not matches:
        return
    if not (notify_email or notify_slack):
        return

    from notifier import send_email_alert, send_slack_alert

    if notify_email:
        ok, msg = send_email_alert(matches, target_dir, config.get("email"))
        print(f"[*] Email notification: {msg}")
        logger.info(f"Email notification: {msg}")

    if notify_slack:
        webhook = config.get("slack_webhook_url")
        ok, msg = send_slack_alert(matches, target_dir, webhook)
        print(f"[*] Slack notification: {msg}")
        logger.info(f"Slack notification: {msg}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulation - Signature-based file scanner"
    )
    parser.add_argument("target", nargs="?", help="Folder to scan")
    parser.add_argument(
        "--sig-db",
        default=os.path.join(BASE_DIR, "signatures.json"),
        help="Path to the signatures JSON database (default: signatures.json)",
    )
    parser.add_argument("--quarantine", action="store_true",
                         help="Move detected malicious files to the quarantine folder")
    parser.add_argument("--quarantine-dir", default=os.path.join(BASE_DIR, "quarantine"),
                         help="Folder to move flagged files into (default: ./quarantine)")
    parser.add_argument("--vt-check", action="store_true",
                         help="Also check unmatched file hashes against VirusTotal")
    parser.add_argument("--api-key", default=None,
                         help="VirusTotal API key (overrides config.json)")
    parser.add_argument("--report-dir", default=os.path.join(BASE_DIR, "reports"),
                         help="Folder to write JSON alert reports into (default: ./reports)")
    parser.add_argument("--notify-email", action="store_true",
                         help="Send an email alert if detections are found (needs config.json)")
    parser.add_argument("--notify-slack", action="store_true",
                         help="Send a Slack alert if detections are found (needs config.json)")
    parser.add_argument("--dashboard", action="store_true",
                         help="Regenerate dashboard.html from all reports after scanning")
    parser.add_argument("--dashboard-only", action="store_true",
                         help="Skip scanning; just regenerate dashboard.html from existing reports")

    args = parser.parse_args()

    logger, log_path = setup_logger(BASE_DIR)
    config = load_config()

    if args.dashboard_only:
        from dashboard_generator import generate_dashboard
        dash_path = generate_dashboard(args.report_dir, os.path.join(BASE_DIR, "dashboard.html"))
        print(f"[*] Dashboard regenerated: {dash_path}")
        return

    if not args.target:
        print("[!] A target folder is required unless using --dashboard-only")
        sys.exit(1)

    if not os.path.isdir(args.target):
        print(f"[!] Target folder does not exist: {args.target}")
        sys.exit(1)

    print(f"[*] Logging to: {log_path}")

    signatures = load_signatures(args.sig_db)
    api_key = load_api_key(args.api_key, config)

    matches = run_scan(
        args.target, signatures, args.quarantine, args.quarantine_dir,
        logger, args.vt_check, api_key
    )

    report_path = write_alert_report(matches, args.report_dir)
    if report_path:
        print(f"[*] Alert report written to: {report_path}")
        logger.info(f"Alert report written: {report_path}")

    send_notifications(matches, args.target, config, logger,
                        args.notify_email, args.notify_slack)

    if args.dashboard:
        from dashboard_generator import generate_dashboard
        dash_path = generate_dashboard(args.report_dir, os.path.join(BASE_DIR, "dashboard.html"))
        print(f"[*] Dashboard updated: {dash_path}")
        logger.info(f"Dashboard updated: {dash_path}")


if __name__ == "__main__":
    main()
