#!/usr/bin/env python3
"""
log_analyzer.py — SSH Auth Log Brute-Force Detector
-----------------------------------------------------
Reads a Linux-style /var/log/auth.log file and flags two things a SOC
analyst would actually be paged for:

  1. BRUTE-FORCE PATTERN — one IP racking up N+ failed logins inside a
     short time window.
  2. POSSIBLE COMPROMISE — a SUCCESSFUL login from an IP that was just
     flagged for brute-forcing (i.e. they eventually got in).

Usage:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py sample_auth.log --threshold 4 --window 5

How it works (for explaining out loud):
    - Parse each line with a regex into (timestamp, status, user, ip).
    - Group failed attempts by source IP.
    - Slide a time-window over each IP's failed attempts; if >= THRESHOLD
      failures fall inside WINDOW_MINUTES, raise a brute-force alert.
    - Cross-check successful logins against recent brute-force IPs to
      catch attempts that eventually succeeded.
"""

import re
import argparse
from datetime import datetime
from collections import defaultdict

LOG_YEAR = 2026  # syslog lines have no year; auth.log rotates yearly on most systems

LINE_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+\s+ssh2$"
)


def parse_line(line):
    """Return (datetime, status, user, ip) for a matching line, else None."""
    m = LINE_PATTERN.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(
        f"{LOG_YEAR} {m.group('month')} {m.group('day')} {m.group('time')}",
        "%Y %b %d %H:%M:%S",
    )
    return ts, m.group("status"), m.group("user"), m.group("ip")


def load_events(path):
    """Parse the whole file into a list of (datetime, status, user, ip)."""
    events = []
    skipped = 0
    with open(path) as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                events.append(parsed)
            elif line.strip():
                skipped += 1
    events.sort(key=lambda e: e[0])
    return events, skipped


def find_brute_force(events, threshold, window_minutes):
    """
    Sliding-window scan per IP: return a dict {ip: alert_info} for any IP
    with >= threshold failed logins inside any window_minutes span.
    """
    failures_by_ip = defaultdict(list)
    for ts, status, user, ip in events:
        if status == "Failed":
            failures_by_ip[ip].append((ts, user))

    alerts = {}
    window = window_minutes * 60  # seconds

    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda a: a[0])
        left = 0
        for right in range(len(attempts)):
            while (attempts[right][0] - attempts[left][0]).total_seconds() > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                users_tried = sorted({u for _, u in attempts[left:right + 1]})
                alerts[ip] = {
                    "start": attempts[left][0],
                    "end": attempts[right][0],
                    "count": count,
                    "users_tried": users_tried,
                }
                break  # one alert per IP is enough to report

    return alerts


def find_possible_compromise(events, brute_force_alerts, grace_minutes=30):
    """
    Flag a successful login from an IP that has a brute-force alert and
    the success happened at or after the brute-force window, within a
    grace period (covers 'kept trying, then got in').
    """
    compromises = []
    for ts, status, user, ip in events:
        if status != "Accepted" or ip not in brute_force_alerts:
            continue
        window_end = brute_force_alerts[ip]["end"]
        delta_minutes = (ts - window_end).total_seconds() / 60
        if 0 <= delta_minutes <= grace_minutes:
            compromises.append({"ip": ip, "user": user, "time": ts})
    return compromises


def print_report(brute_force_alerts, compromises, skipped):
    print("=" * 60)
    print("LOG ANALYSIS REPORT")
    print("=" * 60)

    if not brute_force_alerts:
        print("\nNo brute-force patterns detected.")
    else:
        print(f"\n[!] {len(brute_force_alerts)} BRUTE-FORCE ALERT(S)\n")
        for ip, info in brute_force_alerts.items():
            print(f"  Source IP     : {ip}")
            print(f"  Failed count  : {info['count']} attempts")
            print(f"  Window        : {info['start'].strftime('%H:%M:%S')} - "
                  f"{info['end'].strftime('%H:%M:%S')}")
            print(f"  Usernames hit : {', '.join(info['users_tried'])}")
            print("-" * 40)

    if compromises:
        print(f"\n[!!] {len(compromises)} POSSIBLE COMPROMISE ALERT(S) "
              f"(successful login after brute-force)\n")
        for c in compromises:
            print(f"  CRITICAL: {c['ip']} logged in as '{c['user']}' at "
                  f"{c['time'].strftime('%H:%M:%S')} shortly after a brute-force burst")
            print("-" * 40)

    if skipped:
        print(f"\n({skipped} unparsed line(s) in the log ignored)")

    print()


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in an auth.log file.")
    parser.add_argument("logfile", help="Path to the auth.log-style file")
    parser.add_argument("--threshold", type=int, default=4,
                         help="Failed attempts from one IP to trigger an alert (default: 4)")
    parser.add_argument("--window", type=int, default=5,
                         help="Time window in minutes to count attempts within (default: 5)")
    args = parser.parse_args()

    events, skipped = load_events(args.logfile)
    brute_force_alerts = find_brute_force(events, args.threshold, args.window)
    compromises = find_possible_compromise(events, brute_force_alerts)
    print_report(brute_force_alerts, compromises, skipped)


if __name__ == "__main__":
    main()