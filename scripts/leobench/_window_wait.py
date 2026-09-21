#!/usr/bin/env python3
"""Seconds to wait before attempting Claude work; 0 when every window is usable.

Two stop conditions, not one:

  * utilisation at or above WINDOW_STOP_AT (default 0.90) in ANY unified window with its
    resetsAt still in the future. Claude exposes both five-hour and seven-day windows; checking
    only five_hour caused the scheduler to retry a fully exhausted weekly allowance every time
    the short window rolled over.
  * the primary rate-limit status is rejected, or overage is already in play.

Once a candidate resetsAt is in the past that window has rolled over, whatever utilisation was
logged. When several windows are spent, wait for the latest reset among them.
Override the threshold with WINDOW_STOP_AT, e.g. WINDOW_STOP_AT=0.98 to use more of it.
"""
import glob
import os
import re
import sys
import time

STOP_AT = float(os.environ.get("WINDOW_STOP_AT", "0.90"))
WINDOW = re.compile(
    r"'(five_hour|seven_day)': \{'utilization': ([0-9.]+), 'resetsAt': (\d+)\}"
)
PRIMARY = re.compile(
    r"RateLimitInfo\(status='([^']+)', resets_at=(\d+), rate_limit_type='[^']+'"
)
EVENT = re.compile(r"RateLimitInfo\([^\n]+")
OVERAGE = re.compile(r"'isUsingOverage': True")
logdir = sys.argv[1] if len(sys.argv) > 1 else "outputs/inscope/_genlogs"

now = time.time()
wait_until = []
for path in glob.glob(f"{logdir}/claude_*.log"):
    try:
        text = open(path, errors="replace").read()
    except OSError:
        continue
    for event in EVENT.findall(text):
        windows = [
            (float(m.group(2)), int(m.group(3))) for m in WINDOW.finditer(event)
        ]
        for utilization, ts in windows:
            if ts > now and utilization >= STOP_AT:
                wait_until.append(ts)
        primary = PRIMARY.search(event)
        if primary:
            status, ts = primary.group(1), int(primary.group(2))
            if ts > now and (status == "rejected" or OVERAGE.search(event)):
                wait_until.append(ts)

print(int(max(wait_until) - now) + 120 if wait_until else 0)
