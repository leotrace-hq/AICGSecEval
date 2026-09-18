#!/usr/bin/env python3
"""Seconds to wait before attempting Claude work, 0 if the window is usable.

If the newest five_hour record we logged shows a spent window whose resetsAt is still in the
future, the current window is still spent and waiting beats burning a pass through the cohort.
Once resetsAt is in the past the window has rolled over, whatever utilisation the log shows.
"""
import glob
import re
import sys
import time

PAT = re.compile(r"'five_hour': \{'utilization': ([0-9.]+), 'resetsAt': (\d+)\}")
logdir = sys.argv[1] if len(sys.argv) > 1 else "outputs/inscope/_genlogs"

newest = None
for path in glob.glob(f"{logdir}/claude_*.log"):
    try:
        text = open(path, errors="replace").read()
    except OSError:
        continue
    for m in PAT.finditer(text):
        ts = int(m.group(2))
        if newest is None or ts >= newest[1]:
            newest = (float(m.group(1)), ts)

if newest and newest[0] >= 0.98 and newest[1] > time.time():
    print(int(newest[1] - time.time()) + 120)
else:
    print(0)
