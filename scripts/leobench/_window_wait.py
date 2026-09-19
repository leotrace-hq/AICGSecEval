#!/usr/bin/env python3
"""Seconds to wait before attempting Claude work; 0 when the window is usable.

Two stop conditions, not one:

  * utilisation at or above WINDOW_STOP_AT (default 0.90) with resetsAt still in the future.
    The five-hour cap is NOT a hard ceiling -- once it is reached the subscription spends
    paid usage credits and the run simply carries on billing. Waiting at 90% leaves headroom
    so an in-flight batch cannot tip over the wall and start charging.
  * overage already in play (overage_status set to anything but 'allowed', or isUsingOverage).

Once resetsAt is in the past the window has rolled over, whatever utilisation was logged.
Override the threshold with WINDOW_STOP_AT, e.g. WINDOW_STOP_AT=0.98 to use more of it.
"""
import glob
import json
import os
import re
import sys
import time

STOP_AT = float(os.environ.get("WINDOW_STOP_AT", "0.90"))
REC = re.compile(r"'five_hour': \{'utilization': ([0-9.]+), 'resetsAt': (\d+)\}")
OVR = re.compile(r"'isUsingOverage': (True|False)")
logdir = sys.argv[1] if len(sys.argv) > 1 else "outputs/inscope/_genlogs"

newest = None
using_overage = False
for path in glob.glob(f"{logdir}/claude_*.log"):
    try:
        text = open(path, errors="replace").read()
    except OSError:
        continue
    for m in REC.finditer(text):
        ts = int(m.group(2))
        if newest is None or ts >= newest[1]:
            newest = (float(m.group(1)), ts)
    for m in OVR.finditer(text):
        if m.group(1) == "True":
            using_overage = True

if newest is None:
    print(0)
elif newest[1] <= time.time():
    print(0)                                   # window rolled over
elif newest[0] >= STOP_AT or using_overage:
    print(int(newest[1] - time.time()) + 120)  # wait out the window
else:
    print(0)
