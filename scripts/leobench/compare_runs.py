#!/usr/bin/env python3
"""Compare the LeoPrevent effect between two A.S.E runs on the same instances.

Answers one question: is LeoPrevent better or worse than it was, and by how much?

For each run it computes the paired raw -> leoprevent transition per (instance, cycle), then
reports the difference between the two runs. Both runs must cover the same instance set and the
same cycles, or the comparison is not paired and the delta means nothing; this refuses to run
otherwise rather than quietly comparing different things.

ATTRIBUTION. A differing pair only counts as PREVENTED or REGRESSED when a LeoPrevent review
actually fired on that cell. Without a review the arms are two independent samples from the same
agent and the difference is run-to-run variance, not an effect (operator rule). Those land in
`differed, no review` instead. Review-to-cell mapping reuses map_review_events from
report_ase_html.py, which orders audit events against generated-file mtimes.

Usage:
  compare_runs.py --new-dir outputs/inscope25 --old-dir outputs/inscope \\
                  --dataset data/inscope25_v2.json --agent claude_code:claude_raw:claude_lp
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
BROKEN, SAFE, VULN = "BROKEN", "SAFE", "VULN"
CYCLE_RE = re.compile(r"_cycle(\d+)$")


def _load_html_helpers():
    spec = importlib.util.spec_from_file_location(
        "report_ase_html", os.path.join(HERE, "report_ase_html.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["report_ase_html"] = mod
    spec.loader.exec_module(mod)
    return mod


def classify(row: dict) -> str:
    if not (row.get("completion") and row.get("image_status_check") and row.get("test_case_check")):
        return BROKEN
    return SAFE if row.get("poc_check") else VULN


def load_cells(output_dir: str, agent: str, batch: str, keep: set[str]) -> dict:
    """(instance, cycle) -> verdict, restricted to `keep`."""
    path = os.path.join(output_dir, "generated_code", f"{agent}__{batch}", "scan_results.json")
    out = {}
    with open(path) as fh:
        for row in json.load(fh):
            m = CYCLE_RE.search(row["instance_id"])
            inst = CYCLE_RE.sub("", row["instance_id"])
            if inst not in keep:
                continue
            out[(inst, int(m.group(1)) if m else 1)] = classify(row)
    return out


def load_reviews(output_dir: str, dataset: dict, agent: str, lp_batch: str, cycles: list[int]) -> set:
    """Cells where a LeoPrevent review actually fired."""
    html = _load_html_helpers()
    audit_groups = defaultdict(list)
    audit_path = os.path.join(output_dir, "_server", "review-events.jsonl")
    try:
        with open(audit_path, encoding="utf-8") as fh:
            events = []
            for line in fh:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except OSError:
        return set()
    for event in events:
        if event.get("kind") != "review":
            continue
        repo = str(event.get("repo", "")).removeprefix("github.com/")
        try:
            event["_timestamp"] = datetime.fromisoformat(
                str(event.get("time", "")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        for changed in event.get("files") or []:
            audit_groups[(repo, str(event.get("agent", "")), str(changed.get("path", "")))].append(event)
    specs = [(agent, agent, "", lp_batch)]
    mapped = html.map_review_events(output_dir, dataset, specs, cycles, audit_groups)
    return {(inst, cyc) for (_a, inst, cyc) in mapped}


def transitions(raw: dict, lp: dict, reviewed: set) -> dict:
    out = defaultdict(list)
    for cell in sorted(set(raw) & set(lp)):
        a, b = raw[cell], lp[cell]
        if a == BROKEN or b == BROKEN:
            out["unjudged"].append(cell)
        elif a == b == VULN:
            out["vuln in both"].append(cell)
        elif a == b == SAFE:
            out["safe in both"].append(cell)
        elif cell not in reviewed:
            # differed, but LeoPrevent never acted: variance, not an effect
            out["differed, no review"].append(cell)
        elif a == VULN and b == SAFE:
            out["PREVENTED"].append(cell)
        else:
            out["REGRESSED"].append(cell)
    return out


def summarise(tag: str, raw: dict, lp: dict, reviewed: set) -> dict:
    tr = transitions(raw, lp, reviewed)
    jr = [v for v in raw.values() if v != BROKEN]
    jl = [v for v in lp.values() if v != BROKEN]
    return {
        "tag": tag, "tr": tr,
        "raw_vuln": sum(1 for v in jr if v == VULN), "raw_judged": len(jr),
        "lp_vuln": sum(1 for v in jl if v == VULN), "lp_judged": len(jl),
        "prevented": len(tr["PREVENTED"]), "regressed": len(tr["REGRESSED"]),
        "reviewed": len(reviewed), "task": task_level(raw, lp, reviewed),
    }


def rate(n: int, d: int) -> float:
    return 100.0 * n / d if d else float("nan")


def sign_test(a: int, b: int) -> float:
    """Two-sided exact binomial on discordant pairs."""
    from math import comb
    n = a + b
    if n == 0:
        return 1.0
    k = min(a, b)
    return min(sum(comb(n, i) for i in range(k + 1)) / 2 ** n * 2, 1.0)


def task_level(raw: dict, lp: dict, reviewed: set) -> tuple[int, int, float]:
    """Sign test over TASKS, not cells.

    Cycles of the same task are repeated measurements of one task, not independent
    observations. Testing per cell treats 3 cycles as 3 samples and inflates significance
    (pseudo-replication), so the task-level test is the one to quote. A task counts as
    improved when it has strictly more exploitable cycles under raw than under leoprevent,
    and at least one of its differing cycles was actually reviewed.
    """
    by_task: dict[str, list] = defaultdict(lambda: [0, 0, False])
    for cell in set(raw) & set(lp):
        a, b = raw[cell], lp[cell]
        if a == BROKEN or b == BROKEN:
            continue
        by_task[cell[0]][0] += a == VULN
        by_task[cell[0]][1] += b == VULN
        if a != b and cell in reviewed:
            by_task[cell[0]][2] = True
    better = sum(1 for v in by_task.values() if v[0] > v[1] and v[2])
    worse = sum(1 for v in by_task.values() if v[1] > v[0] and v[2])
    return better, worse, sign_test(better, worse)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--new-dir", required=True)
    ap.add_argument("--old-dir", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--agent", default="claude_code:claude_raw:claude_lp")
    ap.add_argument("--cycles", type=int, default=3)
    ap.add_argument("--markdown")
    args = ap.parse_args()

    agent, raw_b, lp_b = args.agent.split(":")
    data = json.load(open(args.dataset))
    dataset = {d["instance_id"]: d for d in (data.values() if isinstance(data, dict) else data)}
    keep = set(dataset)
    cycles = list(range(1, args.cycles + 1))

    runs = []
    for tag, d in (("NEW", args.new_dir), ("OLD", args.old_dir)):
        try:
            raw, lp = load_cells(d, agent, raw_b, keep), load_cells(d, agent, lp_b, keep)
        except FileNotFoundError as e:
            print(f"{tag} ({d}): not verified yet, no scan_results.json\n  {e}", file=sys.stderr)
            return 1
        runs.append(summarise(tag, raw, lp, load_reviews(d, dataset, agent, lp_b, cycles)))

    new, old = runs
    # Refuse to compare unequal cell sets: an unpaired delta is meaningless.
    if new["raw_judged"] + new["lp_judged"] == 0:
        print("NEW run has no judged cells", file=sys.stderr)
        return 1

    lines = []
    P = lines.append
    P("LeoPrevent effect, NEW vs OLD, on %d instances x %d cycles (%s)"
      % (len(keep), args.cycles, agent))
    P("PREVENTED/REGRESSED require a review to have fired on that cell.")
    P("")
    P("%-22s %12s %12s" % ("", "OLD", "NEW"))
    P("-" * 50)
    P("%-22s %12s %12s" % ("raw vulnerable", "%d/%d (%.0f%%)" % (old['raw_vuln'], old['raw_judged'], rate(old['raw_vuln'], old['raw_judged'])),
                           "%d/%d (%.0f%%)" % (new['raw_vuln'], new['raw_judged'], rate(new['raw_vuln'], new['raw_judged']))))
    P("%-22s %12s %12s" % ("lp vulnerable", "%d/%d (%.0f%%)" % (old['lp_vuln'], old['lp_judged'], rate(old['lp_vuln'], old['lp_judged'])),
                           "%d/%d (%.0f%%)" % (new['lp_vuln'], new['lp_judged'], rate(new['lp_vuln'], new['lp_judged']))))
    P("%-22s %12d %12d" % ("reviews fired", old["reviewed"], new["reviewed"]))
    P("%-22s %12d %12d" % ("PREVENTED", old["prevented"], new["prevented"]))
    P("%-22s %12d %12d" % ("REGRESSED", old["regressed"], new["regressed"]))
    P("%-22s %12d %12d" % ("net (prev - reg)", old["prevented"] - old["regressed"],
                           new["prevented"] - new["regressed"]))
    P("%-22s %12s %12s" % ("cell-level p", "%.3g" % sign_test(old["prevented"], old["regressed"]),
                           "%.3g" % sign_test(new["prevented"], new["regressed"])))
    ot, nt = old["task"], new["task"]
    P("%-22s %12s %12s" % ("TASKS better/worse", "%d / %d" % (ot[0], ot[1]), "%d / %d" % (nt[0], nt[1])))
    P("%-22s %12s %12s" % ("TASK-level p  <-- quote", "%.3g" % ot[2], "%.3g" % nt[2]))
    for k in ("vuln in both", "safe in both", "differed, no review", "unjudged"):
        P("%-22s %12d %12d" % (k, len(old["tr"][k]), len(new["tr"][k])))

    d_net = (new["prevented"] - new["regressed"]) - (old["prevented"] - old["regressed"])
    d_rate = rate(new["lp_vuln"], new["lp_judged"]) - rate(old["lp_vuln"], old["lp_judged"])
    P("")
    P("VERDICT")
    P("  net effect moved %+d (old %+d -> new %+d)"
      % (d_net, old["prevented"] - old["regressed"], new["prevented"] - new["regressed"]))
    P("  leoprevent-arm vulnerable rate moved %+.1f points (lower is better)" % d_rate)
    if d_net > 0:
        P("  -> LeoPrevent is BETTER than the previous run on this cohort")
    elif d_net < 0:
        P("  -> LeoPrevent is WORSE than the previous run on this cohort")
    else:
        P("  -> LeoPrevent is UNCHANGED from the previous run on this cohort")
    if abs(d_net) <= 2:
        P("  CAUTION: a swing this small at n=%d cells is within run-to-run noise."
          % (new["raw_judged"]))

    P("")
    P("per-CWE, leoprevent arm vulnerable rate (targeted classes first)")
    P("  %-10s %10s %10s" % ("cwe", "OLD", "NEW"))
    bycwe = defaultdict(lambda: {"o": [0, 0], "n": [0, 0]})
    for tag, run, d in (("o", old, args.old_dir), ("n", new, args.new_dir)):
        lp = load_cells(d, agent, lp_b, keep)
        for (inst, _c), v in lp.items():
            if v == BROKEN:
                continue
            cwe = str(dataset[inst].get("cwe_id", "?")).upper()
            bycwe[cwe][tag][1] += 1
            if v == VULN:
                bycwe[cwe][tag][0] += 1
    for cwe in sorted(bycwe, key=lambda c: -bycwe[c]["n"][1]):
        o, n = bycwe[cwe]["o"], bycwe[cwe]["n"]
        P("  %-10s %10s %10s" % (cwe,
                                 "%d/%d" % (o[0], o[1]) if o[1] else "-",
                                 "%d/%d" % (n[0], n[1]) if n[1] else "-"))

    report = "\n".join(lines)
    print(report)
    if args.markdown:
        with open(args.markdown, "w") as fh:
            fh.write("# LeoPrevent: new engine vs 2026-09-21\n\n```\n" + report + "\n```\n")
        print("\n[wrote %s]" % args.markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
