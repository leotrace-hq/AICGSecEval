#!/usr/bin/env python3
"""run_coderabbit.py, the coderabbit arm (LEO-862): CodeRabbit's PR review on finished no-tool cycles.

CodeRabbit's main product reviews pull requests, so this arm works like run_deep_review.py (LEO-767)
and reuses its git and GitHub helpers. For each cycle of a no-tool batch
(generated_code/<llm>__<batch>/<instance>_cycleN):

  1. copy the cycle into the arm's batch dir (copy-on-write), and commit it as the fix round's base;
  2. open a PR on the task's private repo leotrace-benchmarking/ase-<instance> (main = the masked
     base the agent started from, harness/corridor/make_repos.py; tree-identical to the
     leotrace-hq copies Deep Review used) with the files the agent changed, as graded;
  3. wait for CodeRabbit's "CodeRabbit" check run on the head commit and its review. A rate-limited
     run (conclusion neutral) pauses every worker for the wait CodeRabbit names, then the harness
     asks for the review again with "@coderabbitai review" (a command, not a reply: the harness never
     replies to findings, replies feed CodeRabbit's learnings);
  4. if CodeRabbit left any finding (actionable, nitpick or outside-diff): one fix round, the same
     agent and model, through the container runtime on the raw arm, with the original task prompt and
     CodeRabbit's own "Prompt to fix all issues" hand-off (its text for coding agents; cleaned
     comments when a review has none). The fix is pushed to the PR; no re-review is awaited (the
     org setting auto_incremental_review is off, so the push does not spend a review);
  5. record coderabbit.json in the cycle's _security dir and close the PR (never merged).

The arm's batch dir is then graded by A.S.E's own security_scan, exactly like any other batch.
A cycle with no finding keeps the no-tool code unchanged.

Stops the whole run (exit 75, "LEOBENCH STOP") after STOP_AFTER cycles in a row end without a
review (timeout, skipped, error): an expired trial or a lost installation must not burn cells.
"""
import argparse
import concurrent.futures
import html
import json
import logging
import os
import re
import shutil
import sys
import threading
import time
from pathlib import Path

import run_deep_review as dr
from run_deep_review import changed_tracked_files, gh_json, push_branch, run, task_clone
from bench.agent import _container, _corridor
from bench.agent.claude_code import container_claude_policy

ORG = "leotrace-benchmarking"
# run_deep_review's helpers (task_clone, push_branch, gh lookups) read the module's ORG.
dr.ORG = ORG
APP = "coderabbitai"
BOT = "coderabbitai[bot]"
CHECK_NAME = "CodeRabbit"
ARM = "coderabbit"
REVIEW_TIMEOUT_S = 45 * 60
# After the check run completes, the review itself can land a little later.
REVIEW_SETTLE_S = 120
POLL_S = 20
RATE_LIMIT_PAD_S = 90
DEFAULT_RATE_LIMIT_WAIT_S = 15 * 60
MAX_RATE_LIMIT_RETRIES = 12
STOP_AFTER = 3
NO_REVIEW = ("review-timeout", "review-skipped", "rate-limited", "error")

FIX_PROMPT = dr.FIX_PROMPT

_throttle = threading.Lock()
_state = {"not_before": 0.0, "last_open": 0.0, "bad_streak": 0}
_stop = threading.Event()


# ---------------------------------------------------------------------------- parsing (pure)

def strip_markup(body):
    """CodeRabbit comment text as a reader sees it, minus the parts that are not feedback: HTML
    comments, icons, the analysis chain (the shell commands CodeRabbit ran), and review info."""
    s = body or ""
    s = re.sub(r"<!--.*?-->", "", s, flags=re.S)
    s = re.sub(r"<picture>.*?</picture>", "", s, flags=re.S)
    s = re.sub(r"<img[^>]*>", "", s)
    s = _drop_details(s, ("Supported by static analysis", "Analysis chain", "Review info",
                          "Review details", "Run configuration"))
    s = re.sub(r"</?(dl|dd|blockquote|br|h6)\s*/?>", "", s)
    s = re.sub(r"<summary>(.*?)</summary>", lambda m: "\n" + m.group(1).strip() + "\n", s, flags=re.S)
    s = re.sub(r"</?details>", "", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t]+\n", "\n", s)
    return re.sub(r"\n{3,}", "\n\n", s).strip()


def _drop_details(s, titles):
    """Remove whole <details> blocks whose <summary> contains one of `titles` (nesting-aware)."""
    out, i = [], 0
    while True:
        j = s.find("<details>", i)
        if j < 0:
            out.append(s[i:])
            return "".join(out)
        m = re.match(r"<details>\s*<summary>(.*?)</summary>", s[j:], flags=re.S)
        if not m or not any(t in m.group(1) for t in titles):
            out.append(s[i:j + len("<details>")])
            i = j + len("<details>")
            continue
        depth, k = 0, j
        while k < len(s):
            o, c = s.find("<details>", k), s.find("</details>", k)
            if c < 0:
                k = len(s)
                break
            if 0 <= o < c:
                depth, k = depth + 1, o + len("<details>")
            else:
                depth, k = depth - 1, c + len("</details>")
                if depth == 0:
                    break
        out.append(s[i:j])
        i = k


def details_block(body, title):
    """The text inside the first <details> whose summary contains `title` (fenced code only)."""
    m = re.search(r"<summary>[^\n]*?" + re.escape(title) + r"[^\n]*?</summary>(.*?)</details>",
                  body or "", flags=re.S)
    if not m:
        return None
    fence = re.search(r"```[a-z]*\n(.*?)```", m.group(1), flags=re.S)
    return (fence.group(1) if fence else strip_markup(m.group(1))).strip() or None


def _count(body, label):
    m = re.search(re.escape(label) + r"\**\s*[:(]\s*(\d+)", body or "")
    return int(m.group(1)) if m else 0


def review_counts(body):
    """Counts CodeRabbit states in a review body."""
    return {"actionable": _count(body, "Actionable comments posted"),
            "nitpick": _count(body, "Nitpick comments"),
            "outside_diff": _count(body, "Outside diff range comments"),
            "duplicate": _count(body, "Duplicate comments")}


SEVERITIES = ("Critical", "Major", "Minor", "Trivial", "Info")


def inline_meta(body):
    """Severity and category from an inline comment's header line, e.g.
    '**<picture>...</picture> Major** · **Security & Privacy** · **Heavy lift**'."""
    s = re.sub(r"<picture>.*?</picture>", "", body or "", flags=re.S)
    s = re.sub(r"<!--.*?-->", "", s, flags=re.S)
    m = re.search(r"\*\*\s*(" + "|".join(SEVERITIES) + r")\s*\*\*\s*·\s*\*\*([^*]+)\*\*", s)
    if m:
        return m.group(1), m.group(2).strip()
    m = re.search(r"(?<![A-Za-z])(" + "|".join(SEVERITIES) + r")(?![A-Za-z])", s[:400])
    return (m.group(1) if m else None), None


def rate_limit_wait_s(comment_body):
    """Seconds CodeRabbit says to wait, from 'available in 4 minutes' / 'wait **X minutes and Y
    seconds**'. None when the text names no wait."""
    s = re.sub(r"\*", "", comment_body or "")
    m = re.search(r"(?:available in|wait)\s+(?:(\d+)\s*hours?)?\s*(?:and\s*)?(?:(\d+)\s*minutes?)?"
                  r"\s*(?:and\s*)?(?:(\d+)\s*seconds?)?", s, flags=re.I)
    if not m or not any(m.groups()):
        return None
    h, mi, se = (int(g) if g else 0 for g in m.groups())
    return h * 3600 + mi * 60 + se


def has_findings(counts, inline):
    return bool(inline) or any(counts[k] for k in ("actionable", "nitpick", "outside_diff"))


def fix_text(reviews, inline):
    """What the fix round is told: the latest review's 'Prompt to fix all issues' (CodeRabbit's own
    hand-off to coding agents, covering inline, nitpick and outside-diff findings), else the cleaned
    comments."""
    for r in reversed(reviews):
        t = details_block(r.get("body"), "Prompt to fix all issues")
        if t:
            return "prompt-to-fix-all", t
    parts = []
    for i, c in enumerate(inline, 1):
        parts.append(f"Comment {i} ({c['path']} line {c['line']}):\n{strip_markup(c['body'])}")
    for r in reviews:
        b = strip_markup(r.get("body"))
        if b:
            parts.append(f"Review summary:\n{b}")
    return "comments", "\n\n".join(parts)


# ---------------------------------------------------------------------------- GitHub

def check_runs(repo, sha):
    runs = (gh_json([f"repos/{ORG}/{repo}/commits/{sha}/check-runs?check_name={CHECK_NAME}&filter=all"])
            or {}).get("check_runs", [])
    return sorted((c for c in runs if c.get("name") == CHECK_NAME
                   and (c.get("app") or {}).get("slug") == APP), key=lambda c: c["id"])


def bot_reviews(repo, pr, sha):
    return [r for r in gh_json([f"repos/{ORG}/{repo}/pulls/{pr}/reviews?per_page=100"]) or []
            if r.get("user", {}).get("login") == BOT and r.get("commit_id") == sha]


def bot_inline(repo, pr, sha):
    return [{"path": c.get("path"), "line": c.get("line") or c.get("original_line"),
             "body": c.get("body", ""), "id": c.get("id")}
            for c in gh_json([f"repos/{ORG}/{repo}/pulls/{pr}/comments?per_page=100"]) or []
            if c.get("user", {}).get("login") == BOT and c.get("commit_id") == sha
            and not c.get("in_reply_to_id")]


def bot_issue_comments(repo, pr):
    return [c for c in gh_json([f"repos/{ORG}/{repo}/issues/{pr}/comments?per_page=100"]) or []
            if c.get("user", {}).get("login") == BOT]


def _brief(c):
    return {"id": c["id"], "conclusion": c.get("conclusion"), "title": (c.get("output") or {}).get("title"),
            "started_at": c.get("started_at"), "completed_at": c.get("completed_at")}


def wait_for_review(repo, pr, sha, logger, cname):
    """Wait for a completed CodeRabbit run on `sha` that reviewed. Returns (status, runs), status one
    of reviewed, review-skipped, rate-limited, review-timeout. Rate-limited runs are retried."""
    deadline, seen, retries, history = time.time() + REVIEW_TIMEOUT_S, 0, 0, []
    while time.time() < deadline and not _stop.is_set():
        runs = [c for c in check_runs(repo, sha) if c["id"] > seen and c.get("status") == "completed"]
        if not runs:
            time.sleep(POLL_S)
            continue
        c = runs[-1]
        seen = c["id"]
        history.append(_brief(c))
        title = ((c.get("output") or {}).get("title") or "").lower()
        if c.get("conclusion") == "success":
            return "reviewed", history
        if "rate limit" in title or c.get("conclusion") == "neutral":
            retries += 1
            if retries > MAX_RATE_LIMIT_RETRIES:
                return "rate-limited", history
            notes = [x for x in bot_issue_comments(repo, pr) if "rate limited by coderabbit.ai" in x.get("body", "")]
            wait = rate_limit_wait_s(notes[-1]["body"]) if notes else None
            wait = DEFAULT_RATE_LIMIT_WAIT_S if wait is None else wait
            with _throttle:
                _state["not_before"] = max(_state["not_before"], time.time() + wait + RATE_LIMIT_PAD_S)
                until = _state["not_before"]
            logger.info(f"{cname}: rate limited, waiting {round(until - time.time())}s (retry {retries})")
            while time.time() < until and not _stop.is_set():
                time.sleep(min(30, max(1, until - time.time())))
            run(["gh", "api", "-X", "POST", f"repos/{ORG}/{repo}/issues/{pr}/comments",
                 "-f", "body=@coderabbitai review"])
            deadline = max(deadline, time.time() + REVIEW_TIMEOUT_S)
            continue
        return "review-skipped", history
    return "review-timeout", history


def collect(repo, pr, sha):
    """The review and inline comments on `sha`, waiting REVIEW_SETTLE_S for the review to land."""
    end = time.time() + REVIEW_SETTLE_S
    while True:
        reviews, inline = bot_reviews(repo, pr, sha), bot_inline(repo, pr, sha)
        if reviews or time.time() >= end:
            return reviews, inline
        time.sleep(10)


def open_slot(min_interval):
    """Pace PR openings: at most one per `min_interval` seconds, and none during a rate-limit wait."""
    while not _stop.is_set():
        with _throttle:
            now = time.time()
            ready = max(_state["not_before"], _state["last_open"] + min_interval)
            if now >= ready:
                _state["last_open"] = now
                return True
        time.sleep(min(30, max(1, ready - now)))
    return False


# ---------------------------------------------------------------------------- one cycle

def do_cycle(a, rec, src_cycle, logger):
    inst, cname = rec["instance_id"], src_cycle.name
    repo = _corridor.ase_name(inst)
    dst = a.out_batch / cname
    state = _corridor.state_dir_for(dst)
    done = state / "coderabbit.json"
    if done.is_file() and json.loads(done.read_text()).get("status") in ("clean", "fixed", "fix-failed", "no-change"):
        return json.loads(done.read_text())
    if _stop.is_set():
        return None
    t0 = time.time()
    record = {"instance_id": inst, "cycle": cname, "repo": f"{ORG}/{repo}", "agent": a.agent,
              "model": a.model, "source_batch": str(a.src_batch), "arm": ARM}
    # 1. the cycle copy and its records
    shutil.rmtree(dst, ignore_errors=True)
    shutil.rmtree(state, ignore_errors=True)
    run(["cp", "-c", "-R", str(src_cycle), str(dst)])
    shutil.rmtree(dst / "scan_outputs", ignore_errors=True)
    state.parent.mkdir(parents=True, exist_ok=True)
    run(["cp", "-c", "-R", str(_corridor.state_dir_for(src_cycle)), str(state)])
    for f in ("prompt.txt", "conversation.txt", "result.diff", "container_agent.json"):
        if (state / f).exists():
            (state / f).rename(state / f"notool.{f}")
    task_prompt = (state / "notool.prompt.txt").read_text(encoding="utf-8")
    run(["git", "init", "-q"], cwd=dst)
    run(["git", "add", "-A"], cwd=dst)
    run([*dr.GIT, "commit", "-q", "-m", "no-tool cycle"], cwd=dst)
    # 2. the PR: the graded tree's changes on top of the masked base
    clone = task_clone(a.cache, repo)
    files = changed_tracked_files(src_cycle, clone)
    record["pr_files"] = files
    if not files:
        record.update(status="no-change", elapsed_s=round(time.time() - t0))
        shutil.rmtree(dst / ".git", ignore_errors=True)
        done.write_text(json.dumps(record, indent=2), encoding="utf-8")
        logger.info(f"{cname}: no-change (the graded tree equals the masked base)")
        return record
    base, n = f"cell/{a.label}-{cname}", 0
    while True:
        branch = base if n == 0 else f"{base}-r{n}"
        existing = gh_json([f"repos/{ORG}/{repo}/pulls?head={ORG}:{branch}&state=all"]) or []
        if not existing or existing[0]["state"] == "open":
            break
        n += 1
    if not existing and not open_slot(a.min_interval):
        return None
    sha1 = push_branch(a.cache, repo, branch, "origin/main", f"Implement {rec['vuln_file']}",
                       files_from=src_cycle, files=files)
    title = f"Implement {Path(rec['vuln_file']).name}"
    if existing:
        pr = existing[0]["number"]
    else:
        pr = gh_json(["-X", "POST", f"repos/{ORG}/{repo}/pulls", "-f", f"title={title}",
                      "-f", f"head={branch}", "-f", "base=main",
                      "-f", f"body=Fills in {rec['vuln_file']}."])["number"]
    record.update(pr=pr, pr_url=f"https://github.com/{ORG}/{repo}/pull/{pr}", head_initial=sha1)
    # 3. the review
    status, runs = wait_for_review(repo, pr, sha1, logger, cname)
    record["review_runs"] = runs
    if status != "reviewed":
        record.update(status=status, elapsed_s=round(time.time() - t0),
                      bot_notes=[strip_markup(c["body"])[:2000] for c in bot_issue_comments(repo, pr)])
        return finish(a, repo, pr, state, record, logger)
    reviews, inline = collect(repo, pr, sha1)
    counts = {"actionable": 0, "nitpick": 0, "outside_diff": 0, "duplicate": 0}
    for r in reviews:
        for k, v in review_counts(r.get("body")).items():
            counts[k] += v
    for c in inline:
        c["severity"], c["category"] = inline_meta(c["body"])
    record.update(reviews=[{"id": r["id"], "state": r.get("state"), "body": r.get("body", "")} for r in reviews],
                  inline=inline, counts=counts,
                  # One inline comment can carry several actionable findings (pilot 2026-11-11: 2 in 1).
                  delivered=max(len(inline), counts["actionable"]) + counts["nitpick"] + counts["outside_diff"],
                  severities=[c["severity"] for c in inline], categories=[c["category"] for c in inline])
    if not has_findings(counts, inline):
        record.update(status="clean", elapsed_s=round(time.time() - t0))
        return finish(a, repo, pr, state, record, logger)
    # 4. the fix round
    source, text = fix_text(reviews, inline)
    record["fix_input"] = {"source": source, "text": text}
    prompt = FIX_PROMPT.format(task=task_prompt.strip(), comments=text)
    rt = _container.ContainerRuntime(
        a.agent, "raw", None, dst, a.model, logger, effort=a.effort, auth="subscription",
        env_file=a.env_file, leobench_home=a.leobench_home,
        claude_policy=container_claude_policy("raw", None) if a.agent == "claude" else None)
    ok = False
    try:
        ok = rt.run(prompt, rec["vuln_file"])
    except _container.ContainerRuntimeError as e:
        record["fix_error"] = str(e)
    res = rt.result or {}
    record["fix_round"] = {"status": res.get("status"), "returncode": res.get("returncode"),
                           "elapsed_s": res.get("elapsed_s"), "ok": ok}
    run(["git", "add", "-A"], cwd=dst)
    fix = run(["git", "diff", "--cached", "--binary", "HEAD"], cwd=dst).stdout
    record["fix_changed_files"] = [ln[6:] for ln in fix.splitlines() if ln.startswith("+++ b/")]
    if not ok or res.get("status") not in ("ok", "empty"):
        record.update(status="fix-failed", elapsed_s=round(time.time() - t0))
        return finish(a, repo, pr, state, record, logger)
    if fix.strip():
        record["head_final"] = push_branch(a.cache, repo, branch, sha1, "Address review comments", patch=fix)
    record.update(status="fixed", elapsed_s=round(time.time() - t0))
    return finish(a, repo, pr, state, record, logger)


def finish(a, repo, pr, state, record, logger):
    run(["gh", "api", "-X", "PATCH", f"repos/{ORG}/{repo}/pulls/{pr}", "-f", "state=closed"], check=False)
    dst = a.out_batch / record["cycle"]
    shutil.rmtree(dst / ".git", ignore_errors=True)
    (state / "coderabbit.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    logger.info(f"{record['cycle']}: {record['status']} findings={record.get('delivered', 0)} "
                f"{record.get('counts', '')} {record.get('elapsed_s')}s {record.get('pr_url', '')}")
    return record


def note_outcome(status, logger):
    with _throttle:
        _state["bad_streak"] = _state["bad_streak"] + 1 if status in NO_REVIEW else 0
        if _state["bad_streak"] >= STOP_AFTER and not _stop.is_set():
            logger.error(f"LEOBENCH STOP: {_state['bad_streak']} cycles in a row without a CodeRabbit "
                         f"review (last: {status}); check the trial, the installation and the rate limit")
            _stop.set()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src-batch", required=True, type=Path,
                    help="the no-tool batch dir (generated_code/<llm>__<batch>)")
    ap.add_argument("--out-batch", required=True, type=Path,
                    help="the arm's batch dir (generated_code/<llm>__<agent>_coderabbit)")
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--agent", required=True, choices=["claude", "codex"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--label", required=True, help="branch label, e.g. opus55")
    ap.add_argument("--effort")
    ap.add_argument("--env-file", default=os.environ.get("LEOPREVENT_ENV_FILE"))
    ap.add_argument("--leobench-home", default=os.environ.get("LEOBENCH_HOME"))
    ap.add_argument("--cache", type=Path, required=True, help="task repo clones")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--min-interval", type=float, default=360,
                    help="seconds between PR openings (360 = 10/hour, the Advanced plan's PR rate)")
    ap.add_argument("--only", nargs="*", help="cycle names to run (default all)")
    a = ap.parse_args()
    a.src_batch, a.out_batch, a.cache = (p.resolve() for p in (a.src_batch, a.out_batch, a.cache))
    a.out_batch.mkdir(parents=True, exist_ok=True)
    a.cache.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(a.out_batch.parent / f"{a.out_batch.name}.log")])
    logger = logging.getLogger("coderabbit")
    data = {r["instance_id"].lower(): r for r in json.loads(Path(a.dataset).read_text())}
    cycles = sorted(p for p in a.src_batch.iterdir()
                    if p.is_dir() and re.fullmatch(r".+_cycle\d+", p.name)
                    and p.name.rsplit("_cycle", 1)[0].lower() in data)
    if a.only:
        cycles = [p for p in cycles if p.name in a.only]
    # Only cycles A.S.E counts as generated: a failed or unfinished source cycle is not in the source
    # batch's processed_instances.json (or has success false) and is never graded there either.
    src_done = {k.lower(): v for k, v in json.loads((a.src_batch / "processed_instances.json").read_text()).items()
                if v.get("success")}
    missing = [p.name for p in cycles if p.name.lower() not in src_done]
    if missing:
        logger.info(f"skipping {len(missing)} cycles the source batch did not generate: {missing}")
    cycles = [p for p in cycles if p.name.lower() in src_done]
    logger.info(f"{len(cycles)} cycles from {a.src_batch} -> {a.out_batch} (org {ORG})")
    with concurrent.futures.ThreadPoolExecutor(a.workers) as ex:
        futs = {ex.submit(do_cycle, a, data[p.name.rsplit("_cycle", 1)[0].lower()], p, logger): p
                for p in cycles}
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
                if r:
                    note_outcome(r["status"], logger)
            except Exception as e:  # one cycle's failure never stops the others
                logger.error(f"{futs[f].name}: ERROR {e}")
                note_outcome("error", logger)
    recs = [json.loads(p.read_text()) for p in (a.out_batch / "_security").glob("*/coderabbit.json")]
    by = {}
    for r in recs:
        by[r["status"]] = by.get(r["status"], 0) + 1
    # A.S.E's security_scan grades the cycles listed in the batch's processed_instances.json.
    final = {r["cycle"].lower() for r in recs if r["status"] in ("clean", "fixed", "fix-failed", "no-change")}
    # every recorded cycle of the batch, not only this invocation's (--only must not drop earlier cycles)
    names = {p.name.lower(): p.name for p in a.src_batch.iterdir() if p.is_dir()}
    proc = {names[c]: src_done[c] for c in sorted(final) if c in src_done and c in names}
    (a.out_batch / "processed_instances.json").write_text(json.dumps(proc, indent=2), encoding="utf-8")
    logger.info(f"done: {len(recs)}/{len(cycles)} recorded {by}")
    if _stop.is_set():
        sys.exit(75)


if __name__ == "__main__":
    main()
