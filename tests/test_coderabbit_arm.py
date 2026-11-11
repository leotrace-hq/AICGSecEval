"""Tests for run_coderabbit.py's parsing of CodeRabbit's GitHub output (no network).

The bodies below are SYNTHETIC, written in the shapes CodeRabbit used on public PRs in November 2026:
a review whose body counts actionable and nitpick comments and carries a "Prompt to fix all issues"
block, inline comments with a "**Severity** · **Category** · **Effort**" header, and a rate-limit
note naming the wait.

    .venv/bin/python -m unittest tests.test_coderabbit_arm
"""
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_coderabbit as cr  # noqa: E402

ICON = '<picture><source media="(prefers-color-scheme: dark)" srcset="x-dark.svg"><img src="x.svg" width="16" height="16" alt=""></picture>'

REVIEW = f"""<!-- coderabbit-ai-generated:v1 -->

**Actionable comments posted: 2**

<details>
<summary>{ICON} Nitpick comments: 1</summary><blockquote>
<dl>
<dd>
<br>

`45-45`: **{ICON} Trivial** · **Maintainability & Code Quality** · **Quick win**

**Name the constant.**

</dd>
</dl>
</blockquote></details>

---

<details>
<summary>{ICON} Prompt to fix all issues</summary>
<dl>
<dd>

```
Verify each finding against current code.

Inline comments:
Review comments at @src/app/Upload.java:
- Line 12: Resolve the target path and reject entries outside the destination directory.

Nitpick comments:
- Line 45: Name the constant.
```

</dd>
</dl>
</details>

<h6>
<details>
<summary>{ICON} Review info</summary>
<dl><dd>Run ID: abc</dd></dl>
</details>
</h6>
"""

INLINE = f"""<!-- coderabbit-ai-generated:v1 -->

**{ICON} Critical** · **Security & Privacy** · **Quick win**

<details>
<summary>{ICON} Supported by static analysis</summary>
<dl>
<dd>
Script executed:

```bash
rg -n unzip src
```

<details><summary>nested</summary>inner</details>
</dd>
</dl>
</details>

**Zip entries can escape the destination.**

`entry.getName()` is joined to the target directory without normalisation &amp; checks.

<!-- ai-agent-prompt:start -->
<!-- cr-comment:v1:deadbeef -->
"""

RATE = """<!-- This is an auto-generated comment: rate limited by coderabbit.ai -->

> [!WARNING]
> ## Review limit reached
>
> **Next included review available in 4 minutes.**
"""


class Parsing(unittest.TestCase):
    def test_review_counts(self):
        self.assertEqual(cr.review_counts(REVIEW),
                         {"actionable": 2, "nitpick": 1, "outside_diff": 0, "duplicate": 0})
        self.assertEqual(cr.review_counts("Nitpick comments (3)")["nitpick"], 3)
        self.assertEqual(cr.review_counts("")["actionable"], 0)

    def test_inline_meta(self):
        self.assertEqual(cr.inline_meta(INLINE), ("Critical", "Security & Privacy"))
        self.assertEqual(cr.inline_meta("_⚠️ Potential issue_ | _🟠 Major_\n\nx"), ("Major", None))
        self.assertEqual(cr.inline_meta("nothing here"), (None, None))

    def test_strip_markup_drops_analysis_chain_keeps_feedback(self):
        s = cr.strip_markup(INLINE)
        self.assertIn("Zip entries can escape the destination.", s)
        self.assertIn("normalisation & checks", s)
        self.assertNotIn("Script executed", s)
        self.assertNotIn("inner", s)
        self.assertNotIn("<", s.replace("<br>", ""))
        self.assertNotIn("cr-comment", s)

    def test_prompt_to_fix_all_is_preferred(self):
        source, text = cr.fix_text([{"body": REVIEW}], [{"path": "a", "line": 1, "body": INLINE}])
        self.assertEqual(source, "prompt-to-fix-all")
        self.assertTrue(text.startswith("Verify each finding"))
        self.assertIn("Line 12: Resolve the target path", text)
        self.assertNotIn("```", text)

    def test_fallback_to_comments(self):
        source, text = cr.fix_text([{"body": "**Actionable comments posted: 1**"}],
                                   [{"path": "src/A.java", "line": 7, "body": INLINE}])
        self.assertEqual(source, "comments")
        self.assertIn("Comment 1 (src/A.java line 7):", text)
        self.assertIn("Zip entries can escape", text)

    def test_has_findings(self):
        zero = {"actionable": 0, "nitpick": 0, "outside_diff": 0, "duplicate": 0}
        self.assertFalse(cr.has_findings(zero, []))
        self.assertTrue(cr.has_findings(dict(zero, nitpick=1), []))
        self.assertTrue(cr.has_findings(zero, [{"body": "x"}]))

    def test_rate_limit_wait(self):
        self.assertEqual(cr.rate_limit_wait_s(RATE), 240)
        self.assertEqual(cr.rate_limit_wait_s("Please wait **12 minutes and 30 seconds** before"), 750)
        self.assertEqual(cr.rate_limit_wait_s("available in 1 hour"), 3600)
        self.assertIsNone(cr.rate_limit_wait_s("no number here"))

    def test_helpers_use_benchmarking_org(self):
        self.assertEqual(cr.dr.ORG, "leotrace-benchmarking")


class Waiting(unittest.TestCase):
    """wait_for_review against a scripted sequence of check runs (no GitHub)."""

    def setUp(self):
        self.p = [mock.patch.object(cr, "POLL_S", 0), mock.patch.object(cr, "RATE_LIMIT_PAD_S", 0),
                  mock.patch.object(cr.time, "sleep", lambda s: None)]
        for p in self.p:
            p.start()
        cr._state.update(not_before=0.0, last_open=0.0, bad_streak=0)
        cr._stop.clear()
        self.log = logging.getLogger("cr-test")

    def tearDown(self):
        for p in self.p:
            p.stop()

    @staticmethod
    def run_(i, conclusion, title):
        return {"id": i, "name": "CodeRabbit", "app": {"slug": "coderabbitai"}, "status": "completed",
                "conclusion": conclusion, "output": {"title": title}}

    def test_rate_limited_then_reviewed(self):
        seq = [[], [self.run_(1, "neutral", "Review rate limited")],
               [self.run_(1, "neutral", "Review rate limited"), self.run_(2, "success", "Review completed")]]
        posted = []
        with mock.patch.object(cr, "check_runs", side_effect=lambda r, s: seq.pop(0) if len(seq) > 1 else seq[0]), \
             mock.patch.object(cr, "bot_issue_comments", return_value=[{"body": RATE}]), \
             mock.patch.object(cr, "rate_limit_wait_s", return_value=0), \
             mock.patch.object(cr, "run", side_effect=lambda cmd, **k: posted.append(cmd)):
            status, hist = cr.wait_for_review("ase-x", 5, "sha", self.log, "c1")
        self.assertEqual(status, "reviewed")
        self.assertEqual([h["conclusion"] for h in hist], ["neutral", "success"])
        self.assertTrue(any("body=@coderabbitai review" in c for c in posted[0]))
        self.assertGreater(cr._state["not_before"], 0)

    def test_skipped(self):
        with mock.patch.object(cr, "check_runs", return_value=[self.run_(1, "skipped", "Review skipped: x")]):
            self.assertEqual(cr.wait_for_review("ase-x", 5, "sha", self.log, "c1")[0], "review-skipped")

    def test_stop_after_three_without_review(self):
        for s in ("clean", "review-timeout", "review-skipped"):
            cr.note_outcome(s, self.log)
        self.assertFalse(cr._stop.is_set())
        cr.note_outcome("error", self.log)
        self.assertTrue(cr._stop.is_set())


if __name__ == "__main__":
    unittest.main()
