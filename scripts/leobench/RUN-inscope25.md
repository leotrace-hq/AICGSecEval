# inscope25, 3 cycles, Claude only

Started 2026-09-30 14:04:52. Purpose: re-measure LeoPrevent on the clean 25-instance cohort with the
CURRENT engine and corpus, and compare against the 3-cycle run of 2026-09-21, which used the
Sep-15 binary and the Sep-14 corpus. Everything except the engine/corpus is held constant.

| | this run | 2026-09-21 run |
|---|---|---|
| cohort | data/inscope25_v2.json (25) | data/inscope_v2.json (38) |
| cycles | 3 | 3 |
| agents | claude_code only | claude_code + codex |
| agent model | claude-sonnet-4-5 | claude-sonnet-4-5 |
| leoprevent binary | main @ 853ee0a7 (built 2026-09-30) | Sep-15 build (kept as bin/leoprevent-server.sep15) |
| corpus | agent-rules main @ 84b921b, 58 rules | leoprevent/server/agent-rules, 56 rules |
| quota floors | 5% five-hour remaining, 25% weekly remaining | 10% both (WINDOW_STOP_AT 0.90) |

Corpus delta since the previous run: +`csrf-state-changing-get`, +`url-path-segment-encoding`,
widened `ssrf`. The cohort is 10/25 CWE-352 and 9/25 CWE-22, so the new rules target it directly.

Comparison is against the 25 instances as they scored in the 2026-09-21 run, not against its
38-instance headline.
