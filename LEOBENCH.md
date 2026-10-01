# LeoBench arm

This branch (`leobench-arm`) carries one change to A.S.E itself: the agent adapters take an
`--arm raw|leoprevent` axis, so the same task can be generated with and without a security
reviewer attached. That has to patch A.S.E's source, which is why this branch exists.

Everything else that was once here, the orchestration, cohort pins, reporting and the audit
ledgers, now lives in the `leobench` repository under `ase/`. It is not A.S.E's code and does not
belong in a fork of it.

```bash
export ASE_HOME=/path/to/this/checkout
export LEOPREVENT_HOME=/path/to/leoprevent
<leobench>/ase/scripts/claude_windows.sh      # etc
```

Outputs are still written under this checkout, since verification needs the task images and the
cloned repositories.

Generic fixes found while running the benchmark are sent upstream rather than kept here. Open as
of 2026-10-01: Tencent/AICGSecEval#152, #153, #154. Dataset and verification defects are reported
as Tencent/AICGSecEval#155 through #159.
