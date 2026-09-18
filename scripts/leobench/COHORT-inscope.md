# in-scope cohort (`data/inscope_v2.json`) — 67 instances

Built 2026-09-18. Purpose: measure LeoPrevent on the languages and vulnerability classes its rule
corpus actually covers. run25 was ~50% C memory corruption, which the corpus has NO rules for
(55 web-application rules; languages named are Python/Go/Java/PHP/JS/TS/Ruby/Rust/C#, no C/C++).
34 reviews on C repos in run25 returned 34 `clean`, including Heartbleed — so half of run25 could
only dilute any real effect toward zero.

## Selection

From `data/data_v2.json` (145), keep languages the corpus covers
(php, java, python, javascript, typescript, go, ruby) -> 74, then drop upstream rot:

| dropped | n | why |
|---|---|---|
| dead image | 5 | `cycloctane/ase-cve-{2022-4223,2024-27306,2024-56408,2025-0520,2025-54418}` 404 on Docker Hub |
| dead repo  | 2 | `lunary-ai/lunary` 404 on GitHub (both its instances) |

Leaves **67**: php 39, java 16, python 11, javascript 1. 33 repos, 14 CWEs.

Preflighted before the run: all 33 repos resolve (note `snipe/snipe-it` and `square/retrofit`
answer 301 -> `grokability/snipe-it`, `lysine-dev/retrofit`; git clone follows redirects) and all
67 images resolve including their tags. Checking Docker Hub requires stripping the `:tag` from the
repo path first — `/v2/repositories/ns/name:tag/` returns 400 and looks exactly like rot.

## Every CWE maps to a corpus rule (verified, 14/14)

CWE-22 path-traversal · CWE-352 csrf-samesite-none · CWE-862 missing-function-level-authz ·
CWE-94 eval-injection · CWE-434 insecure-file-upload · CWE-918 ssrf · CWE-78/77
os-command-injection · CWE-287 jwt-verification · CWE-863 idor-object-level-authz ·
CWE-20 no-input-validation · CWE-79 xss-backend · CWE-89 sql-injection · CWE-1336 ssti

## Known caveat

`zju-cve-2021-26120` (smarty, CWE-94) masks a function in
`tests/UnitTests/SecurityTests/SecurityTest.php`. LeoPrevent declines to review test files
(`kind=telemetry, reason=inert` in run25), so it is a structural no-op. Kept deliberately — it is
an honest limitation, not a defect.
