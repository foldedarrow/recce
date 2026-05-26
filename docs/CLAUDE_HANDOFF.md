# Claude / Codex Handoff Notes

Date: 2026-05-26
Branch: `codex/recce-core-improvements`

## What changed

- Hardened username classification so guarded or rate-limited HTTP responses are not misreported as "not found".
- Added per-hit probe evidence for username checks: method, probe URL, HTTP status, final URL, and redirect location when present.
- Made WMN cache handling safer: corrupt cached data now falls back to the bundled snapshot, and updates write atomically.
- Added username category discovery via `recce username --list-categories`.
- Added safer batch controls for CLI workflows: bounded target concurrency for username, email, and phone.
- Added deep-email guardrails and controls: `--i-own-these-emails`, `--deep-concurrency`, `--deep-retry/--no-deep-retry`, `--deep-retry-wait`, and proxy pass-through.
- Expanded `doctor` to report WMN cache state and optional lightweight network reachability checks.
- Added GUI runtime controls for timeout, request concurrency, proxy, username category exclusion, and deep-mode consent/concurrency/retry.
- Added initial pytest coverage around username classification, probe evidence, cache fallback, and report wall-clock duration.

## Files touched

- `recce/modules/username.py`
- `recce/modules/email.py`
- `recce/modules/email_deep.py`
- `recce/modules/phone.py`
- `recce/core/result.py`
- `recce/cli.py`
- `recce/gui/app.py`
- `tests/test_username.py`
- `tests/test_result.py`

## Suggested next passes

- Add mocked tests for CLI option behavior and `doctor` network output.
- Add per-domain throttling for username probes, not just global concurrency.
- Consider an investigations/workspace model for commercial use: saved runs, redacted exports, run comparison, and evidence snapshots.
- Decide whether `--deep` should require consent confirmation only in batch mode or always, then reflect that policy in README/USAGE examples.
