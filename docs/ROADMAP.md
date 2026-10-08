# Roadmap

Goal: find as much as possible about an identifier, as accurately as possible,
without crossing the lines in [CONSENT.md](CONSENT.md).

This file records what the October 2026 audit found, what has shipped, and
what to build next, in priority order. Numbers come from live runs on the
deployment box (Proton VPN egress) unless stated.

## Audit findings (October 2026)

| Area | Finding | Status |
|---|---|---|
| Username | 3 of 12 hits for a real handle were false (Keybase, GameJolt, Trakt "found" any username) | Fixed — canary verification (#24) |
| Username | Same profile reported 2–3 times (GitHub, Docker Hub); 11 sites ran twice via case-only name clashes | Fixed (#24) |
| Username | ~32% of sites return "unknown", mostly HTTP 403 bot walls | Partly fixed — Chrome fingerprint unblocks ~35% of 403s (#25). Rest is IP reputation (see *Egress*) |
| Username | Errors all said "network error / timeout" — Pi-hole DNS refusals looked like outages | Fixed — DNS/timeout/TLS/refused reasons (#24) |
| Email | HIBP was the only breach source | Fixed — XposedOrNot, LeakCheck, Hudson Rock (#26, #29) |
| Email | No identity pivots | Fixed — Proton key age, GitHub commit search (#26) |
| Username | No profile data / identity extraction | Fixed — GitHub identity (#27); GitLab, Mastodon, Bluesky, Keybase, HN, Chess.com, Docker Hub, npm, Steam (item 2) |
| Domain | crt.sh 502s/timeouts left one source (50 subdomains) | Fixed — Cert Spotter + urlscan (894 subdomains) (#28) |
| Domain | Subdomain DNS validation sequential (hours on big domains) | Fixed — concurrent (#28) |
| Domain | Tech detection flagged React/Vue on words like "reaction" | Fixed (#28) |
| Phone | Bing pivot returned unrelated pages | Fixed (#23) |
| Repo | No CI; local GUI can run a stale installed copy | CI added; see *Engineering* |

## Next — highest value first

### 1. Recursive pivoting — shipped
`recce/modules/pivot.py` collects usernames/emails from FOUND hits
(`extra.usernames`, `extra.emails`, `extra.username`, Gravatar `accounts`
URLs), de-duplicates them against what was searched, and follows them with
`--recursive --depth N` (max 3) or one-click GUI buttons. Investigations keep
the chain and exports explain each attribution. EmailRep `profiles` only names
platforms ("twitter"), not handles, so it is not a pivot source. The profile
providers from (2) emit `extra.usernames` / `extra.emails`, so their finds
pivot automatically.

### 2. Profile parsing for more sites — shipped
`recce/providers/profiles.py`: GitLab, Mastodon, Bluesky, Keybase (proofs),
Hacker News, Chess.com, Docker Hub, npm (maintainer email) and Steam (XML)
report name, bio, location, links, avatar and join date, with linked handles
in `extra.usernames` and emails in `extra.emails` for (1). Left out after
live checks: Reddit `about.json` (403 from Proton egress — revisit with
*Egress*), PyPI (no user JSON), GitLab per-user detail (needs a token).
Other instances (Mastodon beyond mastodon.social, self-hosted GitLab) are
open.

### 3. Attribution confidence (username reuse) — shipped
`recce/modules/attribution.py` links FOUND hits pairwise on same profile,
cross-links, shared email, avatar dHash, display name and location, and
clusters them (`Report.clusters`, `extra.attribution` per hit) with an
account-creation timeline. Site hits get name/avatar/links from their
pages' meta tags (`recce/modules/page_meta.py`). Open: clusters across
pivoted reports (one person, several handles) are not merged yet.

### 4. Site definition health
- Shipped: `recce selftest` probes each definition with a `known` account
  and a canary, records the egress IP, and saves verdicts that searches use
  to skip false-positive sites (`--flagged-sites skip|mark|off`).
- Shipped: weekly `recce-selftest.timer` after the WMN refresh; the journal
  shows changes since the previous run.
- Next: alerting on new breakage (the diff is in `selftest.json` → `changes`);
  more `known` accounts for WMN sites whose only one has gone.
- Consider importing Maigret's site DB (MIT) as a third source — ~3,000 sites
  vs WMN's ~700 — gated behind the same canary verification.

### 5. Egress control — shipped
`recce/core/egress.py`: named exits, per-module exit selection, a username
fallback exit that retries 401/403/429 probes (canary check through the same
exit), the exit recorded on every report and fallback hit, and `doctor`
showing each exit's public IP. The box has Tor as the fallback. Open: a
home-connection or residential exit needs a proxy endpoint outside the VPN.
Some sites block Tor as hard as VPNs, so per-site exit preferences
(learned from selftest results) would be the next step.

### 6. More sources — first batch shipped
Shipped: Hudson Rock `search-by-domain`, Hunter domain search (email
format), reverse IP (HackerTarget), Wayback key pages, and Wayback profile
snapshots for usernames (`recce/modules/archive.py` holds the shared CDX
client). Still open, below.

- **Email:** Microsoft consumer-account existence (the AAD `GetCredentialType`
  endpoint is unreliable for outlook.com — needs a different approach);
  keyed providers for DeHashed / Intelligence X / Snusbase (summaries only,
  never secrets); holehe is unmaintained since 2023 — audit its modules or
  move to a maintained fork.
- **Phone:** Ofcom numbering data (UK range holder / original network,
  offline); a search-API provider (Brave Search / Google CSE / SerpAPI) so the
  dork links return real results automatically instead of needing clicks.
- **Domain:** implement the VirusTotal and SecurityTrails placeholders
  (needs keys to verify live).

### 7. Reporting
HTML dossier (summary, timeline, identity graph, evidence links), and
monitoring alerts when a saved investigation's re-run finds new evidence.

## Engineering
- CI runs ruff + pytest on 3.11 and 3.13 for every PR (`.github/workflows/ci.yml`).
- Local GUI: `recce-gui` from a non-editable install runs a stale copy; use
  `pip install -e '.[dev,gui]'` for development.
- The box's venv is non-editable too: deploy with
  `pip install '/opt/recce[gui]'` after `git pull`, then restart `recce-web`.

## Lines we don't cross
- No leaked secrets in output: passwords, partial passwords, hashes, tokens.
  Providers drop them before they reach a report (see Hudson Rock).
- No techniques that notify the subject (password-reset sends, friend
  requests, message probes). Signup/reset *existence* checks stay behind
  `--deep` and explicit consent.
- Active recon (bruteforce, deep probes) stays consent-gated.
