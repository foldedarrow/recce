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

### 3. Attribution confidence (username reuse)
A username existing on 8 sites does not mean one person owns all 8. Score
each hit by corroboration: same display name, same avatar (perceptual hash),
cross-links between profiles, matching location, account-creation ordering.
Show clusters ("these 5 profiles look like the same person") instead of a
flat list.

### 4. Site definition health
- `recce selftest`: run each site against its WMN `known` accounts and a
  canary; report and auto-disable definitions that fail both ways.
- Weekly job on the box (alongside the WMN refresh timer) that diffs the
  results and flags breakage.
- Consider importing Maigret's site DB (MIT) as a third source — ~3,000 sites
  vs WMN's ~700 — gated behind the same canary verification.

### 5. Egress control
Most remaining 403s are IP reputation: the box exits via Proton Secure Core,
which Cloudflare and others block. Options, per module: a configurable exit
for username probes (e.g. the home connection, or a residential proxy), Tor
for sites that allow it, and recording which exit produced each result.

### 6. More sources
- **Email:** Microsoft consumer-account existence (the AAD `GetCredentialType`
  endpoint is unreliable for outlook.com — needs a different approach);
  keyed providers for DeHashed / Intelligence X / Snusbase (summaries only,
  never secrets); holehe is unmaintained since 2023 — audit its modules or
  move to a maintained fork.
- **Phone:** Ofcom numbering data (UK range holder / original network,
  offline); a search-API provider (Brave Search / Google CSE / SerpAPI) so the
  dork links return real results automatically instead of needing clicks.
- **Domain:** implement the VirusTotal and SecurityTrails placeholders;
  Hudson Rock `search-by-domain` (infected employees/users counts); reverse
  IP; Wayback snapshots of key pages; Hunter domain search for email format.
- **Username:** Wayback snapshots for deleted profiles.

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
