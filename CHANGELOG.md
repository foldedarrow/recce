# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Username fallback exits can be an ordered chain (`--fallback-proxy tor,home`,
  `RECCE_USERNAME_FALLBACK_PROXY=tor,home`): each exit retries only the probes
  the earlier ones left blocked, and every attempt is recorded on the hit.
- **Investigation monitoring with ntfy alerts:** `recce investigations monitor`
  re-runs every open case's saved searches, saves the runs, and pushes an ntfy
  alert when evidence is new to *every* earlier run of that search. Deep and
  bruteforce searches are skipped unless `--include-active`. Alerts carry the
  case reference and counts only (`RECCE_NTFY_DETAIL=1` for more).
  `recce investigations notify-test` checks delivery; `deploy/recce-monitor.*`
  runs it daily. The GUI's re-run button now shares this code.
- **Deep email canary**: every `recce email --deep` hit is re-probed with a
  made-up address at the same domain, and sites that "find" it too are
  downgraded to unknown (`--no-deep-verify` turns this off). The canary uses
  the same domain because Proton's key server answers for made-up @pm.me
  addresses.

- **Ofcom numbering data** for +44 phone numbers (roadmap #6): the provider
  the number's block was originally allocated to (labelled as such, since
  ported numbers move), the block status and allocation date, and the area
  for geographic numbers. It is an offline lookup against a bundled 480 KB
  index of Ofcom's S1/S3/S5/S7/S8/S9 files and area-code table, and runs for
  numbers libphonenumber rejects too, where a Free/Protected block explains
  why. `recce update` now refreshes it as well (`--only ofcom|wmn`), and
  `doctor` shows its block count and publish date.

- **HTML dossier** for investigations (`recce investigations export <id>
  --format html`, GUI "HTML dossier" buttons, full or redacted): one
  self-contained page with a summary, an identity graph of the pivot chain
  (inline SVG), likely-same-person clusters, a dated timeline (account
  creation, first archive capture, breaches, infostealer infections,
  searches), findings with "discovered via" provenance, attribution and
  exits, and methodology with the audit-chain check. No scripts or external
  assets; light/dark and print styles.
- **Profile metadata from site pages**: FOUND username hits take name,
  avatar, bio and `rel="me"` links from the page's OpenGraph/Twitter/title
  tags (live: 108 of 214 hits for a large org handle), minus anything the
  canary page shares. rel=me links to known profile hosts become pivots.
  Attribution now ignores display names containing the handle (site
  templates), treats generic share images as default avatars, and never
  links two definitions of the same site. On that live run this removed 5
  false clusters and kept the 2 real ones (Instagram↔Threads avatar,
  GitHub↔Open Collective link).
- More sources (roadmap #6, first batch):
  - **Domain:** Hudson Rock infostealer counts (infected employees/users,
    malware families, and the domain URLs employee logins were stolen for;
    password stats and URL query strings are dropped); Hunter domain search
    (email address format, organisation, address count, at one credit per
    domain; individual addresses aren't listed); reverse IP via HackerTarget
    (shared hosting flagged); latest Wayback copies of about/contact/team/
    privacy pages.
  - **Username:** Wayback profiles: archived profile pages on 16 major sites,
    flagged "deleted or renamed?" when the live probe finds nothing.
- **Egress control**: named exits (`RECCE_EXITS`), a per-module exit
  (`RECCE_<MODULE>_PROXY`, `RECCE_PROXY`, `--proxy <url|name|direct>`), and a
  username **fallback exit** (`--fallback-proxy`,
  `RECCE_USERNAME_FALLBACK_PROXY`) that retries bot-walled probes
  (401/403/429) and runs their canary check through the same exit. Every
  report records its exit (CLI, GUI, JSON, investigation exports); fallback
  answers are tagged per hit. `recce doctor` lists each exit and the public IP
  it appears as. Proxy passwords are masked wherever exits are shown.
- **Attribution clusters** for username searches: FOUND hits are linked by
  corroborating public data (same profile, cross-links, shared email, avatar
  perceptual hash, display name, location) and grouped into "likely the same
  person" clusters with a confidence, the signals behind each link and an
  account-creation timeline. Uncorroborated hits are marked "username only".
  Shown in the CLI, the GUI (cluster section + column) and investigation
  exports. Adds a `pillow` dependency for avatar hashing.
- **`recce selftest`**: probes every username site definition with a known
  account and a made-up one and classifies it healthy / false-positive /
  false-negative / blocked / error / unverified, recording the egress IP
  (blocks depend on it). `--category`, `--only`, `--json`. Results persist to
  `~/.cache/recce/selftest.json`; username searches skip definitions whose
  last selftest was a false positive (`--flagged-sites mark|off` or
  `RECCE_FLAGGED_SITES` to override). Weekly `deploy/recce-selftest.timer`.
  Custom sites gained `known` accounts; bot-challenge pages served with
  HTTP 200 no longer read as "account exists".
- **Recursive pivoting** for `username` and `email`: identifiers named in hits
  (GitHub identity's X handle and commit emails, GitHub commit logins, the
  GitHub profile email, Gravatar linked profiles, the email local-part) are
  listed as next commands, run automatically with `--recursive --depth N`
  (max 3, `--max-pivots` per level) and printed as a pivot chain. Follow-ups
  are passive only: never `--deep`, never domain bruteforce. The GUI shows
  them as one-click follow-up searches.
- Investigations record the pivot chain: each follow-up run carries the hit
  that named it (`pivot.run` audit event), and JSON/Markdown/PDF exports show
  a *Pivot chain* section and "Discovered via" per run. CLI `--case <id>`
  saves runs to an investigation; `recce investigations export` writes one.
- **Profile parsing** for nine more sites (keyless username providers): GitLab,
  Mastodon (mastodon.social), Bluesky, Keybase, Hacker News, Chess.com,
  Docker Hub, npm and Steam. Each reads the site's public API and reports
  display name, bio, location, links, avatar and join date; linked handles
  (Keybase proofs, Mastodon profile fields, websites/streams pointing at
  known profile sites) go to `extra.usernames`, and emails (npm maintainer
  email, GitLab public email, emails in bios) to `extra.emails`. Reddit
  (`about.json` 403s from VPN egress) and PyPI (no user JSON) were left out.
- **Hudson Rock** infostealer lookups for emails and usernames (keyless): when
  and where a machine holding the identifier's credentials was infected. The
  partial passwords/logins the API returns are never stored or shown.
- Passive subdomains add **Cert Spotter** (second CT source) and **urlscan.io**,
  both keyless. Live: 50 → 894 subdomains for a large domain while crt.sh 502'd.
- **GitHub identity** (username provider): profile details (name, company,
  location, blog, linked X handle, join date) plus the git identities in the
  user's own repos — real names and emails, GitHub noreply aliases, and
  machine-hostname emails from unconfigured git — each flagged as linked to
  the account or not. Username searches now run username providers.
- Four keyless email sources: **XposedOrNot** (breaches, exposed data types,
  plaintext-password flag), **LeakCheck** public API (breach sources incl.
  infostealer logs — field kinds only, never values), **Proton key server**
  (is it a Proton account, and the oldest key date ≈ account age), and
  **GitHub commit search** (email → GitHub logins, author names, repos;
  optional `GITHUB_TOKEN` raises the rate limit).
- Username search re-checks every hit with a made-up username and downgrades
  sites that "find" anything (`--no-verify` to skip); duplicate definitions of
  the same profile collapse into one hit.
- Username probes use a real Chrome TLS fingerprint via curl_cffi
  (`--no-impersonate` for recce's honest UA), getting past many bot walls.
- Shodan free-plan fallback: when `/dns/domain` is refused for lack of a
  Membership, `recce domain` looks up the domain's public IPs (up to 4) via
  `/shodan/host` instead — org/ASN, open ports, CVEs, tags. The free plan only
  covers some IPs; the rest are listed as restricted in the Shodan note.
- Censys provider is now live (Pro): for `recce domain` it looks up each public
  A/AAAA address on the Censys Platform v3 API (ASN, country, exposed services)
  and the TLS certificate served on `:443` (subject, issuer, expiry, SAN count).
- Vonage Number Insight (Advanced) provider: a Pro-gated live **HLR** lookup for
  `recce phone` — current vs original carrier (number portability), ported
  status, reachability, and roaming. Keys: `VONAGE_API_KEY`, `VONAGE_API_SECRET`.
- `recce phone --deep`: a passive, PhoneInfoga-style search-engine footprint —
  clickable per-platform `site:` dorks (socials, classifieds, paste sites) and
  category dorks (documents, paste sites, spam/reputation) across every common
  number format, plus one best-effort live DuckDuckGo query. Gated on
  `--i-have-consent`; also available as a toggle in the GUI phone tab.
- Phone search pivots now cover six number formats across Google, Bing and
  DuckDuckGo (previously two formats on Google only).

### Changed

- **Deep email now runs on user-scanner** (roadmap #6): `recce email --deep`
  probes 99 audited modules of [user-scanner](https://github.com/kaifcodec/user-scanner)
  1.5.2.1 plus the 18 holehe modules for sites user-scanner lacks (117 probes,
  up from 33). Proven working sites went from 4 to 20. All 211 user-scanner
  email modules were read before install; the 104 that could notify the
  address owner (44 flagged loud upstream, plus `vedantu`, which this audit
  caught sending a login code, plus 59 that sign in with a password, submit
  a sign-up or start a recovery flow) never run, and the pinned release is
  checked by a test so new modules can't run unreviewed. Probes follow the
  chosen exit, the same-domain canary covers both backends, and each hit's
  `extra.backend` says which library answered. See
  `docs/USER_SCANNER_AUDIT.md`.

- **holehe module audit** (roadmap #6): all 121 holehe 1.61 modules were tested
  with the operator's own addresses and made-up ones, over the Proton, Tor and
  residential exits. Deep mode now runs 33 modules instead of 108. Skipped:
  16 that could alert the address owner (submitted passwords, account
  creation or sign-up starts, password-reset flows), which are never run,
  plus 72 that are broken (1 always true, 15 always false, 39 erroring,
  17 bot-walled on every exit). Each module has a dated reason; see
  `docs/HOLEHE_AUDIT.md`. `lastfm` answers again and is back in.

- **Censys credentials renamed**: `CENSYS_API_ID` / `CENSYS_API_SECRET` (legacy
  Search API) are replaced by `CENSYS_API_TOKEN` (Platform personal access
  token) and an optional `CENSYS_ORG_ID` for paid plans. The old keys were never
  used by a live query, so nothing else changes.

### Fixed

- Subdomain DNS validation resolves concurrently instead of one name at a time
  (thousands of names previously took hours).
- Technology detection no longer flags React/Vue on ordinary words ("reaction",
  "revue"); frameworks need their real markers. Adds Nuxt, Angular, Svelte.
- Phone pivots: the Bing link returned unrelated pages because Bing mishandles
  quoted digit strings and compact `+44…` numbers; it now searches the spaced
  national, plain national and spaced international formats unquoted. The deep
  X / Twitter dork now targets `x.com`, where new posts are indexed.
- A blank environment variable (e.g. `HIBP_API_KEY=` left in a systemd
  `EnvironmentFile`) no longer masks the real key in `~/.config/recce/.env`;
  after a service restart the web GUI showed — and used — no API keys.
- Shodan no longer reports a valid free-plan key as "invalid or unauthorized".
  A 401 is reported as an invalid key; a 403 "requires membership" is a skipped
  result explaining that the plan lacks DNS API access; other 403s surface
  Shodan's own error text.
- NumVerify now tries HTTPS first and transparently falls back to HTTP on the
  free tier's `https_access_restricted` (error 105), so free-tier keys return
  carrier data instead of an error.
- Test isolation: provider Pro-gating tests no longer depend on a developer's
  local `~/.config/recce/pro_licence.txt` (entitlement now defaults to inactive
  in the test suite).

## [0.5.0] - 2026-05-29

### Added

- Investigations workspace foundation: SQLite store, GUI dashboard, hash-chained audit log, and JSON/Markdown exports.
- Investigation lifecycle operations for closing, reopening, archiving,
  unarchiving, and permanently deleting local cases with a tombstone audit event.
- PDF investigation exports with full and redacted downloads in the GUI.
- GUI run comparison for investigation snapshots, including re-running a saved
  query and diffing new, removed, and changed confirmed evidence.
- `recce domain`, a new domain profile mode with ownership, DNS/network, email-infrastructure, web-surface, passive subdomain, company, and Wayback sources.
- Domain tab in the Streamlit GUI with investigation auto-save support.
- Domain summary card in CLI and GUI, extracting the key ownership, hosting,
  email, web, subdomain, and social-link facts before the detailed evidence.
- SecLists-derived domain bruteforce wordlists for `small` (1k), `medium` (5k), and `big` (20k).
- Domain source adapters split into `recce/modules/domain_sources/` so RDAP,
  whois, DNS, M365, web/TLS, passive subdomain, company-register, Wayback, and
  bruteforce logic can be tested and evolved independently.
- Provider registry foundation with GUI API Keys page, Recce Pro entitlement stub,
  Pro-gated provider status rows, `recce doctor` provider diagnostics, and
  `--no-providers` / `--skip-provider` lookup flags.
- HIBP now runs through the provider registry as the first provider-native
  live adapter.
- EmailRep and Hunter email verification now run through provider-native live
  adapters.
- NumVerify now runs through a provider-native live adapter.
- Shodan now runs through a Recce Pro-gated provider-native live adapter for
  domain DNS intelligence.
- Username probes now use per-domain throttling with guarded-status backoff to
  avoid bursty traffic against repeated hosts.
- Probe evidence capture for username checks.
- WMN cache hardening with corrupt-cache fallback and atomic update writes.
- `recce username --list-categories`.
- Bounded batch concurrency controls.
- Expanded `recce doctor` diagnostics.

### Changed

- Licence is now AGPL-3.0-or-later from v0.4.0 onwards.
- SPDX licence headers added across the Python codebase.
- Investigation databases are created with `0600` file permissions where the
  host platform supports POSIX modes.
- Editable installs on Python 3.13 have been verified for both `recce` and
  `recce-gui` console scripts.
- Companies House and SEC EDGAR domain lookups now use RDAP registrant
  organisation evidence before falling back to a domain-label company guess.
- Existing investigation databases migrate `audit_events.investigation_id` from
  `ON DELETE CASCADE` to `ON DELETE SET NULL` so audit-chain rows survive a
  permanent case delete.
- The default User-Agent now identifies Recce honestly instead of impersonating
  a browser. Override with `RECCE_USER_AGENT` when needed.

### Notes

- The beta investigations database is local stdlib SQLite and is not encrypted
  at the application layer. Use full-disk encryption on the host machine.
  App-layer encryption-at-rest is deferred to Pro Hardening before paid GA.

### BREAKING

- `recce email --deep` now requires the `--i-own-these-emails` consent flag. Running deep mode without it prints a consent-focused error and points to the usage docs.
