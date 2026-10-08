# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- **Censys credentials renamed**: `CENSYS_API_ID` / `CENSYS_API_SECRET` (legacy
  Search API) are replaced by `CENSYS_API_TOKEN` (Platform personal access
  token) and an optional `CENSYS_ORG_ID` for paid plans. The old keys were never
  used by a live query, so nothing else changes.

### Fixed

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
