# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `recce phone --deep`: a passive, PhoneInfoga-style search-engine footprint —
  clickable per-platform `site:` dorks (socials, classifieds, paste sites) and
  category dorks (documents, paste sites, spam/reputation) across every common
  number format, plus one best-effort live DuckDuckGo query. Gated on
  `--i-have-consent`; also available as a toggle in the GUI phone tab.
- Phone search pivots now cover six number formats across Google, Bing and
  DuckDuckGo (previously two formats on Google only).

### Fixed

- NumVerify now tries HTTPS first and transparently falls back to HTTP on the
  free tier's `https_access_restricted` (error 105), so free-tier keys return
  carrier data instead of an error.

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
