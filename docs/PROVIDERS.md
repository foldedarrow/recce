# Provider Integrations

Recce has a small provider registry for optional API integrations. The first
slice is deliberately metadata-first: configuration, status reporting, Pro
entitlement gating, GUI key storage, and command flags are in place before the
premium provider query implementations land.

## Configuration

Recce loads keys from the current working directory `.env` and from:

```text
~/.config/recce/.env
```

The GUI API Keys page writes to the user-level file and keeps it at `0600`
permissions where the host platform supports POSIX file modes.

## Current Registry

| Provider | Tier | Targets | Environment keys | Status |
|---|---|---|---|---|
| Companies House | Free | Domain | `COMPANIES_HOUSE_KEY` | Live in domain module; RDAP org handoff |
| Have I Been Pwned | Free | Email | `HIBP_API_KEY` | Provider-native live query |
| XposedOrNot | Free | Email | none | Provider-native live query: breach names/years, exposed data types, plaintext-password flag, paste count |
| LeakCheck (public) | Free | Email | none | Provider-native live query: breach source names/dates, exposed field kinds (never values), infostealer flag |
| Hudson Rock (infostealers) | Free | Email, Username | none | Provider-native live query: infostealer-infected machines tied to the identifier — date, OS, computer name, malware path, masked IP, exposed service counts. Partial passwords/logins from the API are dropped |
| Proton key server | Free | Email | none | Confirms Proton accounts (incl. custom domains) and dates the oldest public key ≈ account age |
| GitHub commits | Free | Email | optional `GITHUB_TOKEN` | Email → GitHub logins, commit author names, repos; unauthenticated search is 10 req/min |
| Hunter.io | Free | Email | `HUNTER_API_KEY` | Provider-native email query; domain planned |
| NumVerify | Free | Phone | `NUMVERIFY_API_KEY` | Provider-native live query |
| Vonage Number Insight | Pro | Phone | `VONAGE_API_KEY`, `VONAGE_API_SECRET` | Provider-native live HLR: ported status, current/original carrier, reachability, roaming |
| Web search | Pro | Phone | `BRAVE_API_KEY` or `SERPAPI_API_KEY` | Three searches per number (plain, social/classified sites, spam-reputation sites) across all its formats; each page listed once, marked confirmed when its title/snippet contains the number. The number is sent to the search vendor as a query |
| EmailRep | Free | Email | `EMAILREP_API_KEY` | Provider-native live query; key optional |
| Shodan | Pro | Domain | `SHODAN_API_KEY` | Provider-native live query; Recce Pro gated; DNS API needs a paid Shodan Membership; free keys fall back to per-IP host lookups (ports, CVEs, org) for the domain's public IPs — Shodan only allows some IPs on the free plan, the rest are listed as restricted |
| VirusTotal | Pro | Domain, Email | `VIRUSTOTAL_API_KEY` | Provider-native live query (v3): engine verdicts (which engines flag it), reputation, community votes, categories, registrar, creation date, current popularity ranks and DNS records, plus up to 40 known subdomains; email mode looks up the address's domain (consumer webmail skipped). Two calls per domain, one per email — the free API allows 4/min and 500/day |
| SecurityTrails | Pro | Domain | `SECURITYTRAILS_API_KEY` | Gated, query implementation planned |
| Censys | Pro | Domain | `CENSYS_API_TOKEN`, optional `CENSYS_ORG_ID` | Provider-native live query (Platform v3): services on the domain's public IPs + TLS cert on :443; free-tier tokens work without an org ID |

## Recce Pro Entitlement

Pro providers require a local entitlement signal. For now, Recce treats either
of these as active:

- `RECCE_PRO_LICENCE` in the environment or `.env`
- a non-empty `~/.config/recce/pro_licence.txt`

This is an offline stub so the registry can be built safely before the
commercial licence service exists.

## Runtime Controls

Every lookup command accepts:

```bash
recce email person@example.com --no-providers
recce domain example.com --skip-provider shodan,virustotal
```

`--no-providers` disables optional API provider calls such as HIBP, EmailRep,
Hunter, NumVerify, and Companies House while leaving local parsing and ordinary
web/DNS sources intact. `--skip-provider` suppresses registry-based provider
gate rows for the listed provider IDs.

## Notes for Next PRs

- Keep provider-specific network code behind the registry contracts.
- Use HIBP (`recce/providers/hibp.py`) as the first provider-native pattern:
  metadata in the registry, live HTTP in the provider class, orchestration via
  `query_registered_providers()`.
- EmailRep, Hunter email verification, and NumVerify now follow the same
  provider-native pattern; keep future provider conversions behind those
  contracts.
- Free providers should remain usable in the AGPL engine.
- Pro providers should degrade to skipped rows when keys are configured but no
  entitlement is present.
- NumVerify's free tier is HTTP-only and limited; warn in UI/docs, do not block.
- Companies House still lives in the domain source adapter, but company-register
  lookup now uses RDAP registrant organisation evidence before falling back to
  the domain label.
- Shodan uses the official DNS domain endpoint for domain intelligence. Shodan
  bills this as one query credit per lookup.
- VirusTotal sends the key only as the `x-apikey` header. A 429 is reported as
  a rate-limit error and stops the run's remaining VirusTotal call; nothing is
  retried, so a batch of domains spends at most two requests each.
