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
| Companies House | Free | Domain | `COMPANIES_HOUSE_KEY` | Live in domain module |
| Have I Been Pwned | Free | Email | `HIBP_API_KEY` | Live in email module |
| Hunter.io | Free | Email, Domain | `HUNTER_API_KEY` | Email live; domain planned |
| NumVerify | Free | Phone | `NUMVERIFY_API_KEY` | Live in phone module |
| EmailRep | Free | Email | `EMAILREP_API_KEY` | Live; key optional |
| Shodan | Pro | Domain | `SHODAN_API_KEY` | Gated, query implementation planned |
| VirusTotal | Pro | Domain, Email | `VIRUSTOTAL_API_KEY` | Gated, query implementation planned |
| SecurityTrails | Pro | Domain | `SECURITYTRAILS_API_KEY` | Gated, query implementation planned |
| Censys | Pro | Domain | `CENSYS_API_ID`, `CENSYS_API_SECRET` | Gated, query implementation planned |

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
- Free providers should remain usable in the AGPL engine.
- Pro providers should degrade to skipped rows when keys are configured but no
  entitlement is present.
- NumVerify's free tier is HTTP-only and limited; warn in UI/docs, do not block.
