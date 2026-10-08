# Consent And Authority

Recce distinguishes passive public-source checks from active probes that send
targeted traffic or queries against a subject.

## Email Deep Mode

`recce email --deep` sends live sign-up and sign-in lookups to about 115 third-party services.
Modules that could notify the address owner are never run (see
[USER_SCANNER_AUDIT.md](USER_SCANNER_AUDIT.md)).
Use it only for email addresses you own or where you have explicit authority.
The CLI requires `--i-own-these-emails`.

## Domain Bruteforce

`recce domain --bruteforce` sends DNS queries for common subdomain labels
against the target domain. Some organisations and jurisdictions treat active
reconnaissance as unauthorised access unless you have permission.

Use `--i-am-authorised` only when you have authority to perform active
subdomain discovery against the target. Passive domain profiling does not need
this flag.

The bundled wordlists are SecLists-derived and contain 1,000 (`small`), 5,000
(`medium`), or 20,000 (`big`) labels. Larger scans create more DNS traffic and
should be reserved for cases where the authority and proportionality are clear.
