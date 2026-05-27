# Consent And Authority

Recce distinguishes passive public-source checks from active probes that send
targeted traffic or queries against a subject.

## Email Deep Mode

`recce email --deep` sends live signup/reset probes to third-party services.
Use it only for email addresses you own or where you have explicit authority.
The CLI requires `--i-own-these-emails`.

## Domain Bruteforce

`recce domain --bruteforce` sends DNS queries for common subdomain labels
against the target domain. Some organisations and jurisdictions treat active
reconnaissance as unauthorised access unless you have permission.

Use `--i-am-authorised` only when you have authority to perform active
subdomain discovery against the target. Passive domain profiling does not need
this flag.
