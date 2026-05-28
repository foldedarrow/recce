# Third-Party Data Sources

Recce's domain module uses free public endpoints and local DNS lookups in v1.

## Domain Sources

- RDAP: `https://rdap.org/domain/<domain>`
- Whois: registry whois servers discovered via `whois.iana.org`
- DNS: local resolver through `dnspython`
- Team Cymru ASN whois: `whois.cymru.com`
- Microsoft 365 realm: `login.microsoftonline.com/getuserrealm.srf`
- Certificate Transparency: `crt.sh`
- HackerTarget hostsearch: `api.hackertarget.com/hostsearch`
- AlienVault OTX passive DNS: `otx.alienvault.com`
- Wayback CDX: `web.archive.org/cdx`
- Companies House: optional user-provided `COMPANIES_HOUSE_KEY`
- SEC EDGAR: public company search endpoint

## Bruteforce Labels

The bundled active subdomain bruteforce wordlists are derived from SecLists:

- Source project: `https://github.com/danielmiessler/SecLists`
- Source files:
  - `Discovery/DNS/subdomains-top1million-5000.txt`
  - `Discovery/DNS/subdomains-top1million-20000.txt`
- Licence: MIT
- Copyright: Daniel Miessler / SecLists contributors
- Bundled licence text: `recce/data/wordlists/SECLISTS_LICENSE`

Recce bundles:

- `small`: first 1,000 labels from `subdomains-top1million-5000.txt`
- `medium`: full 5,000-label `subdomains-top1million-5000.txt`
- `big`: full 20,000-label `subdomains-top1million-20000.txt`

The lists are bundled so domain bruteforce does not fetch third-party files at
runtime.
