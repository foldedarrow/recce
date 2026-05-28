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

The bundled active subdomain bruteforce labels are a small curated Recce list
of common enterprise hostnames. They are not copied from SecLists. Larger
SecLists-derived wordlists remain a future enhancement if beta users need them.
