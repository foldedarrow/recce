# `recce` usage

Personal OSINT toolkit — trace where a username, email, phone number, or domain appears across the public internet. Repo: https://github.com/foldedarrow/recce.

Two ways to use it: **CLI** (terminal) and **GUI** (Mac app). The GUI is at the bottom of this page.

## CLI

You have **six commands**. Here's what each one does and how to use it.

---

## 1. `recce username <handle>`

Search 720+ platforms in parallel for an account using that username. Backed by WhatsMyName plus a curated custom list.

```bash
recce username foldedarrow                              # basic
recce username --list-categories                        # show valid categories
recce username foldedarrow --only dev,social            # restrict categories
recce username foldedarrow --exclude gaming             # skip categories
recce username foldedarrow --nsfw                       # include adult sites (off by default)
recce username --file handles.txt --target-concurrency 2 # batch: one handle per line
recce username foldedarrow --per-domain-rate 1.5        # throttle probes to each domain
recce username foldedarrow --csv hits.csv               # export CSV
recce username foldedarrow --show-misses                # show every site, not just hits
```

Username searches also check the Wayback Machine for archived profile pages
on 16 major sites. An archived profile shows the account existed at that
date, and is flagged "deleted or renamed?" when the live probe now finds
nothing.

**Categories** include: `dev`, `social`, `video`, `audio`, `art`, `gaming`, `fandom`, `blog`, `creator`, `business`, `fitness`, `civic`, `messaging`, `web3`, plus more from WMN.

Username probes use global concurrency plus a per-domain throttle. The default
rate is conservative; pass `--per-domain-rate 0` only for trusted local tests.

---

## 2. `recce email <addr>`

Look up an email. Without flags it's quick (Gravatar, MX provider, basic checks). Add `--deep` to also probe ~115 sites' sign-up/sign-in lookups (user-scanner, plus holehe for sites user-scanner lacks) to find registered accounts. Each hit is re-checked with a made-up address at the same domain; sites that "find" that too are downgraded to unknown (`--no-deep-verify` turns this off).

```bash
recce email someone@example.com                         # quick: ~5 seconds
recce email someone@example.com --deep --i-own-these-emails
recce email --file emails.txt --deep --i-own-these-emails --batch-concurrency 1
recce email someone@example.com --json out.json
```

**`--deep` is only safe to use on emails you own or have explicit consent for** — it sends real probes to each site's sign-up and sign-in systems, so the CLI requires `--i-own-these-emails`. Modules that could alert the owner (a reset, OTP or login link, a submitted password, a started sign-up) are never run; see [docs/USER_SCANNER_AUDIT.md](docs/USER_SCANNER_AUDIT.md) and [docs/HOLEHE_AUDIT.md](docs/HOLEHE_AUDIT.md).

---

## Egress control (which network exit each module uses)

Many "unknown" username results are IP-reputation blocks: VPN exits are on
Cloudflare-style deny lists. recce lets you pick the exit per module, retry
blocked probes through another one, and records the exit on every report.

```bash
# ~/.config/recce/.env
RECCE_EXITS=tor=socks5h://127.0.0.1:9050;home=socks5h://user:pass@10.0.0.2:1080
RECCE_PROXY=home                     # default exit for every module
RECCE_DOMAIN_PROXY=direct            # per module: USERNAME / EMAIL / PHONE / DOMAIN
RECCE_USERNAME_FALLBACK_PROXY=tor,home  # retry bot-walled username probes, in order
```

```bash
recce doctor                                   # every exit and the public IP it appears as
recce username somehandle --proxy tor          # one-off exit (name, URL or "direct")
recce username somehandle --fallback-proxy tor # retry 401/403/429 probes through Tor
recce username somehandle --fallback-proxy tor,home  # Tor first, then home for what's still blocked
```

- Precedence: `--proxy` > `RECCE_<MODULE>_PROXY` > `RECCE_PROXY` > direct.
- The fallback retries only probes that came back HTTP 401/403/429. A
  decisive answer replaces the blocked one, is tagged `via <exit>`, and its
  made-up-username check runs through the same exit. Use `socks5h://` for Tor
  so DNS resolves through it too.
- A comma list is a chain: each exit retries only the probes the earlier
  ones left blocked, so put the most private exit first (`tor,home` exposes
  your home IP only to the sites Tor couldn't reach).
- `RECCE_IPV4_EXITS=home` resolves targets to IPv4 only for the named
  fallback exits. Needed when an exit has no IPv6 route (e.g. a `socks5://`
  SSH tunnel to a v4-only host): sites with AAAA records otherwise fail with
  "connection reset". Use `socks5://` (not `socks5h://`) for such a tunnel to
  keep DNS on the recce host.
- Every report records its exit (`Exit:` under the query, in JSON as `exit`,
  and in investigation exports). Hits answered by the fallback carry
  `extra.exit`. Proxy passwords are masked wherever an exit is shown or saved.
- The GUI sidebar has the same two settings: *Exit (proxy)* and *Username
  fallback exit*.

---

## Attribution clusters (`username`)

A username existing on eight sites does not mean one person owns all eight.
After every username search recce compares the hits and groups the ones whose
public data corroborates each other into **Likely the same person** clusters:

| Signal | Weight |
|---|---|
| Same profile (a site probe and its profile API) | 0.95 |
| Cross-link (one profile links to the other: website, Keybase proof, X handle) | 0.80 |
| Shared email | 0.80 |
| Same avatar (perceptual hash; default/blank avatars ignored) | 0.60 |
| Same display name (not just the handle; one-word names 0.20) | 0.45 |
| Same location (vague ones like "Earth" ignored) | 0.15 |

Signals combine as `1 − Π(1 − w)`; two hits link at ≥ 0.40, so location or a
one-word name alone never links. Plain site hits get their name, avatar and
`rel="me"` links from the profile page's meta tags (OpenGraph/Twitter card).
Anything the made-up-username page shares with it (a site-wide title or
logo) is dropped. Names that contain the handle ("sample's profile") are
site templates and don't count, and two definitions of the same site never
corroborate each other. Each cluster lists the links that formed it
and a timeline of account-creation dates. Hits outside every cluster are
marked "username only". The only extra network traffic is one GET per public
avatar image. Clusters are saved in reports, investigations and exports.

---

## Recursive pivoting (`username` and `email`)

Hits often name other identifiers: GitHub identity's linked X handle and the
real emails in a user's commits, GitHub commit search's logins for an email,
Gravatar's linked profiles, the email local-part. After every `username` or
`email` run, recce lists these as ready-to-run commands. `--recursive` runs
them for you, breadth-first, and prints the chain.

```bash
recce email someone@example.com --recursive               # follow one level
recce username somehandle --recursive --depth 2           # up to 3 levels
recce username somehandle -R --max-pivots 5               # cap follow-ups per level
recce username somehandle -R --case <investigation-id>    # save runs + chain to a case
recce investigations export <investigation-id>            # Markdown report incl. pivot chain
recce investigations export <id> --format html -o case.html # self-contained HTML dossier
```

- `--depth` defaults to 1 and is capped at 3; `--max-pivots` (default 10)
  limits follow-ups per level. Anything not run is listed under the chain.
- Identifiers are de-duplicated (case-insensitive) against everything already
  searched, so cycles stop on their own.
- Follow-ups are the passive search only. `--deep` probes run on the emails
  you typed and never on discovered ones; domains are never pivoted to, so no
  bruteforce either.
- With `--case`, each follow-up is saved with the hit that named it. Exports
  (`recce investigations export`, or the GUI's case exports) show a *Pivot
  chain* section and a "Discovered via" line per run.

---

## 3. `recce phone <number>`

Parse a phone number and emit pivot links you can click to investigate manually.

```bash
recce phone "+447826916903"                             # international format (preferred)
recce phone "07826 916903" --region GB                  # local format + region hint
recce phone "+14155551234" --region US
recce phone --file numbers.txt
recce phone "+447826916903" --deep --i-have-consent         # passive search-engine footprint
```

Output gives you carrier, region, type, plus clickable URLs for **WhatsApp**, **Google/Bing/DuckDuckGo web search** (across every number format), **Truecaller**, **Sync.me**.

For +44 numbers (UK, Jersey, Guernsey, Isle of Man) an **Ofcom numbering** row gives the provider the number's block was originally allocated to, the block's status and allocation date, and the area for 01/02 numbers. It comes from a local index of Ofcom's published allocations, so no query leaves the machine. A ported number is now served by a different network, which is why the row says "originally allocated to". A block that is Free, Protected or Quarantined means the number shouldn't be in service: it was probably spoofed or mistyped.

`--deep` adds a passive footprint: a comprehensive set of clickable **site: dorks** for socials, classifieds and paste sites (plus document and spam/reputation dorks), each spanning all common formats of the number, and one best-effort live DuckDuckGo query listing the public pages it surfaces. It only reads public search results — it never contacts the number — but it still profiles a person, so it requires `--i-have-consent`. Free search endpoints challenge automated quoted queries from server IPs, so the live query is best-effort and degrades to the dork links when rate-limited.

---

## 4. `recce domain <name>`

Profile a domain or URL. Default mode is passive: ownership/RDAP/whois,
DNS/network, reverse IP (other domains on the same address), email
infrastructure, M365 realm, web metadata, TLS certificate, passive subdomains,
company pivots, Wayback first-seen plus the latest archived about/contact/
team/privacy pages, Hudson Rock infostealer counts (infected employees and
users, and the domain URLs their logins were stolen for), and, with
`HUNTER_API_KEY`, the email address format (one Hunter credit per domain).
Results start with a compact summary card so the key facts are visible before
the detailed evidence table.

```bash
recce domain example.com
recce domain https://www.example.com --only network,email,subs
recce domain example.com --exclude wayback,companies
recce domain example.com --bruteforce --i-am-authorised
recce domain example.com --no-providers
recce domain --file domains.txt --json out.json
```

Categories: `ownership`, `network`, `email`, `web`, `subs`, `companies`, `wayback`.

`--bruteforce` sends active DNS queries from a subdomain wordlist and requires
`--i-am-authorised`. Bundled SecLists-derived wordlists are `small` (1k),
`medium` (5k), and `big` (20k). See `docs/CONSENT.md`.

---

## 5. `recce update`

Refresh the WhatsMyName site database and the Ofcom UK numbering index from upstream. Run this every few months: the WMN community keeps adding platforms and fixing detection markers, and Ofcom republishes number allocations every Wednesday. Refreshed data lands in `~/.cache/recce/` and takes precedence over the bundled snapshots.

```bash
recce update
recce update --only ofcom          # or --only wmn
recce update --reset-cache
recce update --only ofcom --bundled   # maintainers: rewrite recce/data/ofcom-numbering.json.xz
```

---

## 6. `recce doctor`

Sanity check: shows which API keys you have set, total site count, WMN cache status, the Ofcom numbering index (block count and publish date), how many NSFW sites are gated, and lightweight network reachability.

```bash
recce doctor
recce doctor --no-network
```

---

## Universal flags (work on every command)

| Flag | What it does |
|------|--------------|
| `--json out.json` | Save the full machine-readable report |
| `--csv out.csv` | Save all hits as CSV (handy for diffing over time) |
| `--show-misses` | Show "not found" rows (default: hidden) |
| `--show-errors` | Show probes that errored out (default: hidden) |
| `--proxy <exit>` | Exit for this run: a proxy URL (`socks5h://127.0.0.1:9050`), an exit name from `RECCE_EXITS`, or `direct` (see *Egress control*) |
| `--file <path>` | Batch input — one identifier per line, `#` for comments |
| `--no-providers` | Disable optional API provider integrations |
| `--skip-provider <ids>` | Skip registry provider IDs such as `shodan,virustotal` |
| `-h` / `--help` | Show help for a command |

---

## Typical workflows

**Check your own footprint:**
```bash
recce username your_handle
recce email your@email.com --deep --i-own-these-emails
recce phone "+44yournumber"
```

**Verify a contact / new acquaintance:**
```bash
recce username theirhandle --csv recon.csv
recce phone "+44theirnumber"
```

**Periodic refresh of your data:**
```bash
recce update                                            # refresh WMN site DB
recce username your_handle --csv $(date +%Y-%m).csv     # snapshot once a month
```

---

## API keys (optional — unlock more sources)

Edit `~/.config/recce/.env` (create the dir if it doesn't exist):

```
HIBP_API_KEY=...        # Have I Been Pwned breach data — ~$4/mo
HUNTER_API_KEY=...      # Hunter.io email verification — free 25/mo
NUMVERIFY_API_KEY=...   # Phone carrier lookup — free 100/mo
EMAILREP_API_KEY=...    # EmailRep reputation — free / paid
COMPANIES_HOUSE_KEY=... # Optional UK company lookup for recce domain
SHODAN_API_KEY=...      # Pro-gated; DNS API needs a paid Shodan Membership
VIRUSTOTAL_API_KEY=...  # Pro-gated; query implementation planned
SECURITYTRAILS_API_KEY=...
CENSYS_API_TOKEN=...    # Pro-gated; Censys Platform personal access token
CENSYS_ORG_ID=...       # optional; paid Censys plans only
```

Verify they loaded with `recce doctor`. You can also manage these in the GUI's
API Keys tab. See `docs/PROVIDERS.md` for the provider registry and Recce Pro
entitlement notes.

Run `recce <command> --help` for the per-command flag list.

---

## GUI (desktop app)

If you'd rather click than type, recce ships with a Streamlit-based GUI that wraps the same async modules the CLI uses. You get one window with Username / Email / Phone / Domain modes, forms for every flag, live results, and CSV/JSON download buttons.

### Install (one-time)

```bash
cd ~/Documents/Claude/Projects/recce
python -m pip install '.[gui]'
```

Or, with pipx:

```bash
pipx install '~/Documents/Claude/Projects/recce[gui]' --force
```

The `[gui]` extra adds `streamlit` + `pandas`. The CLI keeps working exactly as
before.

### Launch (terminal)

```bash
recce-gui
```

…opens the GUI in your default browser at <http://localhost:8501>. Press `Ctrl+C` to stop.

### Launch (Dock app)

If you want a real Mac app with a Dock icon and no browser chrome, see the README's `GUI app` section — one-time setup wraps the GUI with [Pake](https://github.com/tw93/Pake) into a `.app` bundle. After that, double-click **Recce GUI** in your Dock and the window opens.

### What's in the GUI

- **Sidebar** — mode selector, API-key status, site count, "Refresh WMN data" button.
- **API Keys tab** — provider status table and local key storage at `~/.config/recce/.env`.
- **Username tab** — text input, NSFW toggle, category include/exclude filters, run button. Confirmed hits in cards above the full table.
- **Email tab** — text input, consent-gated deep-mode toggle, deep concurrency/retry controls.
- **Phone tab** — text input, region selector, results with clickable WhatsApp / Truecaller / Sync.me / Google links.
- **Domain tab** — domain profile form with passive categories and consent-gated subdomain bruteforce.
- **Domain summary** — top-level domain facts extracted from the detailed evidence.
- **Likely the same person** — username results open with attribution clusters (members, linking signals, account timeline); the results table has a Cluster column.
- **Follow-up searches** — under username and email results, identifiers named in the hits appear as one-click searches. The follow-up is saved to the active case with the hit that led to it (deep mode never applies).
- **Downloads** — every report has CSV and JSON buttons. The Investigations tab adds an **HTML dossier** (full or redacted): summary, identity graph of the pivot chain, likely-same-person clusters, a dated timeline (account creation, first archived, breaches, infostealer infections), findings with provenance, and methodology. It's one file with no external assets.
