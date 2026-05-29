# recce

> Personal OSINT toolkit — trace where a **username**, **email**, **phone number**, or **domain** has shown up across the public internet, from one terminal command.

`recce` is a fast, async, no-fluff reconnaissance CLI built for personal use:
checking your own digital footprint, profiling domains, verifying contacts, tidying up after old
accounts, or just satisfying curiosity about whether `that_handle` belongs to
the same person across platforms.

It works without API keys, and unlocks more sources when you provide them.

`recce` is the open-source engine that powers Recce Pro, a commercial
self-hosted workspace for corporate investigators. AGPL covers this engine;
Recce Pro is a separate product.

---

## Features

- **Username search** across **720+ platforms** — backed by the canonical [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) database (~700 sites) merged with a hand-curated list of bespoke probes for places WMN doesn't cover (multi-instance Mastodon, Bluesky AT-Proto, redirect-marker detection for Bandcamp/Substack/Wordpress). Refresh with `recce update`. Adult sites are gated behind `--nsfw`.
- **Email lookups** — Gravatar (with profile + linked accounts), DNS/MX provider detection, [EmailRep](https://emailrep.io) reputation & associated profiles, [Have I Been Pwned](https://haveibeenpwned.com) breach history, [Hunter.io](https://hunter.io) verification, plus a consent-gated `--deep` mode that probes ~140 sites' signup/reset endpoints (via [holehe](https://github.com/megadose/holehe)) to discover registered accounts, with configurable concurrency and retry behavior.
- **Phone number lookups** — full parse via Google's `libphonenumber` (region, type, carrier, timezone), optional [NumVerify](https://numverify.com) carrier verification, and manual-pivot rows with clickable URLs (WhatsApp, Google web search, Truecaller, Sync.me).
- **Domain profiles** — a top-level summary card plus ownership, DNS, ASN, email infrastructure, Microsoft 365 realm fingerprinting, web metadata, TLS certificate details, passive subdomain discovery, Wayback first-seen, and company-register pivots.
- **Batch mode** — pass `--file targets.txt` to any subcommand to run a list of identifiers in one go.
- **Output** — Rich terminal tables, optional `--json` export, `--csv` export of all hits across all targets, `--show-misses` and `--show-errors` flags.
- **Network** — concurrent retrying HTTP/2 client, honest default User-Agent, configurable concurrency, per-domain username throttling, optional `--proxy` (HTTP/HTTPS/SOCKS).
- Works **fully offline-of-keys** — every paid source degrades gracefully to `skipped`.

---

## Install

Requires **Python 3.10+** (3.11+ recommended).

### Option A: local venv

```bash
git clone https://github.com/foldedarrow/recce.git
cd recce
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[gui]'
```

Run from that shell afterwards as `recce` or `recce-gui`.

### Option B: pipx

[`pipx`](https://pipx.pypa.io) keeps recce in its own venv outside iCloud Drive
(which can corrupt regular venvs):

```bash
brew install pipx
pipx ensurepath
git clone https://github.com/foldedarrow/recce.git
pipx install './recce[gui]'
```

Run from anywhere afterwards as `recce` or `recce-gui`. To pull updates:

```bash
cd recce && git pull && pipx install '.[gui]' --force
```

The GUI app (`recce-gui` + Mac `.app` bundle) uses the same `[gui]` extra: see
the [GUI app](#gui-app) section below.

### Optional: API keys

Copy `.env.example` to `.env` and fill in any keys you have. Every key is
optional; the matching source is skipped if absent.

```bash
cp .env.example .env
$EDITOR .env
```

| Key | Source | Cost | What it unlocks |
|---|---|---|---|
| `HIBP_API_KEY` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) | ~$4 / mo | Per-email breach history |
| `HUNTER_API_KEY` | [hunter.io/api](https://hunter.io/api) | Free 25 / mo | Email verification + sources |
| `NUMVERIFY_API_KEY` | [numverify.com](https://numverify.com) | Free 100 / mo | Phone carrier / location |
| `EMAILREP_API_KEY` | [emailrep.io](https://emailrep.io) | Free / paid | Higher rate-limit on reputation |
| `LEAKCHECK_API_KEY` | [leakcheck.io](https://leakcheck.io) | Paid | (planned) extra breach data |
| `COMPANIES_HOUSE_KEY` | [Companies House](https://developer.company-information.service.gov.uk/) | Free | UK company lookup for domains |

`.env` is also looked up at `~/.config/recce/.env` so you can set keys once globally.

The GUI includes an **API Keys** page that writes provider credentials to the
user-level `.env` with private file permissions. The provider registry also
recognises Pro-gated credentials for Shodan, VirusTotal, SecurityTrails, and
Censys; see [`docs/PROVIDERS.md`](docs/PROVIDERS.md).

---

## Usage

> **Quick reference:** see [`USAGE.md`](USAGE.md) for a one-page command cheat sheet covering every command, every flag, and typical workflows.

### Username

```bash
recce username foldedarrow
recce username --list-categories
recce username some_handle --only dev,social
recce username some_handle --exclude gaming,fandom --json out.json
recce username some_handle --show-misses        # print everything, not just hits
recce username some_handle -c 60                # crank parallelism
recce username some_handle --per-domain-rate 1.5
```

Categories: `dev`, `social`, `video`, `audio`, `art`, `gaming`, `fandom`, `blog`, `creator`, `business`, `fitness`, `civic`, `messaging`, `web3`.

Username mode spaces requests to the same domain by default. Tune with
`--per-domain-rate`, or pass `0` to disable the per-domain guard for a trusted
local test.

### Email

```bash
recce email someone@example.com
recce email someone@example.com --deep --i-own-these-emails
recce email someone@example.com --json out.json
```

Without keys you still get: Gravatar profile, MX provider detection, EmailRep
(rate-limited), and a username-pivot suggestion for the local-part.

### Phone

```bash
recce phone +447700900123
recce phone "07700 900123" --region GB
recce phone "(415) 555-0123" --region US --json out.json
```

### Domain

```bash
recce domain example.com
recce domain example.com --only network,email,subs
recce domain example.com --exclude wayback,companies
recce domain example.com --bruteforce --i-am-authorised
recce domain example.com --no-providers
recce domain --file domains.txt --json out.json
```

Domain profiling is passive by default. Active subdomain bruteforce requires
`--i-am-authorised`; its bundled SecLists-derived wordlists are `small` (1k),
`medium` (5k), and `big` (20k). See [`docs/CONSENT.md`](docs/CONSENT.md).

### Diagnostic

```bash
recce doctor       # show API keys, cache state, and network reachability
recce doctor --no-network
recce --version
```

Lookup commands also accept `--no-providers` to disable optional API provider
calls, and `--skip-provider provider-id` for registry-level provider skips.

### Investigations

```bash
recce investigations list
recce investigations list --include closed,archived
recce investigations close <case-id> --reason "case concluded"
recce investigations archive <case-id> --reason "old case"
recce investigations reopen <case-id>
recce investigations unarchive <case-id>
recce investigations delete <case-id> --reason "smoke test" --yes
```

---

## Output

Each command prints a header, a per-category table of every source it checked,
and a green "Confirmed hits" panel summarising what was actually found. Add
`--json path.json` to also dump the raw report for downstream tooling.

---

## Data storage

The GUI investigations workspace stores case data locally at
`~/.local/share/recce/investigations.sqlite3` by default. The database file is
created with `0600` permissions where the host platform supports POSIX file
modes.

Investigations can be closed, reopened, archived, unarchived, or permanently
deleted from the GUI and the `recce investigations` CLI. Permanent deletion
removes the case and saved runs, but leaves a tombstone event in the local
audit chain.

This beta build does not encrypt the SQLite database at the application layer.
Use full-disk encryption on the host machine: BitLocker on Windows, FileVault
on macOS, or LUKS on Linux. App-layer encryption-at-rest is deferred to the Pro
Hardening phase before paid GA.

---

## GUI app

recce ships with a Streamlit-based GUI that wraps the same async modules as
the CLI. Username, Email, Phone, Domain, and Investigations modes include forms
for the relevant flags, live results, and CSV/JSON download buttons.

A cold-install and real-investigation walkthrough is available at
[`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).

### Install

```bash
cd /path/to/recce
python -m pip install '.[gui]'
```

Or, with pipx:

```bash
pipx install '/path/to/recce[gui]' --force
```

The `[gui]` extra adds `streamlit` and `pandas`. The CLI keeps working
unchanged.

### Run from the terminal

```bash
recce-gui
```

…opens at <http://localhost:8501>. `Ctrl+C` to stop.

### Wrap as a Mac `.app` (Dock icon)

One-time setup uses [Pake](https://github.com/tw93/Pake) to wrap the GUI
into a real `.app` bundle, plus a tiny launcher `.app` that starts the
server (if it isn't already running) and opens the window with one click:

```bash
brew install rust node
npm install -g pake-cli

cd /tmp && rm -rf rb && mkdir rb && cd rb
pake http://localhost:8501 --name Recce --width 1200 --height 850 --hide-title-bar
sudo rm -rf /Applications/Recce.app
sudo cp -R /opt/homebrew/lib/node_modules/pake-cli/src-tauri/target/aarch64-apple-darwin/release/bundle/macos/Recce.app /Applications/

cd /path/to/recce
./bin/build-launcher-app.sh
```

You'll end up with:

- `/Applications/Recce.app` — the Pake-wrapped UI (a webview window).
- `~/Applications/Recce GUI.app` — the launcher. Drag this to your Dock.

Double-click the launcher: it boots the Streamlit server in the background
(logs to `~/Library/Logs/recce/gui.log`), waits for the port to come up,
then opens the `Recce.app` window.

## How detection works

For username search, every site definition in [`recce/data/sites.json`](recce/data/sites.json) declares a detection method:

- `status` — HTTP status code from a probe URL determines existence.
- `absent` — body must **not** contain a known "user not found" marker.
- `present` — body **must** contain a known "user exists" marker (e.g. a JSON field).
- `post_json` — same but via a JSON POST (used for Roblox).

Guarded responses such as `403` and `429` are treated as ambiguous rather than
"not found" where a marker-based probe cannot actually inspect the account
state. JSON/CSV exports include probe evidence such as method, probe URL, HTTP
status, and final URL to make reviews and false-positive fixes easier.

Sites that hide profiles behind heavy JS (Twitter/X, Instagram, LinkedIn,
Facebook) are intentionally **excluded** — naive HTTP checks return false
positives. If you want them, integrate a real headless browser; that is out of
scope here.

---

## Limitations & ethics

- **Use only on yourself, on consenting third parties, or on legitimately
  public targets.** OSINT is a research technique, not a stalking tool.
- Deep email mode requires explicit ownership/consent confirmation because it
  sends live signup/reset probes to third-party services.
- Some sites change their HTML / API and a site definition will need updating —
  PRs welcome.
- Phone-number reverse lookup beyond carrier data requires paid data brokers,
  which `recce` deliberately does **not** integrate with.
- Messaging apps (WhatsApp, Telegram, Signal, etc.) don't allow programmatic
  enumeration; `recce` prints manual-pivot links rather than probing them.
- Respect each site's ToS and the local law where you operate.

---

## Project layout

```
recce/
├── cli.py            # Typer CLI: username | email | phone | doctor
├── config.py         # .env / settings loader
├── core/
│   ├── http.py       # async httpx client (retries, semaphore, HTTP/2)
│   ├── output.py     # Rich tables / panels / JSON export
│   └── result.py     # Pydantic Hit / Report models
├── modules/
│   ├── username.py   # multi-platform username hunter
│   ├── email.py      # Gravatar + MX + EmailRep + HIBP + Hunter
│   └── phone.py      # libphonenumber + NumVerify
└── data/
    └── sites.json    # 80+ curated site definitions
```

---

## Extending it

Add a new site to the username search by editing `recce/data/sites.json`:

```json
{"name": "MyForum", "category": "forum", "url": "https://myforum.example/u/{u}", "method": "status", "found": [200], "missing": [404]}
```

Add a new email/phone source by writing a coroutine that returns a `Hit` and
calling it from `search_email` / `search_phone`.

---

## Licence

Licensed under AGPL-3.0-or-later from v0.4.0 onwards. Earlier releases remain
MIT. See [`LICENSE`](LICENSE).
