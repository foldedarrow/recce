# `recce` usage

Personal OSINT toolkit — trace where a username, email, or phone number appears across the public internet. Repo: https://github.com/foldedarrow/recce.

Two ways to use it: **CLI** (terminal) and **GUI** (Mac app). The GUI is at the bottom of this page.

## CLI

You have **five commands**. Here's what each one does and how to use it.

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
recce username foldedarrow --csv hits.csv               # export CSV
recce username foldedarrow --show-misses                # show every site, not just hits
```

**Categories** include: `dev`, `social`, `video`, `audio`, `art`, `gaming`, `fandom`, `blog`, `creator`, `business`, `fitness`, `civic`, `messaging`, `web3`, plus more from WMN.

---

## 2. `recce email <addr>`

Look up an email. Without flags it's quick (Gravatar, MX provider, basic checks). Add `--deep` to also probe ~140 sites' signup endpoints to find registered accounts.

```bash
recce email someone@example.com                         # quick: ~5 seconds
recce email someone@example.com --deep --i-own-these-emails
recce email --file emails.txt --deep --i-own-these-emails --batch-concurrency 1
recce email someone@example.com --json out.json
```

**`--deep` is only safe to use on emails you own or have explicit consent for** — it sends real probes to each site's account-recovery system, so the CLI now requires `--i-own-these-emails`.

---

## 3. `recce phone <number>`

Parse a phone number and emit pivot links you can click to investigate manually.

```bash
recce phone "+447826916903"                             # international format (preferred)
recce phone "07826 916903" --region GB                  # local format + region hint
recce phone "+14155551234" --region US
recce phone --file numbers.txt
```

Output gives you carrier, region, type, plus clickable URLs for **WhatsApp**, **Google web search**, **Truecaller**, **Sync.me**.

---

## 4. `recce update`

Refresh the WhatsMyName site database from upstream. Run this every few months — community keeps adding new platforms and fixing detection markers.

```bash
recce update
recce update --reset-cache
```

---

## 5. `recce doctor`

Sanity check: shows which API keys you have set, total site count, WMN cache status, how many NSFW sites are gated, and lightweight network reachability.

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
| `--proxy <url>` | Route through an HTTP / HTTPS / SOCKS proxy (e.g. `socks5://127.0.0.1:9050` for Tor) |
| `--file <path>` | Batch input — one identifier per line, `#` for comments |
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
```

Verify they loaded with `recce doctor`.

Run `recce <command> --help` for the per-command flag list.

---

## GUI (desktop app)

If you'd rather click than type, recce ships with a Streamlit-based GUI that wraps the same async modules the CLI uses. You get one window with three tabs (Username / Email / Phone), forms for every flag, live results, and CSV/JSON download buttons.

### Install (one-time)

```bash
pipx install '~/Documents/Claude/Projects/recce[gui]' --force
```

The `[gui]` extra adds `streamlit` + `pandas` to the recce venv. The CLI keeps working exactly as before.

### Launch (terminal)

```bash
recce-gui
```

…opens the GUI in your default browser at <http://localhost:8501>. Press `Ctrl+C` to stop.

### Launch (Dock app)

If you want a real Mac app with a Dock icon and no browser chrome, see the README's `GUI app` section — one-time setup wraps the GUI with [Pake](https://github.com/tw93/Pake) into a `.app` bundle. After that, double-click **Recce GUI** in your Dock and the window opens.

### What's in the GUI

- **Sidebar** — mode selector, API-key status, site count, "Refresh WMN data" button.
- **Username tab** — text input, NSFW toggle, category include/exclude filters, run button. Confirmed hits in cards above the full table.
- **Email tab** — text input, consent-gated deep-mode toggle, deep concurrency/retry controls.
- **Phone tab** — text input, region selector, results with clickable WhatsApp / Truecaller / Sync.me / Google links.
- **Downloads** — every report has CSV and JSON buttons.
