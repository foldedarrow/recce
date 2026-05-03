# `recce` usage

Personal OSINT toolkit — trace where a username, email, or phone number appears across the public internet, from one terminal command. Repo: https://github.com/foldedarrow/recce.

You have **five commands**. Here's what each one does and how to use it.

---

## 1. `recce username <handle>`

Search 720+ platforms in parallel for an account using that username. Backed by WhatsMyName plus a curated custom list.

```bash
recce username foldedarrow                              # basic
recce username foldedarrow --only coding,social         # restrict categories
recce username foldedarrow --exclude gaming             # skip categories
recce username foldedarrow --nsfw                       # include adult sites (off by default)
recce username --file handles.txt                       # batch: one handle per line
recce username foldedarrow --csv hits.csv               # export CSV
recce username foldedarrow --show-misses                # show every site, not just hits
```

**Categories** include: `coding`, `social`, `gaming`, `tech`, `images`, `hobby`, `business`, `finance`, `misc`, `video`, `music`, plus more.

---

## 2. `recce email <addr>`

Look up an email. Without flags it's quick (Gravatar, MX provider, basic checks). Add `--deep` to also probe ~140 sites' signup endpoints to find registered accounts.

```bash
recce email someone@example.com                         # quick: ~5 seconds
recce email someone@example.com --deep                  # full: ~30–60 seconds
recce email --file emails.txt --deep                    # batch + deep
recce email someone@example.com --json out.json
```

**`--deep` is only safe to use on emails you own** — it sends real probes to each site's account-recovery system.

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
```

---

## 5. `recce doctor`

Sanity check: shows which API keys you have set, total site count, and how many NSFW sites are gated.

```bash
recce doctor
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
recce email your@email.com --deep
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
