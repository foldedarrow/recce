# Self-hosting the recce web GUI

Run `recce-gui` (Streamlit) as a service on loopback and front it with a
reverse proxy that adds a login. Exposed over a private tailnet with
[Tailscale Serve](https://tailscale.com/kb/1312/serve) — no public exposure.

## 1. Install

```bash
sudo install -d -o "$USER" -g "$USER" /opt/recce
git clone https://github.com/foldedarrow/recce.git /opt/recce
python3 -m venv /opt/recce/.venv          # Python 3.11–3.13 recommended
/opt/recce/.venv/bin/pip install -U pip wheel
/opt/recce/.venv/bin/pip install '/opt/recce[gui]'
```

Optional API keys live in the service user's `~/.config/recce/.env` — the GUI's
API Keys tab writes there (see `.env.example` for the names). recce works
without them, degrading paid sources to `skipped`. `/etc/recce/web.env` is for
service settings such as `RECCE_TIMEOUT`; only put a key there to override the
user file, and don't copy blank placeholders in.

## 2. systemd service

The unit is sandboxed (`ProtectSystem=strict`), so pre-create the dirs recce
writes to before first start:

```bash
sudo cp deploy/recce-web.service /etc/systemd/system/   # edit User/Group/HOME first
install -d -m0700 ~/.config/recce ~/.local/share/recce ~/.cache ~/.streamlit
sudo systemctl daemon-reload
sudo systemctl enable --now recce-web
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8501/_stcore/health   # 200
```

Optional weekly WhatsMyName refresh:

```bash
sudo cp deploy/recce-update.service deploy/recce-update.timer /etc/systemd/system/
sudo systemctl enable --now recce-update.timer
```

Optional weekly site selftest (Monday 04:00, after the WMN refresh). It probes
every username site definition with a known account and a made-up one and
saves `~/.cache/recce/selftest.json`; searches (CLI and GUI) then skip sites
caught reporting made-up usernames as existing:

```bash
sudo cp deploy/recce-selftest.service deploy/recce-selftest.timer /etc/systemd/system/   # edit User/Group/HOME
sudo systemctl daemon-reload
sudo systemctl enable --now recce-selftest.timer
sudo systemctl start recce-selftest.service       # optional first run (~5–10 min)
journalctl -u recce-selftest -n 80 --no-pager      # results table + changes since last run
```

If `RECCE_NTFY_URL` is set (see the monitoring section), the weekly run also pushes
an alert when definitions newly break or the exit gets walled more.

Verdicts: `healthy`, `false_positive` (skipped in searches), `false_negative`,
`blocked` (401/403/429 or a bot challenge — depends on the egress IP, which
the report records; not treated as broken), `error`, and `unverified` (no
known account to test with). To probe flagged sites anyway, pass
`--flagged-sites mark` (probe, downgrade hits) or `off`, or set
`RECCE_FLAGGED_SITES` in `/etc/recce/web.env` for the GUI. A flag expires
after 30 days or as soon as the site's definition changes.

### Investigation monitoring + ntfy alerts

Optional daily re-run of every **open** case's saved searches
(`recce investigations monitor`). It saves each re-run to the case and sends an
[ntfy](https://ntfy.sh) push only when a run finds evidence that no earlier run
of that search had, so a site that was briefly blocked doesn't alert when it
answers again. Deep and bruteforce searches are skipped unless the unit adds
`--include-active`.

Add to `~/.config/recce/.env` (not `web.env`):

```bash
RECCE_NTFY_URL=https://ntfy.sh/<long-random-topic>   # or your own ntfy server
# RECCE_NTFY_TOKEN=tk_...                             # if the topic is protected
# RECCE_NTFY_DETAIL=1                                 # include searches + sources
```

Alerts name the **case reference and counts only** by default: anyone who knows
a public ntfy.sh topic can read it, so pick a long random topic, or self-host
ntfy, before turning on `RECCE_NTFY_DETAIL`.

```bash
sudo cp deploy/recce-monitor.service deploy/recce-monitor.timer /etc/systemd/system/   # edit User/Group/HOME
sudo systemctl daemon-reload
sudo systemctl enable --now recce-monitor.timer
recce investigations notify-test                  # confirm the phone gets it
sudo systemctl start recce-monitor.service        # optional first run
journalctl -u recce-monitor -n 60 --no-pager
```

## 3. Caddy + login

```bash
caddy hash-password                        # paste the hash into the Caddyfile
# merge deploy/Caddyfile.example into /etc/caddy/Caddyfile, then:
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl restart caddy               # use restart, not reload, if `admin off`
```

## 4. Expose over Tailscale

```bash
sudo tailscale serve --bg --https=8443 http://127.0.0.1:8081
sudo tailscale serve status
```

Browse to `https://<node>.<tailnet>.ts.net:8443` and log in.
To remove: `sudo tailscale serve --https=8443 off`.
