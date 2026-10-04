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

Optional API keys go in `/etc/recce/web.env` (see `.env.example`); recce works
without them, degrading paid sources to `skipped`.

## 2. systemd service

```bash
sudo cp deploy/recce-web.service /etc/systemd/system/   # edit User/Group/HOME first
sudo systemctl daemon-reload
sudo systemctl enable --now recce-web
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8501/_stcore/health   # 200
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
