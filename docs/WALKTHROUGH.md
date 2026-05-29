# Recce v0.5.0 Walkthrough

This walkthrough is the cold-handoff proof for the learning-frame done criteria:
a fresh install works, the CLI can be discovered without project context, and a
real investigation can be created, run, exported, and closed.

## Fresh Install Smoke

Run on 2026-05-29 in a throwaway Python 3.13.7 virtual environment outside the
repo working directory.

```bash
python3 -m venv /tmp/recce-walkthrough/venv
/tmp/recce-walkthrough/venv/bin/python -m pip install --upgrade pip
/tmp/recce-walkthrough/venv/bin/python -m pip install '.[gui]'
cd /tmp/recce-walkthrough
/tmp/recce-walkthrough/venv/bin/recce --version
/tmp/recce-walkthrough/venv/bin/recce doctor --no-network
/tmp/recce-walkthrough/venv/bin/recce username --list-categories
```

Observed result:

- `recce --version` printed `recce 0.5.0`.
- `doctor --no-network` loaded the CLI, config, provider registry, WMN cache
  state, and Pro entitlement state without errors.
- `username --list-categories` loaded 722 username sites, with 41 NSFW sites
  gated behind `--nsfw`.

The same session also verified editable installs on Python 3.13.7:

```bash
python3 -m venv /tmp/recce-editable/venv
/tmp/recce-editable/venv/bin/python -m pip install -e '.[dev,gui]'
cd /tmp/recce-editable
/tmp/recce-editable/venv/bin/recce --version
/tmp/recce-editable/venv/bin/recce-gui --help
```

Both console scripts worked from outside the repo directory.

## Real Investigation Smoke

Run on 2026-05-29 using passive domain mode only. No active subdomain
bruteforce was used.

Three public domain subjects were investigated:

| Subject | Sources checked | Confirmed findings | Notes |
|---|---:|---:|---|
| `microsoft.com` | 27 | 23 | RDAP, DNS, Microsoft 365, web, passive subdomains, Wayback |
| `github.com` | 26 | 20 | RDAP, DNS, Microsoft 365, web, passive subdomains, Wayback |
| `openai.com` | 24 | 19 | RDAP, DNS, Google Workspace, M365 realm, Cloudflare, passive subdomains, Wayback |

For each subject Recce:

1. Created an investigation case.
2. Ran `search_domain()` with passive defaults and `validate_subs=False`.
3. Saved the run into the local SQLite investigation store.
4. Exported full and redacted JSON, Markdown, and PDF evidence.
5. Closed the investigation with an audit reason.

The generated exports were stored locally under
`artifacts/final-stretch-real-use/` and deliberately not committed. They are
public-domain smoke evidence, but still investigation outputs rather than source
files.

## What A Colleague Should Notice

- A cold install reaches working CLI commands without hidden setup.
- Missing API keys degrade to provider status rows rather than hard failures.
- Domain mode gives an investigator a compact first answer: ownership age,
  DNS/network, email posture, web surface, passive subdomains, and first-seen
  history.
- Full and redacted exports are generated from the same saved case data.
- Closed cases leave an audit trail but disappear from the default active-case
  list.
