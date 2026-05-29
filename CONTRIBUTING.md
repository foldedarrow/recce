# Contributing

External contributions are welcome, but please open an issue first to discuss
the proposed change and fit.

Because Recce is AGPL-3.0-or-later and may also be offered under a separate
commercial licence, external contributions require signing a Contributor Licence
Agreement before they can be merged. CLA paperwork will follow once a
contribution is accepted in principle.

## Development install

Contributor installs can use editable mode:

```bash
git clone https://github.com/foldedarrow/recce.git
cd recce
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,gui]'
```
