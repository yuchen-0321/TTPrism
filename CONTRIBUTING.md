# Contributing to TTPrism

Thanks for your interest! TTPrism welcomes two kinds of contributions:

- **ATT&CK mapping rules** in `rules/attack/*.yaml`. These need no Python; see
  [rules/attack/README.md](rules/attack/README.md).
- **Code**: extraction, parsers, exporters, tests.

Security vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues or pull requests.

## Data handling rules

These rules protect you, your employer and the project. Pull requests that break them will be
closed and the offending data removed from history.

1. **TLP:CLEAR only.** Rules, tests and examples may only use public information. Never commit
   IOCs, samples or report text you received under TLP:GREEN/AMBER/RED, an NDA, or through your work.
2. **No malware.** Do not commit malware, droppers, exploit code, or password-protected archives of
   them. Use hashes and short, sanitized excerpts.
3. **Prefer reserved values in tests.** Use `example.com`, the `.example` / `.test` TLDs and the
   documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) so
   tests never point at a real third party. Hashes should be digests of harmless strings.
4. **Credit sources.** When a rule or test is based on a public report or rule set, link it and
   respect its license.

## Development setup

Requires Python 3.11 or newer and pip 25.1 or newer (for dependency groups).

```sh
git clone https://github.com/yuchen-0321/TTPrism.git
cd TTPrism
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install --group dev -e .
```

## Before you open a pull request

```sh
python -m pytest                 # unit, ReDoS and fuzz tests
ruff check src tests scripts
ruff format src tests scripts
mypy
ttprism validate-rules           # if you touched rules/
```

CI runs the same checks on Linux, Windows and macOS.

Guidelines:

- **Regexes run on attacker-controlled input.** Start patterns with a negative lookbehind so they
  can only match at a token boundary, bound every repetition, and add a pathological case to
  `tests/test_redos.py` for any new pattern.
- Add a positive and a negative test case for every new IOC form.
- Keep runtime dependencies minimal; each one is supply-chain risk for every user.
- Update `CHANGELOG.md` under *Unreleased* for user-visible changes.

## Updating bundled data

- ATT&CK catalog: `python scripts/update_attack_catalog.py`, then bump `attack_version` in the rule
  files after reviewing the warnings from `ttprism validate-rules`.
- TLD list: `python scripts/update_tlds.py`.

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
