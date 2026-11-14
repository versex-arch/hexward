# Contributing

Thanks for wanting to improve hexward. Bug reports, false-positive reports and new detection rules are all welcome.

## Getting started

```console
git clone https://github.com/versex-arch/hexward && cd hexward
pip install -e .[dev]
pytest
```

The code is plain Python 3.10+ with no runtime dependencies; please keep it that way.

## What makes a good change

- **A detection rule** comes with a test that shows what it catches and a harmless sample it must not flag.
  Rules produce a `Finding` with a severity, evidence and advice a non-expert can act on.
- **A false positive** report includes the finding (`--json` output is ideal) and why the item is legitimate.
  Remove anything private first: user names, paths, addresses, tokens.
- **Interface text** is added to every language in `src/hexward/ui.html`; the test suite and the app expect all
  six dictionaries to have the same keys.
- Checks only read. Anything that changes the system (quarantine, autostart, canaries) must be an explicit
  action of the user and must be reversible.

## Before opening a pull request

- `pytest` passes.
- `hexward ai . --exclude "tests/*"` reports nothing (the tests contain sample attack text on purpose).
- New behaviour is described in `docs/usage.md` and `CHANGELOG.md`.
