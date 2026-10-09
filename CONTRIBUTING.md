# Contributing

Thanks for helping. Bug reports, reports of what works (or does not) on your
database version, documentation fixes and code are all welcome.

**Security issues are never filed in public.** Report them privately through
GitHub's private vulnerability reporting, as [`SECURITY.md`](SECURITY.md)
describes.

## Set up

```bash
uv sync --locked --all-extras
uv pip install --python .venv/bin/python --require-hashes -r .github/ci-pip-requirements.txt
```

This is the install CI runs: the locked dependencies, every driver, and pip
(the offline bundle builder's tests need it).

## Run the checks

```bash
.venv/bin/python -m pytest -o addopts='' -q tests/unit         # what CI runs
.venv/bin/ruff check src tests scripts && .venv/bin/mypy --strict src
.venv/bin/python scripts/prepare_offline_bundle.py --check-locks
```

Tests that talk to real databases run only with `UDBMCP_LIVE_FIXTURES=1`,
against the local mock databases that `scripts/fixtures/start_mock_dbs.sh`
starts (`docs/mock-environment.md`); the container-based package tests run
only with `UDBMCP_DOCKER_TESTS=1`. CI runs the unit suite in two parallel jobs
(`.github/workflows/ci.yml`); both must pass.

## What a change needs

- **One topic per pull request**, with tests for the behaviour it changes.
- **Safety changes come with an attack.** A change to the SQL guard, masking,
  session settings or the executor needs a test that tries to get past it: a
  statement, an encoding or a timing that the old code let through or the new
  code must refuse. The guard refuses what it cannot parse; keep it that way.
- **Claims stay true.** The README, the landing page and `docs/` state only
  what tests or recorded evidence show, and several tests re-derive those
  claims from the code. `IMPLEMENTATION_STATUS.md` is the ledger of what is
  verified and what is not.
- **Dependencies move by review.** A runtime dependency changes through
  `requirements/runtime.in`, `prepare_offline_bundle.py --refresh-locks` and a
  matching `uv.lock` (`docs/offline-build.md`). `pyproject.toml` caps some
  dependencies to reviewed series (the SQL parser and the HTTP stack among
  them): moving past a cap needs a review of the code that depends on it.
- **CI files are guarded.** `tests/unit/test_hardening_2026_09_27_ci_hygiene.py`
  checks the workflows, the pytest configuration and the test helpers: a
  change there needs a reviewer as well as a passing test.

## Adding a database engine

`docs/adding-connectors.md` describes the connector interface, the guard
dialect and the read-only session each engine needs. Open a
"New database engine" issue first, so the session-safety approach can be
agreed before the code.

## License

Contributions are made under the [Apache License 2.0](LICENSE), the
project's license (its section 5 covers contributions). Taking part means
following the [code of conduct](CODE_OF_CONDUCT.md).
