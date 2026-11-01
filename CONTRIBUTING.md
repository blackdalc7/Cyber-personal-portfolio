# Contributing

## Layout

Every numbered project is a top-level folder named `NN-short-name/` and must be self-contained (Watchfloor, `automation/`, `lab/`, `deploy/` and `packages/` are the shared platform around them):

```
NN-name/
  README.md             overview, quick start, project layout, development and tests
  src/<package>/        implementation, with docstrings on every module, class and public function
  tests/                pytest or Pester; must run offline
  docs/ARCHITECTURE.md  problem, data flow, decision table, limits
  requirements.txt      runtime deps (bounded ranges)
  requirements-dev.txt  -r requirements.txt + test tools
  ruff.toml             lint config (Python projects)
  .env.example          every variable the project reads, with empty secrets
  .github/              the project's own CI workflow and Dependabot config
  LICENSE, .gitignore, .editorconfig
```

A new project must have all of these. It must also be added to the matrices in the root `.github/workflows/ci.yml` and `.github/dependabot.yml`, to `PY_PROJECTS` in the `Makefile`, and to the tables in `README.md` and `docs/ARCHITECTURE_DEFENSE.md`.

## Before opening a pull request

```bash
make lint
make test                                   # or: make test P=<project>
```

- **No placeholders.** Do not commit `TODO` stubs, `pass` bodies or "insert logic here". If a feature is not finished, leave it out.
- **Documentation.** New modules, classes and public functions need a docstring that says what they do, not how. Note arguments, return values and raised errors where they are not obvious. PowerShell commands need comment-based help.
- **Tests.** Keep coverage at or above the 85% gate. New detection logic needs both positive and negative cases. Sigma rules need cases in `rule-tests/`, and the FP reducer must keep 100% true-threat recall in `evaluate`.
- **Secrets.** Never put a credential in code, tests or examples. Use `os.environ` and dotenv, and add the variable to `.env.example` with an empty value.
- **Network.** Tests must not reach the internet. Mock HTTP clients (see the fake Anthropic clients in 01 and 06), and use recorded fixtures for feeds.
- **Defensive scope.** Contributions that add exploit code, payloads or evasion techniques will not be accepted.

## Commit style

Use a short imperative subject with the project prefix, for example `06: treat scans as sweeps when clustering`. The body explains *why*.
