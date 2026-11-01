# 05 · Sigma-Validated ATT&CK Detection Coverage

> Part of the [Threat Response Engineering portfolio](../README.md). This folder is self-contained and can also be published as its own repository.

This tool turns a purple-team exercise into a measured **Detection Coverage** score. It answers three questions for every MITRE ATT&CK technique that was run:

1. Did the logs see it?
2. Did a standard **Sigma** rule fire on it?
3. If not, which team needs to fix the gap?

It reads the exercise's **exported logs**: Windows event XML (Sysmon Event ID 1 and Security Event ID 4688) and ECS NDJSON (Elastic, Winlogbeat or Auditbeat exports, and Project 01 output). It evaluates Sigma rules against them with a built-in engine and correlates the matches with the exercise timeline. The output is a coverage report, JSON and an **ATT&CK Navigator layer**.

The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

> **Scope.** This project scores an exercise from log files that have already been exported. It does not run payloads and does not read a live host's logs. The red team runs the procedures with its usual tooling (for example Atomic Red Team in a lab) and records when it ran each one in `exercise.yml`.

## Quick start

```bash
cd 05-sigma-attack-coverage
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

PYTHONPATH=src python -m attack_coverage lint --exercise examples/exercise.yml
PYTHONPATH=src python -m attack_coverage test-rules --require-all
PYTHONPATH=src python -m attack_coverage score --exercise examples/exercise.yml \
    --logs examples/logs/ws01_windows_events.xml examples/logs/srv01_auditbeat.ndjson \
    --report out/coverage.md --json out/coverage.json --navigator out/layer.json
```

```
Detection coverage 50.0% | telemetry coverage 87.5% | 8 techniques, 15 process events
  TELEMETRY_GAP  T1082      System Information Discovery
  NO_CONTENT     T1057      Process Discovery
  DETECTION_GAP  T1016      System Network Configuration Discovery
  DETECTION_GAP  T1083      File and Directory Discovery
  DETECTED       T1033      System Owner/User Discovery
  ...
```

The rendered results are in [examples/output/](examples/output/). To view the layer, open the ATT&CK Navigator, choose "Open Existing Layer", and upload `navigator_layer.json`.

## What each outcome means

| Outcome | Meaning | Who fixes it |
|---|---|---|
| `DETECTED` | An expected Sigma rule matched an event from that host inside the step's time window | Nobody |
| `DETECTION_GAP` | The host logged process activity in the window, but no expected rule matched | Detection engineering. The report includes the evidence lines to write the rule from |
| `TELEMETRY_GAP` | No process events from the host in the window, so no rule could ever fire | Logging or platform. Enable Sysmon or 4688 with command line (or auditd execve) and check forwarding |
| `NO_CONTENT` | The catalogue maps no rule to this technique on this platform | Detection engineering |

A technique counts as covered only if it was detected on **every** host it was run on. In the example, T1082 is caught on `ws01` and `srv01`, but `ws02` sends no telemetry, so T1082 is a gap.

## Exporting logs

```powershell
# Windows: Sysmon and Security process creation for the exercise window
wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=1)]]" /f:xml /e:Events > ws01_sysmon.xml
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:xml /e:Events > ws01_4688.xml
```

For Elastic or OpenSearch, export the time range as NDJSON. Either one ECS document per line or raw `_source` hits work.

## Detection as code

- Rules live in `rules/` in the standard Sigma format.
- Each rule has positive and negative cases in `rule-tests/`. `test-rules --require-all` fails CI if a rule has no tests or a case breaks.
- `lint` checks that every rule ID in the catalogue exists, that each rule's `attack.tXXXX` tag matches the technique it is mapped to, and that the exercise file is valid.

## Tests

```bash
pytest --cov      # 68 tests, 98% coverage, gate 85%
```

The suite covers:

- Every supported Sigma modifier and condition form, including operator precedence, `1 of`, `all of them` and the `_helper` convention.
- Rule-schema validation.
- Loud failure on unsupported modifiers.
- Sysmon and 4688 normalisation, including hex PIDs and 7-digit Windows timestamps.
- XXE rejection.
- ECS variants (nested, flattened and raw hits).
- Exercise validation and the outcome logic.
- Clock skew.
- The Navigator layer.
- CLI exit codes.

## Project layout

```text
05-sigma-attack-coverage/
├── src/attack_coverage/
│   ├── cli.py             `lint`, `test-rules` and `score` subcommands
│   ├── sigma/             the Sigma engine: rule loading, modifiers, condition grammar
│   ├── logs/              Windows XML and ECS NDJSON loaders
│   ├── catalog.py         technique catalogue and exercise files
│   ├── coverage.py        scoring, Markdown/JSON outputs and the ATT&CK Navigator layer
│   └── ruletests.py       detection-as-code test runner
├── rules/                 Sigma rules (windows/, linux/)
├── rule-tests/            positive and negative cases for every rule
├── techniques/catalog.yml technique → expected rules
├── examples/              exercise, log exports and sample outputs
├── tests/                 pytest suite
├── docs/ARCHITECTURE.md
└── .env.example
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt ruff
ruff check .            # lint, using this folder's ruff.toml (includes security rules)
pytest --cov            # tests with the 85% coverage gate
```

Every module, class and public function has a docstring explaining what it does,
its arguments and the errors it raises. Start reading at `docs/ARCHITECTURE.md`,
then the entry point named in the layout above.

CI (`.github/workflows/ci.yml`) runs lint and tests on Python 3.10 and 3.13,
`pip-audit` on the runtime dependencies.

## Licence

MIT. See [LICENSE](LICENSE).
