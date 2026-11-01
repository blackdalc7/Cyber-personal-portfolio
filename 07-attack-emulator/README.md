# 07 · Attack Emulator

> Part of the [Threat Response Engineering portfolio](../README.md). Runs on its own; scores against [Watchfloor](../watchfloor/README.md).

This project closes the purple-team loop automatically. It runs Atomic Red Team tests on disposable lab machines, then asks the Watchfloor hub what the platform made of each one. Every technique gets one of six verdicts:

| Outcome | What it means | Who fixes it |
|---|---|---|
| **detected** | A finding for that technique (or its parent) fired on that host inside the scoring window | nobody |
| **prevented** | Endpoint protection blocked it (for example Defender quarantined the payload) | counted as covered |
| **telemetry only** | Events reached the lake, but no rule fired | detection engineering ([08](../08-detection-rules/README.md)) |
| **missed** | Nothing arrived at all | sensor and log pipeline |
| **error** | The test did not run cleanly, or the hub never answered | the lab |
| **skipped** | Dry run, or nothing to score against | n/a |

The results are an `emulation-run` JSON the Watchfloor coverage page reads, an ATT&CK Navigator layer, and a Markdown report with the gaps listed.

> **Lab only.** This tool executes real attack techniques. Every live target must be an IP inside `LAB_ALLOWED_CIDRS` (anything wider than a /16 is refused), every kubectl context must be named in `LAB_KUBE_CONTEXTS` *and* point at an API server inside those CIDRs, and a live run needs `--confirm-lab`. Use the [lab](../lab/README.md), which builds exactly such machines.

## The loop, with no lab at all

`scripts/purple_loop.py` runs the whole chain in one process with the real code of every piece: 07 replays recorded lab telemetry, the Watchfloor hub ingests it, the lake writer persists it to Parquet, 08's Sigma rules run on DuckDB and post findings back through the hub, and 07 polls and scores. Only Redis is faked (fakeredis) and time is virtual.

```bash
cd 07-attack-emulator
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt -r ../watchfloor/backend/requirements.txt -r ../08-detection-rules/requirements.txt fakeredis
python scripts/purple_loop.py
```

```
run-20261030T202140Z-5c0dd8: detection coverage 62.5%, telemetry coverage 87.5%
  T1003.008  Read /etc/shadow             detected in 1.1s
  T1136.001  Create local account         detected in 1.3s
  T1053.003  Cron persistence             detected in 1.9s
  T1070.003  Clear shell history          telemetry_only
  T1059.001  Encoded PowerShell           detected in 1.2s
  T1036.003  Masquerade as lsass.exe      detected in 1.5s
  T1087.001  Enumerate local accounts     telemetry_only
  T1562.001  Stop Sysmon                  missed
```

That output is committed in [examples/output](examples/output). The gaps are deliberate: clearing shell history and local account discovery have telemetry but no rule yet, and once the Sysmon driver is unloaded the host goes quiet, which is what "missed" looks like. Times to detect in this mode reflect the emulator's poll cadence, not real pipeline latency.

## Against the live stack

```bash
cp .env.example .env            # set EMU_HUB_TOKEN, EMU_INGEST_TOKEN, lab credentials
pip install -r requirements-dev.txt

# Replay into a running hub (docker compose up in ../deploy, with the detect profile for 08's rules)
python -m attack_emulator run campaigns/replay-demo.yml --fixtures tests/fixtures/replay

# See exactly what a live campaign would execute, without executing or contacting anything
python -m attack_emulator run campaigns/lab-windows.yml --dry-run

# Live, on the lab (see ../lab): Linux techniques in the runner pod, Windows over WinRM
python -m attack_emulator run campaigns/lab-linux.yml --confirm-lab
python -m attack_emulator run campaigns/lab-windows.yml --confirm-lab --only T1059,T1036

python -m attack_emulator report results/run-*.json     # Markdown for any run
python -m attack_emulator validate campaigns/*.yml
```

Point Watchfloor's coverage page at the results with `COVERAGE_07_DIR` in `deploy/.env` (the default is `examples/output`).

## Campaigns

A campaign names its targets and picks tests explicitly. "Run every test for a technique" is not allowed.

```yaml
name: Lab Linux (k8s runner pod)
settle_s: 20                     # quiet time between techniques, so scoring windows do not overlap
targets:
  - {name: k8s, executor: kubectl, hostname: lab-k8s, kube_context: microk8s, namespace: atomic}
tests:
  - technique: T1003.008
    name: Read /etc/shadow
    tactic: credential-access
    target: k8s
    test_names: ["Access /etc/shadow (Local)"]   # or test_numbers / test_guids
    telemetry_match: shadow                       # narrows "did telemetry arrive" to relevant events
    # input_args: {...}, timeout_s: 120, get_prereqs: false, cleanup: true
```

Tests are picked by name because names survive upstream renumbering. Check what a name resolves to on the target with `Invoke-AtomicTest T1003.008 -ShowDetailsBrief`.

| Executor | Reaches | How |
|---|---|---|
| `kubectl` | the lab's Atomic runner pod | `kubectl exec ... pwsh -EncodedCommand`, argv only |
| `winrm` | a Windows lab VM | pywinrm `run_ps` (NTLM) |
| `ssh` | a Linux lab VM | paramiko, `sudo -n pwsh -EncodedCommand`; unknown host keys rejected unless `EMU_SSH_TRUST_LAB_HOSTKEYS` |
| `replay` | the hub's `/api/ingest/ocsf` | recorded OCSF activity from `tests/fixtures/replay`, rebased to now; recorded findings are dropped |
| `dry-run` | nothing | prints the PowerShell it would send |

## How scoring works

1. The executor runs the test and records when it started.
2. The poller asks `/api/findings` for that technique on that host, with exponential backoff and full jitter (`EMU_POLL_BASE_S` doubling up to `EMU_POLL_MAX_S`), until a finding shows up or `EMU_POLL_TIMEOUT_S` passes. A sub-technique matches its parent and the other way round.
3. If nothing fired, it counts events from that host between the start and now (before cleanup, before the next test), filtered by `telemetry_match`. Some events means telemetry only; none means missed.
4. If every poll failed, the verdict is **error**, not missed: an unreachable hub says nothing about detection.
5. Cleanup runs (`Invoke-AtomicTest -Cleanup`) for every test that executed, then the campaign waits `settle_s`.

Output that means protection stopped the test (Defender's "contains a virus", AMSI's "malicious content and has been blocked", quarantine messages) is scored **prevented** without polling.

## Safety model

- **Guard rails before the first command.** `safety.check_campaign` refuses live targets without `--confirm-lab`, addresses that are not IP literals inside the lab CIDRs, and kube contexts that are not allowlisted or that resolve to an API server outside the lab.
- **No shell, no interpolation.** Campaign values become single-quoted PowerShell literals (`'` doubled), the script travels base64 UTF-16LE in `-EncodedCommand`, and `kubectl` gets an argv list. Campaign validation rejects multi-line values, odd argument names and quotes in paths before any of that.
- **Secrets only in `.env`.** WinRM and SSH credentials and both hub tokens come from the environment; `.env` is gitignored.
- **Replay never forges detections.** Fixtures go in as activity events only; a finding in a fixture file is dropped, so a "detected" can only come from the platform's own rules.

## Layout

```
src/attack_emulator/
  campaign.py      campaign schema and strict validation
  safety.py        lab guard rails
  executors/       kubectl, winrm, ssh, replay, dry-run; PowerShell command building
  poller.py        hub client, backoff, verdicts
  runner.py        run loop: execute, score, clean up, settle
  report.py        emulation-run JSON, Navigator layer, Markdown
  cli.py           validate | run | report
campaigns/         lab-linux.yml, lab-windows.yml, replay-demo.yml
scripts/
  build_fixtures.py  rebuild the replay fixtures from raw Tetragon/Sysmon records via Watchfloor's mappers
  purple_loop.py     the in-process end-to-end demo
tests/             96 tests (99% coverage) including the full loop against the real hub, lake and rules
```

## Tests

```bash
pytest --cov          # coverage gate is 85%
ruff check .
```

`tests/test_purple_loop.py` runs the end-to-end loop and asserts every verdict; it skips itself if the sibling projects or their dependencies are missing.

## Limits

- Live executors were written against the lab in [`../lab`](../lab/README.md) and unit-tested with fakes; they have not been run against real VMs in the environment this was built in (no hypervisor there). The replay path and the full scoring loop were run for real.
- Atomic test names come from the upstream `atomic-red-team` repository at the ref pinned in `lab/ansible/group_vars/all.yml`. Upstream renames would need a campaign update; `-ShowDetailsBrief` is the check.
- One technique at a time per host. Running two campaigns against the same host at once would blur both runs' telemetry counts.
