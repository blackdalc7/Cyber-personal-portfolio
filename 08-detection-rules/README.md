# 08 · Detection Rules (Sigma → OCSF → DuckDB)

> Part of the [Threat Response Engineering portfolio](../README.md). Runs over the [Watchfloor](../watchfloor/README.md) lake.

Ordinary Sigma rules, compiled with **pySigma** through a custom **OCSF processing pipeline** and a custom **DuckDB backend**, run on a schedule over Watchfloor's Parquet lake. Hits go back to the hub as OCSF Detection Findings, where the incident view, the playback scorer and [07](../07-attack-emulator/README.md)'s emulation runs pick them up.

Every rule ships with samples that must match and samples that must not. The build fails if any of them do the wrong thing, and so does the Docker image.

```
$ python -m detection_rules test -q
7 rules, 26/26 rule tests passed
```

## Why a custom backend

Sigma rules use log-source field names (`Image`, `CommandLine`, `TargetFilename`). The lake stores OCSF 1.4.0. The pipeline maps one to the other, and the backend writes SQL that DuckDB runs directly against Parquet:

| Sigma field | `ocsf_flat` column | OCSF source |
|---|---|---|
| `Image` | `process_path` | `process.file.path` (or `actor.process.file.path`) |
| `CommandLine` | `cmd_line` | `process.cmd_line` |
| `ParentImage`, `ParentCommandLine` | `parent_path`, `parent_cmd_line` | `process.parent_process.*` |
| `TargetFilename` | `target_file` | `file.path` |
| `User` | `user_name` | `actor.user.name` / `process.user.name` |
| `SourceIp/Port`, `DestinationIp/Port` | `src_ip`, `src_port`, `dst_ip`, `dst_port` | `src_endpoint`, `dst_endpoint` |
| `ProcessId`, `ParentProcessId`, `Computer` | `process_pid`, `parent_pid`, `hostname` | |

| Logsource category | OCSF filter |
|---|---|
| `process_creation` | Process Activity [1007], Launch |
| `file_access` | File System Activity [1001], Read |
| `file_event` | File System Activity [1001], Create or Update |
| `file_delete` | File System Activity [1001], Delete |
| `network_connection` | Network Activity [4001] |

A field or category without a mapping fails the conversion loudly instead of silently matching nothing.

A compiled rule looks like this (`build/queries/*.sql` has all of them):

```sql
SELECT uid, time, hostname, ... FROM ocsf_flat
WHERE time >= ? AND time < ? AND class_uid = 1001 AND activity_id = 2
  AND ((coalesce(target_file ILIKE '/etc/shadow' ESCAPE '\', false) OR ...)
  AND NOT (coalesce(process_path ILIKE '%/unix\_chkpwd' ESCAPE '\', false) OR ...))
ORDER BY time
```

Design choices worth knowing:

- **Case-insensitive by default**, as Sigma specifies: `ILIKE`. `|cased` switches to `LIKE`; `|re` uses RE2 via `regexp_matches`.
- **Nothing reaches SQL unescaped.** Quotes are doubled, `%` `_` `\` are escaped for `LIKE`, and the time window is a bind parameter. Tests prove an injection-shaped value matches only itself.
- **Missing fields do not break `not` filters.** Every comparison is wrapped in `coalesce(..., false)`, so `selection and not filter` still matches an event that has no parent process, where plain SQL NULL logic would have dropped it.

## Rules

| Rule | Technique | Level | Notes |
|---|---|---|---|
| Read of /etc/shadow by a process that has no business reading it | T1003.008 | high | Tetragon `security_file_permission`; tuned after sudo's `unix_chkpwd` alerted on every login |
| Local account created with useradd or adduser | T1136.001 | medium | |
| Crontab replaced from a file | T1053.003 | high | `-l`, `-e`, `-r` excluded |
| PowerShell started with an encoded command | T1059.001 | high | every prefix of `-EncodedCommand` down to `-e`/`-ec`; ignores Linux `pwsh` (07's own transport) |
| Windows system process name running from the wrong folder | T1036.003, T1036.005 | critical | lsass, svchost, csrss... outside System32/SysWOW64/WinSxS |
| Scheduled task created to run at startup or logon | T1053.005 | medium | |
| LSASS memory dump through comsvcs.dll MiniDump | T1003.001 | critical | |

The first and the fifth close the two gaps 05's purple-team exercise reported (shadow read, masquerading).

## Run it

```bash
cd 08-detection-rules
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export PYTHONPATH=src

python -m detection_rules test                     # samples, per rule
python -m detection_rules build                    # test, then build/rules_index.json + build/queries/*.sql
python -m detection_rules convert rules/linux/*.yml   # print the SQL

cp .env.example .env                               # RULES_LAKE_DIR, RULES_HUB_URL, RULES_INGEST_TOKEN
python -m detection_rules run --dry-run            # one cycle, findings printed as NDJSON
python -m detection_rules run --watch --interval 60
```

In the stack, `docker compose --profile detect up` in [`../deploy`](../deploy/README.md) runs the `rules` service with the lake mounted read-only, and the hub serves `build/rules_index.json` at `/api/rules` for the console's Rules page.

## How the runner works

Each cycle opens the lake read-only, runs every rule over `[watermark - RULES_OVERLAP_S, now)` and posts new findings as NDJSON to the hub's `/api/ingest/ocsf`, from where they flow through the same stream and lake as everything else.

- **Late events.** The lake writer batches, so an event can land after the cycle that should have seen it. The overlap re-reads the last few minutes.
- **No duplicates.** A finding's uid is `sha256(rule id | event uid)`, so the overlap cannot double-report, and the runner remembers what it sent until the event falls out of the re-read window.
- **No silent loss.** If the hub is down, the cycle fails before the watermark moves, and the next cycle retries the same window. A rule that errors is reported and skipped; the others still run.
- **Bounded.** `RULES_MAX_FINDINGS_PER_RULE` caps one rule's output per cycle, so a bad rule cannot flood the queue.

## Adding a rule

1. Write `rules/<platform>/<category>_<name>.yml` with a fresh UUID `id`, ATT&CK tags (`attack.t1059.001`, `attack.execution`) and a `level`.
2. Write `samples/<same name>.yml` with at least one `match` and one `nomatch` event. Samples are partial OCSF; the loader fills in the envelope. Put the false positive you tuned away in `nomatch`, and say why in a `tuned_from` field on the rule.
3. `python -m detection_rules build` and commit `build/`.

The finding validates against Watchfloor's OCSF schema in the tests, and so does every sample.

## Layout

```
src/detection_rules/
  backend.py    OCSF pipeline + DuckDB backend (pySigma 2.0)
  lake.py       read-only lake access and the ocsf_flat view; in-memory lakes for tests
  rules.py      load and compile rule files, metadata from tags
  testing.py    sample-based rule tests
  findings.py   OCSF Detection Finding [2004] from a hit
  runner.py     watermark/overlap cycles, hub sink, state file
  index.py      build/rules_index.json and build/queries/*.sql
  cli.py        test | build | convert | run
rules/ samples/ build/ tests/
```

## Tests

```bash
pytest --cov       # 37 tests, 98% coverage; gate 85%
ruff check .
```

## Limits

- Single-event rules only. Sigma correlation rules (counts, sequences) are not converted yet; the backend raises rather than guessing.
- `cidr` and keyword (unbound value) searches are not supported by this backend.
- Tetragon export is the Linux source and Sysmon via Fluent Bit the Windows one; rules for other sources need their fields added to the pipeline first.
