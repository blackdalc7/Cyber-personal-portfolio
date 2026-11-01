# 09 · Evidence Timeline (Velociraptor + Hayabusa)

> Part of the [Threat Response Engineering portfolio](../README.md). Started by n8n after a human approves containment in [02](../02-hitl-soar-bot/README.md).

When an analyst approves isolating a host, the evidence on that host is about to matter. This service collects it right then. It runs Hayabusa and a few read-only triage artifacts on the endpoint through **Velociraptor**, pulls the platform's own telemetry for the same host and window from **Watchfloor**, merges everything into one sorted timeline, and writes a package where every file is SHA-256 hashed in a manifest. The Watchfloor console shows the package on the incident page.

```
02: analyst clicks Approve ─► signed decision webhook ─► n8n ─► signed POST /collect ─► 09
                                                                                          │
     Velociraptor server ◄── gRPC (VQL with env variables) ── find client, collect_client(Hayabusa, Pslist,
          │                                                    Netstat, Autoruns), wait, read results
          ▼
     lab-win01 runs the artifacts                    Watchfloor hub /api/events?hostname=...&since=&until=
                                                                                          │
                          evidence/<incident>/ raw/*.jsonl · timeline.csv · timeline.jsonl ·
                                               manifest.json · manifest.json.sha256
```

## What a package looks like

[examples/output/INC-20261026-F64AEE6E](examples/output/INC-20261026-F64AEE6E) was built by `scripts/build_example.py`, which runs the real Watchfloor hub in-process over the maldoc-to-ransomware scenario and uses the Hayabusa CSV in `examples/hayabusa/ws01.csv` as the endpoint side. It merges 10 Hayabusa rows with 50 Watchfloor events into 60 timeline rows. The manifest's highlights put the two views side by side:

```
09:00:12.000  critical  watchfloor:edr-canary  Office application spawned a shell or script host
09:00:12.000  high      hayabusa               Suspicious Office Child Process
09:00:12.500  high      hayabusa               Suspicious Encoded PowerShell Command Line
09:00:12.700  high      hayabusa               Potential Download Cradle (IEX DownloadString)
09:00:20.000  critical  hayabusa               Process Masquerading As Svchost (Typo Name)
09:00:23.400  critical  watchfloor:edr-canary  Mass file modification (possible encryption)
09:00:24.000  critical  hayabusa               Shadow Copies Deletion Using Operating Systems Utilities
```

The endpoint saw the download cradle and the shadow-copy deletion, which the EDR canary did not report. That gap is why the collection exists.

## Run it

```bash
cd 09-evidence-timeline
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export PYTHONPATH=src

# Offline: a Hayabusa CSV you already have, at EVIDENCE_LOCAL_DIR/<host>.csv
EVIDENCE_MODE=local python -m evidence_timeline collect --incident INC-TEST --host ws01
python -m evidence_timeline verify evidence/INC-TEST          # re-hash everything against the manifest

# The service n8n calls
cp .env.example .env          # EVIDENCE_SHARED_SECRET, VELOCIRAPTOR_API_CONFIG, EVIDENCE_HUB_*
python -m evidence_timeline serve
```

In the stack it is the `evidence` service of the `dfir` profile in [`../deploy`](../deploy/README.md), next to the Velociraptor server. The server writes `api.config.yaml` into its volume on first start, and the evidence container reads it through a shared group, with no other access to the server's files.

### Velociraptor setup

1. `docker compose --profile dfir up -d` in `deploy/` (set `VELOCIRAPTOR_URL` and `VELOCIRAPTOR_SHA256` first; the image verifies the binary).
2. Enrol `lab-win01` with the client config (see [lab/README.md](../lab/README.md#velociraptor)).
3. Import `Windows.EventLogs.Hayabusa` from the Velociraptor artifact exchange in the GUI (Server Artifacts → `Server.Import.ArtifactExchange`). It downloads and runs Hayabusa on the endpoint and returns its detections as rows.

## API

| Method | Path | Auth | |
|---|---|---|---|
| `POST` | `/collect` | HMAC: `X-SOAR-Timestamp`, `X-SOAR-Signature: sha256=HMAC(secret, "<ts>." + body)` | `{"incident_id", "host", "around_ms"?, "requested_by"?, "decided_by"?, "reason"?, "force"?}`. Answers 202 with the job, or 200 with the existing job (one per incident unless `force`) |
| `GET` | `/jobs/{incident_id}` | same, over an empty body | `queued`, `running`, `done` (with package path and row count) or `failed` (with the error) |
| `GET` | `/healthz` | none | |

## Safety

- **Only signed requests start a collection.** Timestamps outside five minutes are refused, and so is a signature already seen, so a captured request cannot be replayed. It is the same signing scheme 02 uses, with its own secret.
- **Read-only artifacts only.** `HAYABUSA_ARTIFACT` and `TRIAGE_ARTIFACTS` must match an allowlist (event logs, process and network state, autoruns, forensics); anything with remediation, quarantine, delete, kill, shell or upload in the name is refused at start-up. Containment itself stays in 02.
- **No string-built VQL.** Host, client, flow and artifact names reach Velociraptor as query environment variables, so a hostile host name cannot change the query. A test proves it with `ws01' OR 1=1 --`.
- **Input that becomes a path is checked twice.** Incident ids and hosts are validated by the API and again by the job itself; file names inside a package are sanitised.
- **Evidence is never overwritten.** Packages are built in a temporary directory and renamed into place. A forced re-collection moves the earlier package aside instead of replacing it. `verify` recomputes every hash, and `manifest.json.sha256` covers the manifest itself.
- **Attacker-controlled text is defanged for spreadsheets.** Timeline CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'`.
- A hub outage does not fail the collection: the package is written with a warning in the manifest.

## Layout

```
src/evidence_timeline/
  app.py           signed HTTP API (FastAPI)
  jobs.py          one collection: endpoint + hub -> package; job store (one job per incident)
  velociraptor.py  gRPC client: find client, collect_client, wait, source()
  hayabusa.py      Hayabusa CSV / artifact rows -> timeline rows
  timeline.py      Watchfloor events, triage snapshots, merge, highlights, CSV/JSONL
  package.py       atomic package writing, SHA-256 manifest, verification
  signing.py       HMAC verification with replay protection
  config.py        EVIDENCE_* settings and the artifact allowlist
  cli.py           serve | collect | verify
scripts/build_example.py   the example package, against the real hub
```

## Tests

```bash
pytest --cov      # 34 tests, 99% coverage; gate 85%
ruff check .
```

The Velociraptor side is tested against a fake server that checks every query is parameterised, and the gRPC wiring against a stubbed channel. A real collection needs the lab.
