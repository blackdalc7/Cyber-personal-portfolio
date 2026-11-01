# Deploy: the whole Watchfloor stack with Docker Compose

```bash
cd deploy
cp .env.example .env        # fill in every REQUIRED value; generate secrets with secrets.token_urlsafe(48)
docker compose up -d --build
open http://127.0.0.1:8000  # dashboard (enter WF_HUB_TOKEN when asked)
```

## Services

| Service | Profile | Port (host) | Role |
|---|---|---|---|
| `redis` | core | none | Redis Streams spine (password, AOF on, `noeviction`) |
| `ingest` | core | none | Stream to Parquet lake writer |
| `adapters` | core | none | 01 NDJSON tail, 06 queue watcher, 02 incident poller |
| `hub` | core | 127.0.0.1:8000 | API, SSE, ingest endpoint and the dashboard |
| `siem` (01) | core | 127.0.0.1:5514/udp | Syslog detection and AI chain summaries |
| `soar-bot` (02) | core | 127.0.0.1:8080 | Human-approved containment over Slack or Discord |
| `n8n` | automation | 127.0.0.1:5678 | Playbooks in [`../automation/n8n`](../automation/n8n) |
| `rules` (08) | detect | none | Sigma rules over the lake, findings back to the hub |
| `evidence` (09) | dfir | none | Velociraptor and Hayabusa collection on approval |
| `velociraptor` | dfir | 127.0.0.1:8889 GUI, 8100 frontend | DFIR server for the lab endpoints |
| `analyst` (10) | ai | none | Cited AI investigations for new incidents |
| `exposure` (04), `triage` (06) | batch | none | One-shot jobs: `docker compose --profile batch run --rm exposure` |

Start more profiles with `--profile`, for example
`docker compose --profile automation --profile detect --profile dfir --profile ai up -d --build`.

## Connecting the lab

The lab VMs live on the host-only network 192.168.56.0/24 (see [`../lab`](../lab/README.md)). For them to ship
telemetry and enrol in Velociraptor, bind those ports to the host-only address in `.env`:

```
HUB_BIND=192.168.56.1
SYSLOG_BIND=192.168.56.1
VELO_FRONTEND_BIND=192.168.56.1
```

Keep the dashboard token set whenever `HUB_BIND` is not 127.0.0.1.

## Slack, Discord and n8n callbacks

Slack and Discord call 02 over HTTPS, so expose `127.0.0.1:8080` through a TLS tunnel or reverse proxy and set
02's request URLs to `https://<public-host>/slack/interactions` or `/discord/interactions`. n8n and 02 talk on the
compose network; 02's decision webhook goes to `http://n8n:5678/webhook/watchfloor-decision`.

Import and activate the playbooks once the secrets are in `.env` (details in
[`../automation/n8n`](../automation/n8n/README.md)):

```bash
docker compose exec n8n n8n import:workflow --separate --input=/workflows
docker compose exec n8n n8n update:workflow --all --active=true
docker compose restart n8n
```

## Hardening

Every service built from this repo runs as a non-root user with a read-only root filesystem, a private `/tmp`,
no Linux capabilities and `no-new-privileges`. Secrets only come from `.env`, which is git-ignored and checked by
CI. Images are not pushed anywhere.

## What was and was not verified

`docker compose config` validates this file with every profile enabled (CI runs it too). The build sandbox used to
write the portfolio has no Docker daemon, so the images were not built or started there; CI builds the project
images and the Watchfloor image (see `.github/workflows/ci.yml`). The Velociraptor image needs a pinned release URL
and checksum, so CI does not build it. The n8n image tag and the Velociraptor release are pinned through `.env`: check them
against the upstream release pages before the first build.
