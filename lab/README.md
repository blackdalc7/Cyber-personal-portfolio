# Detection lab (Vagrant + Ansible)

> Part of the [Threat Response Engineering portfolio](../README.md). The machines [07-attack-emulator](../07-attack-emulator/README.md) attacks and [Watchfloor](../watchfloor/README.md) watches.

Two disposable VMs on a host-only network, provisioned so that every technique 07 runs produces telemetry in the Watchfloor lake:

| VM | Address | What runs on it | Telemetry path |
|---|---|---|---|
| `lab-k8s` (Ubuntu 24.04) | 192.168.56.10 | microK8s, **Tetragon** (eBPF), Fluent Bit DaemonSet, the Atomic runner pod | Tetragon JSON export → Fluent Bit → `POST /api/ingest/tetragon` |
| `lab-win01` (Windows 11) | 192.168.56.20 | **Sysmon**, the [03 EDR canary](../03-edr-canary-process-tree/README.md), Fluent Bit, Invoke-AtomicRedTeam, Velociraptor client | Sysmon / Security logs → Fluent Bit → `/api/ingest/winlog`; canary NDJSON → `/api/ingest/edr` |

The hub runs on your workstation and is reached from the VMs at `192.168.56.1:8000`.

```
             workstation (192.168.56.1)
   ┌───────────────────────────────────────────────┐
   │ deploy/ docker compose: hub, redis, lake,      │
   │ 08 rules, 02 SOAR, n8n, Velociraptor server    │
   │ 07 attack-emulator ──kubectl──┐   ──WinRM──┐   │
   └───────────────▲───────────────┼────────────┼───┘
       ingest      │               ▼            ▼
   ┌───────────────┴──────┐   ┌──────────────────────┐
   │ lab-k8s .10          │   │ lab-win01 .20        │
   │ Tetragon ► FluentBit │   │ Sysmon ► FluentBit   │
   │ atomic-runner pod    │   │ EDR canary, Velo     │
   └──────────────────────┘   └──────────────────────┘
```

## What you need

- VirtualBox 7 or Hyper-V, Vagrant 2.4, and Ansible (`pip install ansible-core ansible pywinrm`) on the host. On Windows hosts run Ansible from WSL.
- About 16 GB of RAM for the two VMs, plus what the Watchfloor stack uses.
- The stack running with the hub bound to the host-only interface. In `deploy/.env` set `HUB_BIND=192.168.56.1` and a `WF_INGEST_TOKEN` of at least 16 characters.

## Bring it up

```bash
cd deploy && docker compose --profile detect up -d && cd ..     # hub, lake, 08's rules

cd lab
export WF_INGEST_TOKEN=...            # the same value as deploy/.env
vagrant up                            # both VMs, then Ansible provisions both
```

Re-run provisioning with `vagrant provision lab-win01` (the provisioner is attached to the last VM so Ansible sees the whole inventory), or directly:

```bash
cd lab/ansible
ansible-playbook site.yml -e wf_ingest_token=$WF_INGEST_TOKEN
ansible-playbook site.yml --syntax-check
```

## What the playbook does

`site.yml` starts with two guard rails: it refuses any host whose address is outside `lab_net_prefix` (192.168.56.x), and it refuses to run without the ingest token.

| Role | Host | Does |
|---|---|---|
| `common` | k8s | packages, UTC, rsyslog forwarding to 01's syslog listener, ufw |
| `microk8s` | k8s | snap install at a pinned channel, dns/helm3/hostpath add-ons, `kubectl`/`helm` shims, a kubeconfig whose server is the host-only address |
| `tetragon` | k8s | Helm chart at a pinned version with JSON export to `/var/run/cilium/tetragon/tetragon.log`, plus three TracingPolicies |
| `fluent_bit_k8s` | k8s | the ingest token as a Kubernetes Secret, Fluent Bit tailing the Tetragon export to the hub |
| `atomic_runner` | k8s | namespace `atomic`, a long-lived PowerShell pod with the atomics installed, a NetworkPolicy |
| `windows_sysmon` | win01 | Sysmon and its config, both pinned by SHA-256 |
| `windows_edr_canary` | win01 | 03's canary as a scheduled task writing NDJSON |
| `windows_fluent_bit` | win01 | Fluent Bit (pinned by SHA-256) shipping Sysmon, Security and canary logs; the token file is ACL'd to SYSTEM |
| `windows_atomic` | win01 | Invoke-AtomicRedTeam at a pinned version and the atomics. Defender stays on, so a blocked test is scored "prevented" |
| `velociraptor_client` | win01 | the client MSI and the server's client config; skipped until you set the MSI URL and checksum |

### Tetragon policies

| Policy | Hook | Why |
|---|---|---|
| `file-credential-access` | `security_file_permission` reads (mask 4) of `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/root/.ssh` | credential access (08's shadow-read rule) |
| `privilege-escalation` | `__sys_setuid` | setuid to root from a non-root process |
| `network-connect` | `tcp_connect` | outbound connections from pods (port scans, C2) |

Process exec and exit events come from Tetragon without a policy.

### The Atomic runner pod

07's `kubectl` executor runs `kubectl exec deploy/atomic-runner -- pwsh -EncodedCommand ...` in namespace `atomic`. The pod runs as root (several Linux atomics need it) but drops every capability except a short list, mounts no service-account token, and its NetworkPolicy allows no inbound traffic and outbound only DNS plus the internet for the bootstrap download: the lab subnet, the host and cluster-internal ranges are excluded. Because the pod shares the node's kernel, Tetragon sees everything it does and reports it under the node name `lab-k8s`.

## Pins you must fill in

`ansible/group_vars/all.yml` holds every version and checksum. The plays **refuse to continue** while a checksum is empty, so nothing is downloaded unverified:

- `sysmon_zip_sha256`, `sysmon_config_sha256`
- `fluent_bit_windows_sha256` for the pinned `fluent_bit_windows_version`
- `velociraptor_client_msi_url` and `velociraptor_client_msi_sha256` (optional: the role skips itself without them)

`atomic_red_team_ref` is `master` by default. Pin it to a commit for repeatable runs; 07's campaigns pick tests by name, which survives most upstream changes.

## Using the lab from 07

```bash
vagrant ssh lab-k8s -c "cat ~/.kube/config" > ~/.kube/lab-k8s.config
export KUBECONFIG=~/.kube/lab-k8s.config            # context "microk8s", server https://192.168.56.10:16443

cd ../07-attack-emulator
cat >> .env <<'EOF'
LAB_ALLOWED_CIDRS=192.168.56.0/24
LAB_KUBE_CONTEXTS=microk8s
EMU_WINRM_USER=vagrant
EMU_WINRM_PASSWORD=vagrant
EOF
python -m attack_emulator run campaigns/lab-linux.yml --confirm-lab
python -m attack_emulator run campaigns/lab-windows.yml --confirm-lab
```

07 checks the kube context's API server address against `LAB_ALLOWED_CIDRS` before it sends anything. If `kubectl` complains that the certificate is not valid for 192.168.56.10, run `vagrant ssh lab-k8s -c "sudo microk8s refresh-certs --cert server.crt"`.

## Velociraptor

The `dfir` profile in `deploy/` runs the Velociraptor server. Its first start writes `client.config.yaml`; copy it out before provisioning the client:

```bash
cd deploy
docker compose --profile dfir cp velociraptor:/velo/client.config.yaml velociraptor/client.config.yaml
```

09-evidence-timeline then collects from `lab-win01` through the server's API after a human approves containment in 02.

## Safety

- The VMs are targets. Keep them on the host-only network; never bridge them to a real LAN.
- `vagrant`/`vagrant` is Vagrant's well-known default for throwaway boxes. Do not reuse it, and do not expose WinRM (5985) beyond the host-only network.
- `vagrant destroy -f` is the reset button. Rebuild rather than clean up after a campaign that went sideways.

## Status

Every file here passes `ansible-playbook --syntax-check`, `yamllint` and a template render. The environment this was written in has no hypervisor, so the VMs themselves have not been booted there; the first `vagrant up` on a real workstation is the integration test.
