# 03 · Advanced EDR Canary and Process Tree

> Part of the [Threat Response Engineering portfolio](../README.md). This folder is self-contained and can also be published as its own repository.

A PowerShell EDR sensor that consumes **kernel ETW** (process, file I/O and disk I/O), maintains a live **parent-child process tree**, and raises ECS alerts when:

- an Office application spawns a shell or script host, such as `winword.exe → powershell.exe`, directly or through an intermediate process (EDR-PT-001 to 004);
- PowerShell runs an encoded command (`-e`, `-ec`, `-enc`, `-EncodedCommand` and the other accepted abbreviations), with the payload decoded into the alert and severity set by the parent: low under a management agent, raised under WMI, WinRM or a service (EDR-PT-005);
- any process writes, renames or deletes a **canary decoy file** (EDR-CN-001);
- one process modifies 25 or more distinct files within 10 seconds, or drops a ransomware extension or ransom note (EDR-RW-001/002).

It can **suspend** the offending process after taking a metadata-only forensic snapshot. It only does so for high and critical alerts (`Containment.MinSeverity`), and it refuses to touch protected system processes or itself. Every exported and private function is covered by Pester tests.

The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start (Windows, elevated PowerShell 5.1 or 7)

```powershell
cd projects\03-edr-canary-process-tree
Copy-Item .env.example .env            # set EDR_WATCH_PATHS, optionally EDR_SIEM_HOST
.\scripts\Install-TraceEvent.ps1       # pinned TraceEvent 3.2.8, SHA-256 verified
.\scripts\Start-EdrCanary.ps1          # kernel ETW; falls back to WMI + FileSystemWatcher if ETW is unavailable
```

Optional: register the Event Log source once so alerts also land in the Application log (IDs 9001 canary, 9002 ransomware, 9003 process tree):

```powershell
New-EventLog -LogName Application -Source EdrCanary
```

## Safe simulation

```powershell
# Any OS: replay the simulated maldoc → ransomware chain through the full pipeline
.\scripts\Invoke-SafeSimulation.ps1
```

```
Rule       Name                                                    Count Severity
EDR-CN-001 Canary file tampered                                        1       99
EDR-PT-001 Office application spawned a shell or script host           2       99
EDR-PT-002 Office application spawned a living-off-the-land binary     1       73
EDR-RW-001 Mass file modification (possible encryption)                1       99
```

```powershell
# Windows, with the monitor watching C:\EdrLab in another window
.\scripts\Invoke-SafeSimulation.ps1 -Mode Live -LabPath C:\EdrLab
```

Live mode writes plain text files and appends one line to the canary. It encrypts nothing, deletes nothing outside its own `sim_*.txt` files, and makes no network calls.

## Rule regression

```powershell
# Any OS: replay labelled malicious and benign cases and print the verdict for each
.\scripts\Invoke-RuleRegression.ps1 | Format-Table -AutoSize
```

Run it before and after a change to `config/rules.psd1` to see exactly which cases changed. The worked example, with before-and-after output, is [case study 02](../docs/case-studies/02-encoded-powershell-detection-improvement.md). The investigation of the maldoc replay is [case study 01](../docs/case-studies/01-maldoc-to-ransomware-investigation.md).

## Event sources

| Source | Needs | What it sees |
|---|---|---|
| `Etw` (default) | Windows, administrator, TraceEvent | Kernel Process, FileIO and DiskIO events, through the NT Kernel Logger session, with back-pressure and a drop counter |
| `Fallback` | Windows | `Win32_ProcessStartTrace` (WMI) plus a `FileSystemWatcher` on each canary |
| `Replay` | Any OS | NDJSON event recordings, used by tests, the simulation and detection engineering |

## Outputs

- `alerts.ndjson`: ECS 8.11 alert documents (the same schema Project 01 emits), rotated at `EDR_ALERT_MAX_BYTES`.
- RFC 5424 syslog to `EDR_SIEM_HOST:EDR_SIEM_PORT`, which Project 01 ingests and correlates directly.
- The Windows Application event log, when the source is registered.
- Forensic snapshots (`snapshot_<pid>_<ts>.json`) for every contained process.

## Tests

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Force -SkipPublisherCheck
Invoke-Pester ./tests -Output Detailed
```

There are 102 tests. On Linux, 2 Windows-only tests are skipped. The suite covers:

- Process-tree mapping, including PID reuse, cycles, pruning and depth-limited ancestry.
- Every parent-child rule and the severity escalation for command-line markers.
- Encoded PowerShell: every accepted flag abbreviation, near misses such as `-Encoding`, payload decoding, parent-based severity and the containment floor.
- Canary matching for DOS paths and `\Device\HarddiskVolumeN` kernel paths.
- The ransomware sliding window, including no alert storms for repeated writes to one file.
- The containment guards (protected names and PIDs, self-protection), plus `-WhatIf` and mocked kernel32 calls.
- Alert rotation, the syslog framing and real UDP delivery.
- `.env` parsing.
- The pinned-hash installer, including the rejection path.
- The scripts.
- A real compile of the C# kernel consumer against TraceEvent, when `lib/traceevent` is present.

`PSScriptAnalyzer` runs in CI with [PSScriptAnalyzerSettings.psd1](PSScriptAnalyzerSettings.psd1).

## Project layout

```text
03-edr-canary-process-tree/
├── src/EdrCanary/
│   ├── EdrCanary.psd1 / .psm1   module manifest and loader
│   ├── Public/                  exported commands (Start-EdrMonitor, Suspend-EdrProcess, ...)
│   ├── Private/                 process table, rules, event sources, alerting, config
│   └── Native/EtwKernelConsumer.cs   kernel ETW reader compiled at runtime
├── scripts/                     launcher, TraceEvent installer, safe simulation, rule regression
├── config/rules.psd1            detection rules (parent/child pairs, thresholds)
├── tests/                       Pester 5 suite and simulated attack fixtures
├── docs/ARCHITECTURE.md
├── PSScriptAnalyzerSettings.psd1
└── .env.example
```

## Development

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
Invoke-Pester ./tests
```

Every exported command has comment-based help (`Get-Help Start-EdrMonitor -Full`),
and internal helpers carry a one-line description. The C# ETW consumer uses XML doc comments.

CI (`.github/workflows/ci.yml`) runs PSScriptAnalyzer and Pester on Windows and Ubuntu.

## Licence

MIT. See [LICENSE](LICENSE).
