# Detection coverage: Q4 discovery and execution exercise

**Detection coverage: 50.0%**, telemetry coverage 87.5% across 8 exercised techniques.

| Tactic | Detected / exercised |
|---|---|
| discovery | 1 / 5 |
| execution | 3 / 3 |

| | Technique | Outcome | Rule(s) that fired | Hosts |
|---|---|---|---|---|
| ✅ | T1033 System Owner/User Discovery | DETECTED | Linux Current User Discovery; Local User Discovery via Whoami | srv01, ws01 |
| ✅ | T1059.001 Command and Scripting Interpreter: PowerShell | DETECTED | PowerShell Run Non-Interactively With an Inline Command | ws01 |
| ✅ | T1059.003 Command and Scripting Interpreter: Windows Command Shell | DETECTED | Cmd.exe Executing an Inline Command | ws01 |
| ✅ | T1059.004 Command and Scripting Interpreter: Unix Shell | DETECTED | Linux Shell Executing an Inline Command | srv01 |
| 🟧 | T1016 System Network Configuration Discovery | DETECTION_GAP | Network Configuration Discovery via Ipconfig, Route or Arp | srv01, ws01 |
| 🟧 | T1083 File and Directory Discovery | DETECTION_GAP | Linux Listing of Sensitive Directories | srv01, ws01 |
| ⬜ | T1057 Process Discovery | NO_CONTENT | - | ws01 |
| 🟥 | T1082 System Information Discovery | TELEMETRY_GAP | Linux System Information Discovery; System Information Discovery via Systeminfo or Hostname | srv01, ws01, ws02 |

## Hosts with no process telemetry

Nothing from these hosts reached the log export during their exercise steps:

- **ws02** (windows)

## Gaps and who fixes them

### 🟥 T1082 System Information Discovery: TELEMETRY_GAP

Logging/platform: enable process-creation logging (Sysmon EID 1 or 4688 with command line; auditd execve on Linux) and confirm the host forwards to the SIEM.
- ✅ ws01 (windows) `systeminfo`: DETECTED, 1 event(s) in window
- ✅ srv01 (linux) `uname -a`: DETECTED, 1 event(s) in window
- 🟥 ws02 (windows) `systeminfo`: TELEMETRY_GAP, 0 event(s) in window

### ⬜ T1057 Process Discovery: NO_CONTENT

Detection engineering: no Sigma rule is mapped to this technique for this platform yet.
- ⬜ ws01 (windows) `tasklist /v`: NO_CONTENT, 1 event(s) in window
    - `2026-10-26T09:06:02+00:00 ws01 C:\Windows\System32\tasklist.exe | tasklist /v`

### 🟧 T1016 System Network Configuration Discovery: DETECTION_GAP

Detection engineering: the events are there. Extend or add a Sigma rule using the evidence lines.
- ✅ ws01 (windows) `ipconfig /all`: DETECTED, 1 event(s) in window
- 🟧 srv01 (linux) `ss -tunap`: DETECTION_GAP, 1 event(s) in window
    - `2026-10-26T09:13:02+00:00 srv01 /usr/bin/ss | ss -tunap`

### 🟧 T1083 File and Directory Discovery: DETECTION_GAP

Detection engineering: the events are there. Extend or add a Sigma rule using the evidence lines.
- 🟧 ws01 (windows) `cmd.exe /c dir C:\Users`: DETECTION_GAP, 1 event(s) in window
    - `2026-10-26T09:05:04+00:00 ws01 C:\Windows\System32\cmd.exe | cmd.exe /c dir C:\Users`
- ✅ srv01 (linux) `ls -la /etc`: DETECTED, 1 event(s) in window

