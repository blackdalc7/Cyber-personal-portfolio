# Case study 01: macro document to mass file modification on a finance share

**Analyst:** Alvin Thomas
**Sensor:** [03 EDR canary and process tree](../../03-edr-canary-process-tree/)
**Disposition:** true positive, malicious. Execution chain confirmed with high confidence. "Ransomware" assessed with medium confidence.

## What is real and what is simulated

I want the reader to be able to tell these apart, so here they are:

| Part | Status |
|---|---|
| Event recording ([`maldoc_ransomware_chain.ndjson`](../../03-edr-canary-process-tree/tests/fixtures/maldoc_ransomware_chain.ndjson)) | **Simulated.** I wrote it to look like the kernel ETW events the sensor records. It was not captured from a real infection. The host, the user `dana`, the share and the file names are made up. |
| Encoded PowerShell payload | **Simulated and cut short.** It decodes to `IEX (New-Obj` and nothing more, so the second stage is not in the evidence. |
| Detection pipeline run | **Real.** I ran the alerts below through the project's own code with `Invoke-SafeSimulation.ps1` (replay mode, PowerShell 7.4). |
| Containment | **Mocked.** In replay mode the suspend call is a stub that records which PIDs it would have suspended. Replay also cannot show what suspending a process prevents, because the recorded events keep coming either way. |
| Live Windows lab capture | **Not done yet.** None of this has been run on a live endpoint with real ETW. |
| Fleet-wide scoping, network and identity logs | **Not available.** The sensor only sees one host's processes and files. Where I would have used other sources, I say so. |

## 1. Initial alert

The first alert arrived at `09:00:12.000Z`:

```json
{
  "@timestamp": "2026-10-26T09:00:12.000Z",
  "message": "[CRITICAL] Office application spawned a shell or script host: winword.exe spawned cmd.exe (PID 3150)",
  "event": { "severity": 99 },
  "rule": { "id": "EDR-PT-001" },
  "process": {
    "pid": 3150,
    "name": "cmd.exe",
    "command_line": "cmd.exe /c powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
    "parent": { "name": "winword.exe", "pid": 3100 }
  },
  "edr": {
    "markers": ["-enc", "-w hidden"],
    "depth": 1,
    "ancestry": "explorer.exe(1200) -> winword.exe(3100) -> cmd.exe(3150)"
  }
}
```

The rule's base severity is **high**. Two command-line markers raised it to **critical**: `-enc` and `-w hidden`. (The marker names above come from the sensor before the change in [case study 02](02-encoded-powershell-detection-improvement.md). After that change the same line reports `encodedcommand`, `-w hidden` and `decoded:iex `.)

## 2. First look: is this worth more than a minute?

On their own, Word spawning `cmd.exe` and PowerShell spawning from it are not proof. Some finance teams really do run macros that shell out. Four things made me treat it as hostile before I had looked at anything else:

1. **The document.** Word opened `C:\Users\dana\Downloads\invoice_8841.docm`. It is a macro-enabled format, it came from the Downloads folder, and it has an invoice-style name. Internal macro tooling usually sits on a share or in a template path, not in Downloads.
2. **The window was hidden** (`-w hidden`). That is how you run something the user is not supposed to see.
3. **The command was encoded.** I decoded the Base64 as UTF-16LE, which is what PowerShell expects:

   ```powershell
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA'))
   # IEX (New-Obj
   ```

   `IEX (New-Object ...` is the start of the usual download-and-execute pattern (`IEX (New-Object Net.WebClient).DownloadString(...)`). The payload stops there, so I **cannot** say what it downloaded or from where. I logged that as a gap and did not fill it with a guess.
4. **Word exited** one second after launching its children (`ProcessStop` at `09:00:14`). That fits a dropper that hands off and closes, though a user closing the document fits it too.

The encoding by itself would not have convinced me (see case study 02). What did was all four together, under an Office parent.

## 3. Raw evidence

These are the process events from the recording, cut down with `jq` (query Q1 below):

```text
time          pid   ppid  image           command line
09:00:01.000  1200  1100  explorer.exe    C:\Windows\Explorer.EXE
09:00:05.000  2200  1200  notepad.exe     notepad.exe notes.txt
09:00:06.000  2300  1200  powershell.exe  powershell.exe -NoProfile
09:00:10.000  3100  1200  WINWORD.EXE     "WINWORD.EXE" /n "C:\Users\dana\Downloads\invoice_8841.docm"
09:00:12.000  3150  3100  cmd.exe         cmd.exe /c powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA
09:00:12.500  3160  3150  powershell.exe  powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA
09:00:13.000  3170  3100  rundll32.exe    rundll32.exe C:\Users\Public\x.dll,Start
09:00:14.000  3100        (WINWORD.EXE stops)
09:00:20.000  4100  3160  svch0st.exe     svch0st.exe          (image path C:\Users\Public\svch0st.exe)
```

And the file activity of PID 4100 (queries Q2 and Q4):

```text
events: 32   first: 09:00:21.000   last: 09:00:26.000
FileWrite x30   report_00.xlsx ... report_29.xlsx in \Share\Finance, 65,536 bytes each, about 10 files a second
FileCreate x1   report_00.xlsx.lockbit                     09:00:25.000
DiskWrite  x1   0_passwords.docx (canary), 4,096 bytes     09:00:26.000
```

The recording also has two broken lines: an event of type `Bogus` and a line that is not valid JSON. The replay source skipped and counted both (`"malformed": 2`). I included them on purpose, to check that bad input does not crash the sensor.

## 4. Timeline

| Time (UTC) | +s | What happened | Alert |
|---|---|---|---|
| 09:00:10.0 | 0.0 | `dana` opens `invoice_8841.docm` in Word (user inferred from the path; see section 9) | |
| 09:00:12.0 | 2.0 | Word starts `cmd /c powershell -w hidden -enc ...` | EDR-PT-001 critical |
| 09:00:12.5 | 2.5 | PowerShell 3160 runs the encoded `IEX (New-Obj...` | EDR-PT-001 critical (depth 2 through cmd.exe) |
| 09:00:13.0 | 3.0 | Word starts `rundll32 C:\Users\Public\x.dll,Start` | EDR-PT-002 high |
| 09:00:14.0 | 4.0 | Word exits | |
| 09:00:20.0 | 10.0 | PowerShell 3160 starts `C:\Users\Public\svch0st.exe` | **none** |
| 09:00:21.0 | 11.0 | svch0st.exe starts rewriting `\Share\Finance\report_*.xlsx` | |
| 09:00:23.4 | 13.4 | 25th distinct file inside 10 s | EDR-RW-001 critical |
| 09:00:25.0 | 15.0 | `report_00.xlsx.lockbit` created | suppressed (PID already alerted) |
| 09:00:26.0 | 16.0 | Canary `0_passwords.docx` written | EDR-CN-001 critical |

The whole thing took 16 seconds. The first alert came **9 seconds before** the first file write.

## 5. Investigation queries

All of these run against the recording, so anyone can repeat them from the project folder. I strip the deliberately broken line before slurping (`grep -v '^{not'`).

**Q1. Process tree, with image names shortened**

```bash
jq -c 'select(.Type=="ProcessStart")
       | {t:.TimeStamp[11:23], pid:.ProcessId, ppid:.ParentProcessId,
          img:(.ImageName|split("\\")|last), cmd:.CommandLine}' \
   tests/fixtures/maldoc_ransomware_chain.ndjson
```

**Q2. Everything the writer process did to files**

```bash
grep -v '^{not' tests/fixtures/maldoc_ransomware_chain.ndjson | jq -s -c '
  map(select(.ProcessId==4100 and (.Type|test("^(File|Disk)"))))
  | {events:length, first:.[0].TimeStamp, last:.[-1].TimeStamp,
     types:(group_by(.Type)|map({(.[0].Type):length})|add),
     distinct:(map(.FilePath)|unique|length), sizes:(map(.Size)|unique)}'
```

Result: `{"events":32,"types":{"DiskWrite":1,"FileCreate":1,"FileWrite":30},"distinct":32,"sizes":[null,4096,65536]}`

**Q3. What did rundll32 do?**

```bash
grep -v '^{not' tests/fixtures/maldoc_ransomware_chain.ndjson | jq -c 'select(.ProcessId==3170 or .ParentProcessId==3170)'
```

Result: only its own start event. It had no children and no file events. Either `x.dll` did nothing the sensor can see (network, memory, registry), or it failed. I can't tell which from this data.

**Q4. Ransomware artefacts and canary contact**

```bash
grep -v '^{not' tests/fixtures/maldoc_ransomware_chain.ndjson \
  | jq -c 'select(.FilePath? and (.FilePath|test("lockbit|passwords|readme|decrypt";"i")))'
```

Result: one `.lockbit` file and the canary write. There is **no ransom note** in the recording.

**Queries I would run with a SIEM.** I did not run these, because the data is not in this project:

- Other hosts opening `invoice_8841.docm`, or Word spawning `cmd.exe` or `powershell.exe` in the same hour (email or proxy logs for the attachment's source).
- Outbound connections from PIDs 3160 and 3170 between 09:00:12 and 09:00:20, to find where the `IEX` stage came from.
- Authentication events for `dana` after 09:00:12 on other hosts, for signs of lateral movement.
- File-server audit logs for `\Share\Finance`, to see whether other clients were writing at the same time.

## 6. Alternative explanations I considered

| Explanation | Why I rejected it, or why I couldn't |
|---|---|
| A legitimate finance macro that calls PowerShell | Hidden window, encoded command, a macro document from Downloads, and a binary dropped in `C:\Users\Public`. One of these could be careless IT practice. All four together could not. |
| Backup, sync or AV software rewriting files | The writing process is `svch0st.exe`. Its name is one character off `svchost.exe`, it runs from `C:\Users\Public` instead of `System32`, and its parent is the PowerShell launched from Word, not `services.exe`. It also created a `.lockbit` file. |
| An administrator running a script | There is no management agent anywhere in the tree. The chain starts in the user's own Explorer session. |
| A sensor artefact (PID reuse building a false tree) | The process table rejects a "parent" that started after its child. Every parent here started first, and the times only go forward. |
| Mass writes without encryption (for example, a bulk export overwriting files) | **Not fully ruled out.** Each write is exactly 65,536 bytes, which fits in-place encryption in fixed blocks, but the sensor records no entropy or file contents. The `.lockbit` file and the canary write are what tip it. That is why my "ransomware" call is medium confidence, not high. |

## 7. Disposition

- **True positive, malicious.**
- **Initial access and execution (high confidence):** a user opened a macro document, the macro ran a hidden, encoded PowerShell loader (T1566.001, T1204.002, T1059.001, T1027), and the chain dropped a renamed binary (T1036.005).
- **Impact (medium confidence):** one process rewrote 30 finance files in about 3 seconds, created a `.lockbit` file and touched a canary (T1486). There is no ransom note, and there is no proof of content change.
- **Unknown:** what `x.dll` did, what the `IEX` stage downloaded, and whether data left the host. The sensor has no network telemetry.

## 8. Response and why

| Step | Rationale |
|---|---|
| **Suspend** PIDs 3150, 3160, 3170 and 4100, not kill them | Suspending stops encryption at once and keeps process memory, which may hold the downloaded stage and possibly a key. Killing them throws both away. With auto-containment on, the mocked replay suspended exactly these four, in that order, and left the canary alert alone because 4100 was already suspended. |
| **Network-isolate the host** | The sensor cannot do this. I would hand it to [02 HitL SOAR bot](../../02-hitl-soar-bot/), which only isolates after a signed analyst approval. With an unknown second stage and possible exfiltration, isolation is worth the disruption to one workstation. |
| **Collect** `invoice_8841.docm`, `C:\Users\Public\x.dll`, `C:\Users\Public\svch0st.exe` and the snapshot JSON | Hashes for fleet-wide scoping, and samples for analysis. The snapshots are metadata only, so the files themselves have to be collected separately. |
| **Restore** `\Share\Finance\report_00..29.xlsx` from snapshots | 30 files known to be affected, and the exact list comes from Q2. I would not restore until the writer is stopped and the share has been checked for other writers. |
| **Reset `dana`'s credentials** | Precautionary. An `IEX` stage running as the user can read anything the user can, including saved credentials. |
| **Scope other hosts** with the SIEM queries in section 5 | One phishing document rarely goes to only one person. |

**Why I keep auto-containment opt-in and gated at high severity.** The first alert came 9 seconds before encryption began. If I had trusted EDR-PT-001 and contained at 09:00:12.5, `svch0st.exe` would probably never have started. (This is an inference: replay cannot show it.) That is the argument for containing early. The argument against is that Word-to-PowerShell also fires on legitimate macros, and suspending a finance user's Excel automation in the middle of a quarter-end close is a self-inflicted incident. My compromise in the sensor: containment stays off by default, and when it is on, it only acts on high and critical alerts (`Containment.MinSeverity`, added in case study 02).

## 9. What the sensor got wrong or missed

These are the lessons I took back into detection engineering:

1. **`svch0st.exe` starting from `C:\Users\Public` raised nothing.** A misspelled system binary name, a user-writable path and a PowerShell parent each count against it on their own. Nothing caught it until it started writing files. This is my next rule: system binary names, or names one character away from them, running outside `System32`/`SysWOW64`.
2. **The `.lockbit` artefact was suppressed.** EDR-RW-002 alerts once per PID to avoid an alert storm, and RW-001 had already fired for 4100. That is the right call for noise, but it means the strongest single indicator only exists in the raw events. A later version should attach it to the existing alert instead of dropping it.
3. **The depth-2 alert message read backwards.** It said "winword.exe is a depth-2 descendant of powershell.exe". I fixed it to "powershell.exe (PID 3160) is a depth-2 descendant of winword.exe".
4. **The user is inferred, not recorded.** I got `dana` from the document path. The ETW events the sensor records carry no user SID, so on a shared or terminal-server host this inference would fail. Adding the token user to `ProcessStart` is on the list.
5. **The encoded-command check was a plain substring match.** It would have missed `-e` or `-ec`, and it fired on `-Encoding`. That became [case study 02](02-encoded-powershell-detection-improvement.md).

## 10. Reproduce it

From `03-edr-canary-process-tree/`, in any OS with PowerShell 7:

```powershell
./scripts/Invoke-SafeSimulation.ps1 -Keep                    # replays the recording, writes alerts.ndjson
Get-Content "$([IO.Path]::GetTempPath())edr-lab/out/alerts.ndjson" | ConvertFrom-Json |
    Select-Object '@timestamp', @{n='rule';e={$_.rule.id}}, @{n='sev';e={$_.event.severity}}, message
```

Expected summary:

```text
Rule       Name                                                    Count Severity
EDR-CN-001 Canary file tampered                                        1       99
EDR-PT-001 Office application spawned a shell or script host           2       99
EDR-PT-002 Office application spawned a living-off-the-land binary     1       73
EDR-RW-001 Mass file modification (possible encryption)                1       99
```

Two Pester tests in `tests/Pipeline.Tests.ps1` check the same result. `runs the full maldoc -> ransomware chain and raises every expected alert` covers the alerts, and `auto-contains the offending process exactly once` covers the four suspended PIDs.
