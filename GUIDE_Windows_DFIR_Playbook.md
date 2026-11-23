# Windows DFIR — Hands-On Playbook & Cheat Sheet

A practical, command-first companion to `GUIDE_Windows_DFIR.md`. This document is built for the keyboard: what to run, where to look, what it proves, and what it does **not** prove.

> **Scope:** Windows 10/11 and Windows Server. Validate artifact paths against the exact build (`winver`, `systeminfo`) before drawing conclusions.

---

## 1. First 15 minutes — triage decision tree

```
Alert received
  │
  ├─ Is there active harm? (ransomware encrypting, active exfil, hands-on-keyboard)
  │     YES → Contain FIRST (EDR network-contain, not shutdown). Then collect.
  │     NO  → Collect volatile evidence FIRST, then decide containment.
  │
  ├─ Do we have EDR telemetry on this host?
  │     YES → Pull process tree + network events before touching the host.
  │     NO  → Go straight to live response (§3) and triage collection (§4).
  │
  └─ Is the host a DC / server / crown-jewel?
        YES → Escalate, involve identity team, expect broader blast radius.
        NO  → Standard endpoint workflow.
```

**Never shut down** a suspected-compromised host as a first move: you lose memory and may re-lock BitLocker. Use EDR network containment instead.

---

## 2. Evidence priority order (order of volatility)

| Priority | Evidence | Lost if... |
|---:|---|---|
| 1 | RAM, process state, sockets, sessions | Reboot / shutdown |
| 2 | DNS cache, ARP, netstat, handles | Reboot, minutes-to-hours |
| 3 | Event logs, registry, NTFS metadata | Log rollover, attacker clearing |
| 4 | Disk image | Reimaging, disk wipe |
| 5 | VSS, backups, centralized/cloud logs | Retention expiry |

---

## 3. Live response — copy/paste collection block

Run from an elevated, trusted shell. Write output to **external** evidence storage (`E:\Evidence\`), never the local disk under investigation.

```powershell
$Eviden = "E:\Evidence\$env:COMPUTERNAME"
New-Item -ItemType Directory -Force -Path $Eviden | Out-Null
Set-Location $Eviden

# --- Context & time (ALWAYS FIRST) ---
Get-Date -Format o                              | Tee-Object collection_start_utc.txt
Get-TimeZone                                    | Out-File timezone.txt
systeminfo                                      | Out-File systeminfo.txt
Get-ComputerInfo | Select WindowsProductName, OsBuildNumber, CsDomain,
    CsName, OsLastBootUpTime | Out-File computerinfo.txt

# --- Identity & sessions ---
whoami /all                                     | Out-File whoami.txt
quser                                           | Out-File sessions.txt 2>$null
Get-LocalUser                                   | Out-File local_users.txt
Get-LocalGroupMember Administrators              | Out-File local_admins.txt

# --- Processes (the single most valuable live artifact) ---
Get-CimInstance Win32_Process |
  Select ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
  Export-Csv processes.csv -NoTypeInformation

# --- Network ---
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
  Export-Csv tcp.csv -NoTypeInformation
netstat -ano        | Out-File netstat.txt
ipconfig /displaydns| Out-File dnscache.txt
arp -a              | Out-File arp.txt

# --- Persistence surfaces ---
Get-CimInstance Win32_Service | Select Name,State,StartMode,StartName,PathName |
  Export-Csv services.csv -NoTypeInformation
Get-ScheduledTask   | Export-Clixml scheduled_tasks.xml
Get-CimInstance Win32_StartupCommand | Export-Csv startup.csv -NoTypeInformation

# --- Security posture ---
manage-bde -status  | Out-File bitlocker.txt
Get-MpComputerStatus| Out-File defender_status.txt
Get-MpThreatDetection | Out-File defender_detections.txt

Get-Date -Format o  | Out-File collection_end_utc.txt
Get-ChildItem -Recurse | Get-FileHash -Algorithm SHA256 | Export-Csv _hashes.csv -NoTypeInformation
```

**Autoruns one-liner** (broadest persistence sweep available):
```cmd
autorunsc64.exe -accepteula -a * -c -h -s -m > autoruns.csv
```

---

## 4. Triage collection — pick one and go

| Tool | Command | When |
|---|---|---|
| **KAPE** | `kape.exe --tsource C: --tdest E:\out --target !SANS_Triage --vhdx host` | Fastest standard triage |
| **Velociraptor** | `Windows.KapeFiles.Targets` artifact | Fleet-wide / remote |
| **CyLR** | `CyLR.exe -od E:\out` | Minimal footprint, no install |

`!SANS_Triage` grabs EVTX, registry hives, `$MFT`, `$UsnJrnl`, Prefetch, Amcache, LNK, Jump Lists, SRUM, and browser data in one pass — this is the default answer for "what do I collect?"

---

## 5. Artifact quick-reference — path → what it proves

| Artifact | Path | Proves | Does **NOT** prove |
|---|---|---|---|
| Security log | `C:\Windows\System32\winevt\Logs\Security.evtx` | Logons, priv use, account changes | Anything not audited |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Execution + run count + last-run times | Absence ≠ no execution (may be off on servers) |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | File **presence** + metadata + SHA1 | Not reliable execution proof |
| Shimcache | `SYSTEM` hive, AppCompatCache | Path existed / was enumerated | **NOT execution** on modern Windows |
| BAM/DAM | `SYSTEM` hive | SID ↔ exe path + last-run time | Coverage varies by build |
| UserAssist | `NTUSER.DAT` (ROT13) | GUI-launched apps + run count | Misses CLI/script execution |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | App **bytes sent/received** per user | Exact destinations |
| `$MFT` | Volume root | File names, MACB times, resident data | Timestomping possible |
| `$UsnJrnl:$J` | Volume root | Create/rename/delete change reasons | User intent, file content |
| LNK / Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\` | File & volume access, incl. removable/network | Shortcut times ≠ access times |
| Shellbags | `UsrClass.dat` | Folder browsing, incl. deleted paths | Whether files were opened |
| PSReadLine | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Typed PowerShell commands | Scripted/encoded execution |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\` | Original path + deletion time | Permanent deletes |
| MOTW | `file.exe:Zone.Identifier` ADS | Internet origin + referrer URL | Absence ≠ locally created |

### The execution-evidence hierarchy (memorize this)
```
STRONG   → EDR process event, Security 4688, Sysmon 1, Prefetch
MODERATE → BAM/DAM, UserAssist, SRUM, PSReadLine
WEAK     → Amcache (presence), Shimcache (path seen), file on disk
```
Never assert "the attacker ran X" from the WEAK tier alone.

---

## 6. Event log cheat sheet

```powershell
# Export without altering the source
wevtutil epl Security E:\Evidence\Security.evtx
wevtutil epl System   E:\Evidence\System.evtx
wevtutil epl Microsoft-Windows-PowerShell/Operational E:\Evidence\PS-Op.evtx
wevtutil epl Microsoft-Windows-TaskScheduler/Operational E:\Evidence\Tasks.evtx
wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" E:\Evidence\RDP-LSM.evtx

# Fast triage queries
Get-WinEvent -FilterHashtable @{LogName='System';   Id=7045}              # service installed
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}              # LOG CLEARED
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720}              # user created
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -in 3,10 }                        # network + RDP logons
```

### Event IDs that matter most

| ID | Log | Meaning | Red flag when... |
|---:|---|---|---|
| 1102 | Security | **Audit log cleared** | Almost always malicious |
| 4624 | Security | Successful logon | Type 3 (network) / 10 (RDP) from odd source |
| 4625 | Security | Failed logon | Spray/brute pattern; check substatus |
| 4648 | Security | Explicit credentials used | Lateral movement / runas |
| 4672 | Security | Special privileges assigned | Unexpected admin logon |
| 4688 | Security | Process created | Requires audit policy + CLI logging |
| 4697 / 7045 | Security / System | Service installed | Random name, `%TEMP%` path, unsigned |
| 4698 / 4702 | Security | Scheduled task created/updated | Persistence |
| 4719 | Security | Audit policy changed | Defense evasion |
| 4720 / 4728 / 4732 | Security | Account created / added to group | Privilege escalation |
| 4768 / 4769 / 4771 | Security (DC) | Kerberos TGT / service ticket / preauth fail | Kerberoasting, AS-REP roasting |
| 4104 | PowerShell Op | Script block logged | Obfuscation, `FromBase64String`, download cradles |

### Logon types (Type field in 4624)
`2` interactive · `3` network (SMB/share) · `4` batch · `5` service · `7` unlock · `8` network cleartext · `9` new credentials (runas /netonly) · **`10` RemoteInteractive (RDP)** · `11` cached

---

## 7. Persistence hunt checklist

```powershell
# Run keys (both hives, both bitness)
$paths = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$paths | ForEach-Object { Get-ItemProperty $_ -EA SilentlyContinue }

# Services with suspicious paths
Get-CimInstance Win32_Service |
  Where PathName -match 'temp|appdata|programdata|users\\public' |
  Select Name, PathName, StartName

# Scheduled tasks not from Microsoft
Get-ScheduledTask | Where TaskPath -notlike '\Microsoft*' |
  Select TaskName, TaskPath, @{n='Action';e={$_.Actions.Execute}}

# WMI event subscriptions (fileless persistence)
Get-CimInstance -Namespace root\subscription -Class __EventFilter
Get-CimInstance -Namespace root\subscription -Class __EventConsumer
Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding

# Startup folders
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# Winlogon hijack
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' |
  Select Shell, Userinit

# IFEO debuggers (incl. accessibility/sticky-keys backdoor)
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  ForEach-Object { Get-ItemProperty $_.PSPath -EA SilentlyContinue } |
  Where Debugger
```

For every hit record: **path, args, signer, SHA-256, ACLs, creation time, fleet prevalence.** Preserve before you delete.

---

## 8. Triage heuristics — what "suspicious" actually looks like

**Process anomalies**
- `svchost.exe` **without** `-k` argument, or parented by anything other than `services.exe`
- `lsass.exe`, `csrss.exe`, `winlogon.exe` with a parent other than expected, or running from a non-`System32` path
- Office app (`WINWORD.EXE`, `EXCEL.EXE`) spawning `cmd`, `powershell`, `wscript`, `mshta`, `rundll32`
- Browser spawning a shell
- Any process running from `%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%`, `C:\Users\Public\`, or a recycle-bin path

**Command-line red flags**
```
-enc / -EncodedCommand      -w hidden / -WindowStyle Hidden
-nop / -NoProfile           -ExecutionPolicy Bypass
IEX / Invoke-Expression     DownloadString / DownloadFile
FromBase64String            certutil -urlcache / -decode
bitsadmin /transfer         mshta http
rundll32 javascript:        regsvr32 /s /u /i: scrobj.dll
wmic process call create    vssadmin delete shadows
```

**LOLBins to scrutinize** (never malicious by name — judge by parent/args/target):
`certutil`, `bitsadmin`, `mshta`, `rundll32`, `regsvr32`, `msbuild`, `installutil`, `wmic`, `cscript`, `curl.exe`, `forfiles`, `odbcconf`. Reference: https://lolbas-project.github.io/

**Ransomware precursors** — `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`, mass `$UsnJrnl` deletes, Defender exclusions added.

---

## 9. Parsing collected artifacts (Eric Zimmerman toolset)

```powershell
MFTECmd.exe            -f "E:\out\C\$MFT"           --csv E:\parsed
MFTECmd.exe            -f "E:\out\C\$J"             --csv E:\parsed
PECmd.exe              -d "E:\out\C\Windows\Prefetch" --csv E:\parsed
AmcacheParser.exe      -f "E:\out\...\Amcache.hve"  --csv E:\parsed
AppCompatCacheParser.exe -f "E:\out\...\SYSTEM"     --csv E:\parsed
LECmd.exe              -d "E:\out\...\Recent"       --csv E:\parsed
JLECmd.exe             -d "E:\out\...\AutomaticDestinations" --csv E:\parsed
SBECmd.exe             -d "E:\out\...\"             --csv E:\parsed
SrumECmd.exe           -f "E:\out\...\SRUDB.dat" -r "E:\out\...\SOFTWARE" --csv E:\parsed
EvtxECmd.exe           -d "E:\out\...\winevt\Logs"  --csv E:\parsed
RECmd.exe              -d "E:\out\...\config" --bn BatchExamples\Kroll_Batch.reb --csv E:\parsed
```

Then review everything in **Timeline Explorer** (sortable, filterable grid built for these CSVs).

**Automated detection over EVTX:**
```bash
hayabusa.exe csv-timeline -d E:\out\...\winevt\Logs -o timeline.csv
chainsaw hunt E:\out\ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

---

## 10. Memory analysis quick path

```bash
vol.py -f mem.raw windows.info
vol.py -f mem.raw windows.pstree          # anomalous parentage
vol.py -f mem.raw windows.psscan          # hidden/unlinked procs (diff vs pslist)
vol.py -f mem.raw windows.cmdline         # full command lines
vol.py -f mem.raw windows.netscan         # sockets ↔ PIDs
vol.py -f mem.raw windows.malfind         # injected RWX regions
vol.py -f mem.raw windows.svcscan
vol.py -f mem.raw windows.dlllist --pid <PID>
```

Key comparison: **`pslist` vs `psscan`** — anything in `psscan` but not `pslist` may be unlinked/hidden or terminated. `malfind` is heuristic; confirm before calling it injection.

---

## 11. Scoping & lateral movement pivots

Once you have one compromised host, pivot on:

1. **Identity** — every 4624/4648 for that account, everywhere. Which hosts did it touch?
2. **Hashes** — SHA-256 across the fleet (EDR / Velociraptor hunt).
3. **Infrastructure** — C2 domain/IP in DNS, proxy, firewall logs.
4. **Behavior** — same service name, task name, file path, mutex, or command pattern.
5. **Time window** — what else happened on other hosts in that window?

**Lateral movement evidence map**

| Method | Source host | Destination host |
|---|---|---|
| RDP | 4648, RDP Client Op logs, Shellbags | 4624 type 10, TS-LocalSessionManager, profile creation |
| PsExec / SMB | 4648, prefetch of `psexec.exe` | 4624 type 3, 7045 (`PSEXESVC`), admin share access |
| WMI | Process lineage, `wmic` cmdline | `WmiPrvSE.exe` parent, WMI-Activity log |
| WinRM / PS Remoting | 4648, PSReadLine | 4624 type 3, `wsmprovhost.exe`, PS Op logs |
| Scheduled task | `schtasks /s` cmdline | 4698, Task Scheduler Op log |
| Pass-the-Hash | LSASS access, EDR | 4624 type 3 + NTLM, 4776 |

---

## 12. Containment & eradication order

1. **Preserve** — memory + triage before any change (unless active harm).
2. **Contain** — EDR network isolation; block C2 at egress; disable compromised accounts.
3. **Scope** — complete §11 pivots *before* eradicating; premature cleanup tips off the attacker.
4. **Eradicate** — remove persistence, kill payloads, close the initial-access vector.
5. **Rotate credentials** — every account/token/key exposed on the host; **`krbtgt` twice** if DC compromise is suspected.
6. **Recover** — reimage if trust cannot be established. Restoring a backdoored host is not recovery.
7. **Monitor** — targeted detections for the observed TTPs; watch for re-entry.

---

## 13. Reporting template

```markdown
## Executive Summary
What happened, business impact, current status, confidence level.

## Timeline (UTC)
| Time (UTC) | Host | Event | Evidence source | Confidence |

## Initial Access
Vector, entry point, first malicious artifact + hash.

## Actions on Objective
Execution, persistence, priv-esc, lateral movement, collection, exfil — each ATT&CK-mapped.

## Scope
Hosts, accounts, and data confirmed / suspected / ruled out.

## IOCs
Hashes, domains, IPs, filenames, service/task names, mutexes.

## Detection & Response Gaps
What we missed and why (logging, coverage, tuning).

## Remediation & Recommendations
Immediate, short-term, strategic — with owners.

## Appendix
Commands run, tool versions, evidence hashes, chain of custody.
```

State **facts vs. interpretation vs. assumption** separately, and give an explicit confidence level (high/medium/low) for each conclusion.

---

## 14. Anti-forensics to watch for

| Technique | Detection |
|---|---|
| Log clearing | Security 1102, System 104, unexplained log gaps |
| Timestomping | `$MFT` `$SI` vs `$FN` mismatch, sub-second precision zeroed |
| USN journal deletion | `fsutil usn deletejournal`, journal starting mid-timeline |
| Prefetch disabled | `EnablePrefetcher` = 0 in registry |
| Secure delete / wiping | Tool artifacts, `$MFT` gaps, missing `$UsnJrnl` entries |
| Defender tampering | Exclusions added, real-time protection off, Defender Op events |
| EDR unhooking / BYOVD | Vulnerable driver loaded, sensor gap, Code Integrity events |
| Alternate Data Streams | `Get-Item -Stream *`, `dir /r` |

An evidence **gap is itself evidence** — document it.

---

## 15. Quick links

- Eric Zimmerman tools — https://ericzimmerman.github.io/#!index.md
- KAPE — https://www.kroll.com/kape
- Velociraptor — https://docs.velociraptor.app/
- Volatility 3 — https://volatility3.readthedocs.io/
- Hayabusa — https://github.com/Yamato-Security/hayabusa
- Chainsaw — https://github.com/WithSecureLabs/chainsaw
- Sigma — https://sigmahq.io/
- LOLBAS — https://lolbas-project.github.io/
- Sysinternals — https://learn.microsoft.com/sysinternals/
- Sysmon config (Olaf Hartong) — https://github.com/olafhartong/sysmon-modular
- MITRE ATT&CK Windows — https://attack.mitre.org/matrices/enterprise/windows/
- SANS FOR500 — https://www.sans.org/cyber-security-courses/windows-forensic-analysis/
- 13Cubed — https://www.13cubed.com/

> **Deeper reference:** see `GUIDE_Windows_DFIR.md` in this workspace for full explanations, acquisition theory, AD/identity DFIR, and evidence-handling procedure.
