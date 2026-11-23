# Investigating a Potentially Malicious File on Windows

A complete workflow: interview-ready answer first, then the detailed phase-by-phase guide.

---

## The interview answer (~90 seconds)

> "First I **preserve and identify** — hash the file immediately with `Get-FileHash` and record its metadata and provenance before touching it. On Windows the key provenance artifact is the Mark-of-the-Web: the `Zone.Identifier` alternate data stream tells me the download URL and referrer, and SmartScreen/browser logs add context. Absence of MOTW is a signal — it may have come from a zip, a network share, or been stripped.
>
> Then I do **static triage without executing it**: `Get-AuthenticodeSignature` and Sysinternals `sigcheck` for the signature and signer, then I examine the PE itself — headers, imports, sections, and entropy — with PEStudio or Detect It Easy. A high-entropy section or a tiny import table usually means it's packed. I pull strings with FLOSS to catch obfuscated config and C2. A valid signature doesn't mean benign — attackers abuse signed binaries and legitimate certs, so I verify the signer and check whether it proxies execution.
>
> If it's a script or document, I read it directly — Office macros with `olevba`, MSI with a table viewer, scripts in a text editor. Auto-running macros and obfuscated PowerShell are immediate red flags.
>
> For anything that warrants it, I move to **isolated dynamic analysis** in a FLARE-VM with no production network, running Process Monitor and Wireshark to capture process, file, registry, and network behavior.
>
> Finally I **correlate and scope** — EDR or Sysmon process lineage to find the parent, check persistence locations like Run keys, scheduled tasks, and services, then hunt the hash and behavior across the fleet. The approach is: identify and preserve, static triage, dynamic if needed, correlate, then scope."

Then stop and let the interviewer probe.

---

## Detailed guide

### Phase 0 — Preserve & identify (before analysis)

```powershell
# Hash immediately — forensic identity for the file
Get-FileHash -Algorithm SHA256 .\suspicious.exe
Get-FileHash -Algorithm MD5    .\suspicious.exe   # legacy intel lookups

# Record metadata without executing
Get-Item .\suspicious.exe | Format-List *           # size, times, attributes
Get-Item .\suspicious.exe -Stream *                  # list ADS (incl. Zone.Identifier)
```

**Provenance on Windows — the Mark-of-the-Web (MOTW):**

```powershell
# Read the Zone.Identifier ADS — download URL + referrer
Get-Content .\suspicious.exe -Stream Zone.Identifier
```

Output looks like:
```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://phishing.example/download
HostUrl=https://cdn.malicious.example/suspicious.exe
```

| MOTW field | Tells you |
|---|---|
| `ZoneId=3` | Came from the Internet zone |
| `ZoneId=2` | Trusted/intranet |
| `ReferrerUrl` / `HostUrl` | Download source + referring page |

**Interpretation cue:** a file **without** MOTW usually means it was extracted from an archive (some tools don't propagate it), copied from a network share, created by another process, or deliberately stripped with `Unblock-File`. Correlate with EDR process lineage and browser/email telemetry to find the true origin.

---

### Phase 1 — Static triage (never execute on the host)

#### Signature & reputation

```powershell
Get-AuthenticodeSignature .\suspicious.exe | Format-List *
sigcheck64.exe -accepteula -a -h -i .\suspicious.exe
```

- **Unsigned** claiming to be legit software → suspicious.
- **Validly signed** → verify the signer against the real vendor; attackers steal certs and abuse signed **LOLBins** to proxy execution. A signature proves *who signed*, not *good intent*.
- Check the timestamping counter-signature — a cert valid *after* signing may indicate a stolen/renewed cert.

#### PE header analysis

```powershell
# Quick entropy + structure with PEStudio (GUI) or CLI tools
# Detect It Easy: packer/protector identification
```

Examine with **PEStudio**, **Detect It Easy**, or `objdump`:

| Indicator | Why it's suspicious |
|---|---|
| High-entropy section (>7.0) | Packed/encrypted payload |
| Tiny import table | Packer stubs import almost nothing |
| Odd section names (`.aspack`, `.vmp`, `UPX`) | Known packer/protector |
| Imports: `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` | Process injection capability |
| Imports: `URLDownloadToFile`, `WinHttp*` / `WinINet*` | Downloader |
| Imports: `CryptEncrypt` + file APIs | Ransomware-like |
| No `Rich` header / bogus compile timestamp | Timestomp or custom build |

#### Strings & IOC extraction

```powershell
# FLOSS deobfuscates stack strings that plain 'strings' misses
floss.exe .\suspicious.exe
strings64.exe -a .\suspicious.exe | findstr /i "http https .onion cmd powershell"
```

Look for: URLs/IPs, mutex names, registry Run keys, command lines, and PDB paths.

#### By file type

| Type | Tool | What to check |
|---|---|---|
| **Office doc** | `olevba`, `oleid` (oletools) | AutoRun macros (`AutoOpen`, `Document_Open`), suspicious keywords |
| **MSI** | `lessmsi`, `msitools` | Custom actions, embedded scripts |
| **PowerShell** | read the file | `-enc`, `IEX`, `DownloadString`, `FromBase64String`, AMSI bypass |
| **LNK** | `LECmd` (Zimmerman) | Target path + args (LNK often launches `powershell`/`mshta`) |
| **ISO/IMG/VHD** | mount read-only | Nested payloads, LNK/ISO container abuse |
| **Archive** | extract read-only | Nested executables, password-protected payloads |
| **OneNote/HTML/HTA** | read | Embedded scripts, `mshta` launch |

```powershell
# Office macro triage
olevba.exe suspicious.docm

# LNK target
LECmd.exe -f suspicious.lnk
```

---

### Phase 2 — Dynamic analysis (isolated FLARE-VM only)

Run in a **snapshotted, network-isolated VM** (FLARE-VM) with a sinkhole (FakeNet-NG / INetSim), never production. Capture with:

| Tool | Captures |
|---|---|
| **Process Monitor (ProcMon)** | File, registry, process, network events — filter to the sample's PID |
| **Process Explorer** | Live process tree, signatures, handles, DLLs |
| **Wireshark** | Network traffic / C2 |
| **FakeNet-NG / INetSim** | Answers network requests so the malware reveals C2 behavior |
| **Regshot** | Before/after registry diff |

What to watch for:
- Child processes and injection (ProcMon / Process Explorer)
- Persistence: Run keys, scheduled tasks, services created
- File drops to `%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%`
- Outbound beacons (Wireshark / FakeNet)
- Defense evasion: `vssadmin delete shadows`, Defender exclusions, log clearing

```powershell
# Start ProcMon headless, run sample, then stop & save
procmon.exe /AcceptEula /BackingFile capture.pml /Quiet
# ... run sample ...
procmon.exe /Terminate
```

---

### Phase 3 — Persistence & scope

After confirming malicious, sweep every persistence surface:

```powershell
# Run keys (both hives, both bitness)
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' |
  ForEach-Object { Get-ItemProperty $_ -EA SilentlyContinue }

# Services in suspicious paths
Get-CimInstance Win32_Service |
  Where PathName -match 'temp|appdata|programdata|users\\public' |
  Select Name, PathName

# Scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where TaskPath -notlike '\Microsoft*' | Select TaskName, TaskPath

# Startup folders
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# WMI event subscriptions (fileless persistence)
Get-CimInstance -Namespace root\subscription -Class __EventFilter
Get-CimInstance -Namespace root\subscription -Class __EventConsumer
```

Then scope across the fleet: hunt the SHA-256, signer, parent process, C2 domain/IP, and persistence mechanism via EDR/Sysmon/SIEM.

---

## Red flags quick-list

| Signal | Why it matters |
|---|---|
| No MOTW on a "downloaded" file | Archive/share origin or stripped |
| Invalid/stolen signature, or signer ≠ claimed vendor | Cert abuse |
| High-entropy section / tiny import table | Packed payload |
| Office macro with `AutoOpen` + suspicious keywords | Macro malware |
| PowerShell `-enc`, `IEX`, `DownloadString` | Obfuscated downloader |
| LNK launching `powershell`/`mshta`/`rundll32` | LNK proxy execution |
| Imports for injection (`CreateRemoteThread`) | Process injection |
| Writes to Run keys / creates a service or task | Persistence |
| `vssadmin delete shadows` / Defender exclusion | Ransomware / defense evasion |
| File in `%TEMP%`, `%APPDATA%`, `C:\Users\Public\` | Staging location |

---

## Related references

- Companion guide: `GUIDE_Windows_DFIR.md` §10 (malware analysis)
- LOLBAS (signed-binary proxy execution) — https://lolbas-project.github.io/
- oletools — https://github.com/decalage2/oletools
- FLOSS — https://github.com/mandiant/flare-floss
- FLARE-VM — https://github.com/mandiant/flare-vm
- PEStudio — https://www.winitor.com/
- MITRE ATT&CK Windows — https://attack.mitre.org/matrices/enterprise/windows/
