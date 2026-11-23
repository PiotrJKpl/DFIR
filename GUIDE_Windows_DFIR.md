# Windows DFIR - Detailed Field Guide

A practical, resource-linked guide to Digital Forensics and Incident Response on Windows workstations, servers, and Active Directory environments. It is organized by workflow: preparation, acquisition, volatile collection, artifacts, memory, malware, attacker TTPs, tooling, and repeatable response.

> **Golden rules:** obtain authorization, preserve before analyzing, follow the order of volatility, record every action and timestamp, hash collected evidence, and analyze verified copies. A live response changes the system; document that footprint and collect only what the incident requires.

---

## 0. Authoritative starting points

| Resource | Why it matters | Link |
|---|---|---|
| NIST SP 800-86 | Integrating forensic techniques into incident response | https://csrc.nist.gov/pubs/sp/800/86/final |
| NIST SP 800-61 Rev. 3 | Current incident-response recommendations aligned with CSF 2.0 | https://csrc.nist.gov/pubs/sp/800/61/r3/final |
| Microsoft audit policy recommendations | Current baseline/advanced audit guidance for workstations and servers | https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations |
| Windows Event Log reference | Official Security log event IDs and field definitions | https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624 |
| Microsoft Sysinternals | Trusted Windows inspection and response utilities | https://learn.microsoft.com/sysinternals/ |
| Sysmon documentation | Process, network, file, registry, pipe, WMI, and tampering telemetry | https://learn.microsoft.com/sysinternals/downloads/sysmon |
| MITRE ATT&CK Windows matrix | Map evidence and detections to adversary techniques | https://attack.mitre.org/matrices/enterprise/windows/ |
| SANS Windows Forensics poster | Compact artifact and event-reference poster | https://www.sans.org/posters/windows-forensic-analysis/ |
| Velociraptor documentation | Endpoint collection, hunting, artifact parsing, and timelines at scale | https://docs.velociraptor.app/ |

> Version caveat: artifact locations and behavior differ across Windows 10, Windows 11, Windows Server releases, feature updates, and policy configurations. Record the exact build with `winver`, `systeminfo`, or the registry before interpreting artifacts.

---

## 1. Windows concepts a responder must understand

These concepts determine what evidence exists, how to acquire it, and what an artifact can prove.

- **NTFS** records filesystem metadata in structures such as `$MFT`, `$UsnJrnl`, `$LogFile`, directory indexes (`$I30`), and security descriptors (`$Secure`). These sources can reveal create, rename, delete, and path history even when content is gone.
- **Registry** hives store system configuration, users, services, persistence, program execution traces, network history, and account metadata. Important hives include `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, and `UsrClass.dat`.
- **Windows Event Log** stores `.evtx` channels under `C:\Windows\System32\winevt\Logs\`. Evidence depends on audit policy, channel enablement, retention, collection, and attacker clearing.
- **Volume Shadow Copy Service (VSS)** may preserve older copies of files, registry hives, and logs. It is useful for before/after comparison but is not guaranteed to exist or be complete.
- **BitLocker** protects data at rest. A powered-off acquisition may be encrypted; a live, unlocked system can permit logical collection and may expose recovery context. Coordinate with legal and system owners before collecting keys.
- **Prefetch, Amcache, Shimcache, BAM/DAM, UserAssist, LNK files, and Jump Lists** are complementary execution or user-activity artifacts. None should be treated as a complete process ledger.
- **DPAPI** protects user and system secrets using credentials and machine context. Credential and browser evidence may require the relevant profile, keys, and lawful access.
- **Virtualization-Based Security (VBS), Credential Guard, HVCI, and Protected Process Light (PPL)** affect credential theft, memory access, and acquisition tools.
- **EDR telemetry** often provides process lineage and remote scoping faster than disk artifacts, but retention, sensor health, exclusions, and data normalization must be verified.
- **Active Directory** distributes identity evidence across endpoints, domain controllers, identity providers, DNS, VPN, and cloud control planes. A local host rarely contains the complete authentication story.

---

## 2. Preparation and evidence handling

### 2.1 Before an incident

A Windows DFIR program is much stronger when evidence collection is designed in advance:

1. Centralize Security, PowerShell, Defender, Sysmon, RDP, Task Scheduler, and relevant application logs.
2. Define Advanced Audit Policy through Group Policy and validate that required event fields are present.
3. Increase log sizes and retention based on event volume; default sizes are often insufficient.
4. Deploy and test an approved EDR and triage collector.
5. Maintain clean response media and record hashes of trusted tools.
6. Document BitLocker recovery-key ownership and lawful responder access.
7. Pre-authorize isolation, memory acquisition, disk imaging, account disablement, and evidence transfer.
8. Test collection under VBS, Credential Guard, antivirus, EDR, and server workloads.
9. Synchronize time and retain the source timezone and UTC offset.
10. Run tabletop and technical exercises using representative endpoints and domain controllers.

Useful hardening and logging resources:

- Microsoft security baselines: https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- Microsoft Advanced Audit Policy: https://learn.microsoft.com/windows/security/operating-system-security/auditing/advanced-security-audit-policy-settings
- SwiftOnSecurity Sysmon configuration: https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong's modular Sysmon configuration: https://github.com/olafhartong/sysmon-modular

### 2.2 Case log and chain of custody

Record at minimum:

- Case/incident identifier and authorization.
- Collector, date, UTC time, local timezone, host, user, and physical location.
- Exact commands/tools, versions, parameters, and tool hashes.
- Source device identifiers, serial numbers, partitions, and encryption state.
- Output filenames, sizes, SHA-256 hashes, storage destination, and transfer history.
- Every evidence handoff, access, copy, mount, conversion, and analysis action.
- Known collection errors and changes made to the source.

Hash example:

```powershell
Get-FileHash -Algorithm SHA256 .\memory.raw
Get-FileHash -Algorithm SHA256 .\disk.E01
```

For courtroom or regulatory matters, follow organizational legal guidance and validated forensic procedures rather than relying on this field guide alone.

---

## 3. Evidence acquisition

### 3.1 Order of volatility

Collect the most transient evidence first when it is safe and proportionate:

1. CPU/process state, memory, logged-on sessions, network connections, handles, and encryption state.
2. Live response data: services, scheduled tasks, autoruns, DNS cache, ARP cache, firewall state, EDR context.
3. Targeted triage artifacts: event logs, registry hives, NTFS metadata, execution artifacts, browser and application evidence.
4. Full disk or volume image.
5. VSS snapshots, backups, centralized logs, cloud telemetry, and adjacent systems.

> Isolation changes network evidence; shutdown destroys memory and may lock BitLocker volumes. Decide deliberately. During active ransomware or exfiltration, risk reduction may take priority over perfect evidence preservation.

### 3.2 Memory acquisition

Memory can expose processes, injected code, sockets, command history, credentials or keys, decrypted content, and malware that never touched disk.

Common tools:

| Tool | Notes | Link |
|---|---|---|
| WinPmem | Open-source Windows physical memory acquisition | https://github.com/Velocidex/WinPmem |
| Magnet RAM Capture | Free Windows memory acquisition utility | https://www.magnetforensics.com/resources/magnet-ram-capture/ |
| Belkasoft RAM Capturer | Free acquisition option; validate in your environment | https://belkasoft.com/ram-capturer |
| DumpIt | Commercial/free variants depending on use; confirm licensing | https://www.magnetforensics.com/resources/dumpit/ |

Operational cautions:

- Memory acquisition loads a driver and changes RAM; record tool/version/hash and start/end times.
- Security controls may block the driver or produce alerts. Do not disable EDR casually to force acquisition.
- Dumps can contain passwords, tokens, personal data, encryption keys, and confidential documents. Encrypt and restrict evidence storage.
- Validate output size and hash immediately. Retain acquisition logs.
- Hibernation (`hiberfil.sys`), crash dumps (`MEMORY.DMP`), and page files may supplement but do not replace a live memory image.

### 3.3 Disk and volume imaging

Use a hardware write blocker for offline media when practical. Acquire the correct source: physical disk, logical volume, virtual disk, cloud snapshot, or targeted files.

Common tools:

- FTK Imager: https://www.exterro.com/digital-forensics-software/ftk-imager
- Arsenal Image Mounter: https://arsenalrecon.com/products/arsenal-image-mounter
- Guymager (Linux acquisition workstation): https://guymager.sourceforge.io/
- `ewfacquire`/libewf for E01 workflows: https://github.com/libyal/libewf
- NIST CFTT disk-imaging test program: https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/disk-imaging

Capture and verify:

- Device make/model/serial, sector size, partition table, and capacity.
- Image type (`raw/dd`, `E01`, `VHD/VHDX`) and compression settings.
- Acquisition and verification hashes.
- Read errors, bad sectors, and tool logs.
- BitLocker status and whether data was collected encrypted or unlocked.

Do not mount the original evidence read-write. Mount verified copies read-only or use a forensic image mounter.

### 3.4 Fast triage collection

Full imaging is not always the fastest or most proportionate response. Triage collectors preserve high-value artifacts in minutes:

| Tool | Best use | Link |
|---|---|---|
| KAPE | High-speed targeted collection and processing | https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape |
| KapeFiles | Community KAPE targets/modules | https://github.com/EricZimmerman/KapeFiles |
| Velociraptor | Remote collection, hunts, VQL parsing, and fleet response | https://docs.velociraptor.app/ |
| CyLR | Lightweight triage collection from live systems | https://github.com/orlikoski/CyLR |
| UAC | Cross-platform artifact collection | https://github.com/tclahr/uac |

Prefer a tested collection profile tied to the incident hypothesis. Collecting everything can waste time, overload endpoints, and increase privacy exposure.

### 3.5 Virtual machines and cloud hosts

- Coordinate hypervisor/cloud snapshots to preserve disk consistency and record snapshot time.
- A disk snapshot does not capture RAM unless the platform explicitly supports memory state.
- Export cloud control-plane, serial console, identity, network flow, and EDR logs separately.
- Preserve the original virtual disk format when possible and hash exports.
- Record auto-scaling, ephemeral disks, temporary disks, and instance replacement behavior.

---

## 4. Live response and volatile state

Run commands from a trusted administrative shell where authorized. Redirect output to protected evidence storage and record command start/end times.

```powershell
# Host, OS, time, and boot context
Get-Date -Format o
Get-TimeZone
hostname
systeminfo
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber,
  CsDomain, CsName, OsLastBootUpTime

# Users, sessions, and local groups
whoami /all
quser
qwinsta
Get-LocalUser
Get-LocalGroupMember -Group Administrators

# Processes and command lines
Get-CimInstance Win32_Process |
  Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine,
    CreationDate | Export-Csv .\processes.csv -NoTypeInformation
tasklist /v

# Services and drivers
Get-CimInstance Win32_Service |
  Select-Object Name, State, StartMode, StartName, PathName |
  Export-Csv .\services.csv -NoTypeInformation
driverquery /v /fo csv > drivers.csv

# Network and DNS state
Get-NetTCPConnection | Export-Csv .\tcp_connections.csv -NoTypeInformation
Get-NetUDPEndpoint | Export-Csv .\udp_endpoints.csv -NoTypeInformation
netstat -ano > netstat.txt
ipconfig /all > ipconfig.txt
ipconfig /displaydns > dns_cache.txt
arp -a > arp_cache.txt
route print > routes.txt
Get-NetFirewallProfile
Get-NetFirewallRule | Where-Object Enabled -eq True |
  Export-Csv .\enabled_firewall_rules.csv -NoTypeInformation

# Scheduled tasks, startup commands, and shares
Get-ScheduledTask | Export-Clixml .\scheduled_tasks.xml
Get-CimInstance Win32_StartupCommand | Export-Csv .\startup_commands.csv -NoTypeInformation
Get-SmbShare | Export-Csv .\shares.csv -NoTypeInformation

# BitLocker and Defender state
manage-bde -status > bitlocker_status.txt
Get-MpComputerStatus | Format-List * > defender_status.txt
Get-MpThreatDetection | Format-List * > defender_detections.txt
```

Useful Sysinternals tools:

- Process Explorer: process tree, signatures, handles, DLLs
- Autoruns/Autorunsc: broad persistence enumeration
- TCPView: live network ownership
- Handle: open files and objects
- Sigcheck: signatures, hashes, version information
- ListDLLs: loaded modules

Download and documentation: https://learn.microsoft.com/sysinternals/downloads/

> Do not terminate a suspicious process merely because it looks malicious. Capture process lineage, command line, executable, hashes, network state, handles, and memory first when operational risk permits.

---

## 5. Core forensic artifacts

### 5.1 Windows Event Logs

Default location:

```text
C:\Windows\System32\winevt\Logs\
```

High-value channels include:

- `Security.evtx`: logons, account/group changes, process creation when enabled, audit-policy changes, and log clearing.
- `System.evtx`: service installation/state, drivers, shutdown/startup, and system failures.
- `Microsoft-Windows-PowerShell%4Operational.evtx`: script blocks and PowerShell activity when logging is configured.
- `Windows PowerShell.evtx`: legacy engine events.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`: task registration and execution when enabled.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx`: WMI provider and consumer activity.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`: RDP sessions.
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`: RDP authentication/connection activity.
- `Microsoft-Windows-Windows Defender%4Operational.evtx`: Defender detections and configuration events.
- `Microsoft-Windows-Sysmon%4Operational.evtx`: Sysmon telemetry if deployed.
- `Microsoft-Windows-Bits-Client%4Operational.evtx`: BITS jobs and transfers.
- `Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx`: firewall events when configured.

Collection examples:

```powershell
# Export a complete channel without changing the source log
wevtutil epl Security C:\Evidence\Security.evtx
wevtutil epl System C:\Evidence\System.evtx
wevtutil epl Microsoft-Windows-PowerShell/Operational C:\Evidence\PowerShell-Operational.evtx

# Record channel configuration and retention settings
wevtutil gl Security > C:\Evidence\Security-channel-config.txt

# Query recent service installation events
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-7)}
```

Important caveats:

- An absent event may mean disabled auditing, overwritten logs, collection gaps, or attacker clearing; it does not prove the activity did not happen.
- Event IDs are channel/provider-specific. Interpret provider, version, fields, logon type, status codes, and surrounding events.
- Security 4688 command-line content requires the relevant process-creation auditing policy.
- Correlate `Logon ID`, account SID, source address, workstation, process ID, and time rather than relying only on username.
- Event timestamps are stored consistently, but viewers may display local time. Normalize to UTC and retain the source timezone.

Tools:

- Event Viewer and `Get-WinEvent` (built in)
- Eric Zimmerman's EvtxECmd: https://ericzimmerman.github.io/#!index.md
- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Chainsaw: https://github.com/WithSecureLabs/chainsaw
- Sigma rules: https://sigmahq.io/ and https://github.com/SigmaHQ/sigma

### Selected event IDs

| Event | Provider/log | Investigative value |
|---:|---|---|
| 1102 | Security | Audit log cleared |
| 4624 | Security | Successful logon; inspect logon type and source fields |
| 4625 | Security | Failed logon; inspect status/substatus and pattern |
| 4648 | Security | Logon using explicit credentials |
| 4672 | Security | Special privileges assigned to a new logon |
| 4688 | Security | New process, if process-creation auditing is enabled |
| 4697 | Security | Service installed, if relevant auditing is enabled |
| 4698/4702 | Security | Scheduled task created/updated |
| 4719 | Security | System audit policy changed |
| 4720 | Security | User account created |
| 4728/4732/4756 | Security | Member added to privileged or security-enabled group types |
| 4768/4769 | Security on DC | Kerberos TGT/service-ticket activity |
| 4771/4776 | Security on DC | Kerberos pre-authentication/NTLM credential validation |
| 7045 | System | Service installed |
| 4104 | PowerShell Operational | Script block logging, when enabled |

Microsoft event reference landing point: https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-policy-recommendations

### 5.2 Registry hives

### System hives

```text
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SECURITY
C:\Windows\System32\config\DEFAULT
```

### User hives

```text
C:\Users\<user>\NTUSER.DAT
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

High-value evidence:

- Hostname, timezone, network interfaces, USB history, services, and control sets in `SYSTEM`.
- Installed software, Windows version, persistence, and policy in `SOFTWARE`.
- Local users and groups in `SAM`; secrets and cached security data require careful lawful handling.
- Run keys, UserAssist, typed paths/URLs, RecentDocs, mapped drives, and per-user settings in `NTUSER.DAT`.
- Shellbags and shell-class data in `UsrClass.dat`.

Live export examples:

```cmd
reg save HKLM\SYSTEM C:\Evidence\SYSTEM.hiv /y
reg save HKLM\SOFTWARE C:\Evidence\SOFTWARE.hiv /y
reg save HKLM\SAM C:\Evidence\SAM.hiv /y
reg save HKLM\SECURITY C:\Evidence\SECURITY.hiv /y
```

Also collect transaction logs (`.LOG1`, `.LOG2`) and related files; they may contain recent changes not fully committed to the primary hive.

Parsers:

- Registry Explorer and RECmd: https://ericzimmerman.github.io/#!index.md
- RegRipper: https://github.com/keydet89/RegRipper3.0
- regipy: https://github.com/mkorman90/regipy

### 5.3 NTFS metadata

| Artifact | Purpose |
|---|---|
| `$MFT` | Master record for files/directories, names, attributes, timestamps, and data runs |
| `$UsnJrnl:$J` | Change journal: create, rename, overwrite, delete, and other reasons |
| `$LogFile` | NTFS transaction log; useful for recent filesystem operations |
| `$I30` | Directory index entries; may retain references to deleted/renamed children |
| `$Secure:$SDS` | Security descriptor data |
| Alternate Data Streams | Hidden or auxiliary content attached to NTFS files |

Key cautions:

- Standard Information and File Name timestamps can differ; understand which timestamp set the parser reports.
- Copy, move, extraction, restore, and application behavior affect timestamps differently.
- Timestomping can alter some fields; correlate with USN, event logs, Prefetch, LNK, and EDR.
- `$UsnJrnl` records change reasons, not user intent or necessarily file content.
- A filename in metadata does not prove execution.

Tools:

- MFTECmd/MFTExplorer: https://ericzimmerman.github.io/#!index.md
- The Sleuth Kit/Autopsy: https://www.sleuthkit.org/ and https://www.autopsy.com/
- Plaso/log2timeline: https://plaso.readthedocs.io/

### 5.4 Program execution artifacts

### Prefetch

Location:

```text
C:\Windows\Prefetch\*.pf
```

Prefetch can show executable name, path-related resources, run count, and recent execution timestamps. It is primarily a performance artifact and may be disabled or absent, especially depending on system role and configuration.

Parser: PECmd - https://ericzimmerman.github.io/#!index.md

Do not conclude that every referenced DLL/file was maliciously accessed. Prefetch records resources involved in application startup behavior and should be correlated.

### Amcache

Common location:

```text
C:\Windows\AppCompat\Programs\Amcache.hve
```

Amcache records file/application inventory and metadata useful for identifying binaries that existed or were observed. Schema changes across Windows versions. Treat it as evidence of presence/inventory and correlate before asserting execution.

Parser: AmcacheParser - https://ericzimmerman.github.io/#!index.md

### Application Compatibility Cache (Shimcache)

Stored in the `SYSTEM` hive under AppCompatCache-related keys. Shimcache can show paths and metadata associated with application compatibility processing. On modern Windows it is **not, by itself, proof of execution**.

Parsers: AppCompatCacheParser and Registry Explorer - https://ericzimmerman.github.io/#!index.md

### BAM/DAM

Background Activity Moderator/Desktop Activity Moderator entries in the `SYSTEM` hive can associate user SIDs with executable paths and timestamps. Coverage and semantics vary by Windows version; correlate with process and user artifacts.

### UserAssist

Stored per user under `NTUSER.DAT` and ROT13-encoded. It records GUI-launched application interactions and counters. It does not cover all execution methods.

### PCA and other modern artifacts

Program Compatibility Assistant artifacts can provide additional execution/application evidence on modern Windows releases. Validate parser support and schema against the target build.

### 5.5 User activity and file-access artifacts

| Artifact | Typical location | What it can show |
|---|---|---|
| LNK shortcuts | `%APPDATA%\Microsoft\Windows\Recent\` and elsewhere | Target path, volume, timestamps, network/removable-media context |
| Automatic Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Files accessed through an application |
| Custom Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\` | Application-specific recent targets |
| Shellbags | `NTUSER.DAT`/`UsrClass.dat` | Folder navigation, including removable or deleted paths |
| RecentDocs | `NTUSER.DAT` | Recently accessed document names by extension |
| Open/Save MRUs | `NTUSER.DAT` | Paths selected in common file dialogs |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\` | Original path, deletion time, and retained content |
| ActivitiesCache | User Connected Devices Platform database | Timeline/activity data when enabled |

Parsers:

- LECmd and JumpList Explorer/JLECmd: https://ericzimmerman.github.io/#!index.md
- ShellBags Explorer/SBECmd: https://ericzimmerman.github.io/#!index.md
- RBCmd for Recycle Bin: https://ericzimmerman.github.io/#!index.md

LNK and Jump List timestamps may describe the target volume/file rather than shortcut creation. Parse each field semantically.

### 5.6 SRUM

Location:

```text
C:\Windows\System32\sru\SRUDB.dat
```

The System Resource Usage Monitor database can associate applications and users with network and resource usage over time. It is valuable for identifying network-active executables and usage patterns, but retention and update cadence vary.

Parser: SrumECmd - https://ericzimmerman.github.io/#!index.md

Collect the `SOFTWARE` hive with SRUM because application identifiers may require registry mapping.

### 5.7 Browser, download, email, and collaboration artifacts

Common browser paths:

```text
# Chrome
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\<profile>\History

# Microsoft Edge
C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\<profile>\History

# Firefox
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite
```

Collect relevant SQLite databases with `-wal` and `-shm` sidecar files. They may contain recent uncheckpointed records.

Correlate:

- Browser history, downloads, cookies, extensions, and cache.
- Mark-of-the-Web in the `Zone.Identifier` alternate data stream.
- Email headers, attachment metadata, mailbox audit logs, and message trace.
- Teams/Slack/other collaboration logs where authorized.
- Proxy, DNS, EDR, and identity-provider telemetry.

Example Mark-of-the-Web check:

```powershell
Get-Item -Path .\suspicious.exe -Stream *
Get-Content -Path .\suspicious.exe -Stream Zone.Identifier
```

Absence of `Zone.Identifier` does not prove a file was local or benign; archives, filesystems, tools, and attacker actions can remove or fail to propagate it.

### 5.8 PowerShell, WMI, and command execution

PowerShell evidence may include:

- Event 4104 script blocks when Script Block Logging is enabled.
- Events 4103/module logging when configured.
- PowerShell engine/provider events.
- Console history under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\`.
- Process creation, EDR, AMSI, Defender, and Sysmon telemetry.
- Transcription files if policy enabled them.

Microsoft PowerShell logging guidance: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows

WMI evidence may include:

- `Microsoft-Windows-WMI-Activity/Operational` logs.
- Sysmon WMI events 19-21 when configured.
- Persistent event filters, consumers, and bindings in the WMI repository.
- Process lineage involving `WmiPrvSE.exe`.

Do not treat `powershell.exe`, `wscript.exe`, `rundll32.exe`, `regsvr32.exe`, or `wmic.exe` as malicious by name alone. Analyze parent, command line, signer, target, user, network, and prevalence.

### 5.9 Network and remote-access evidence

Sources include:

- Live connections: `Get-NetTCPConnection`, `netstat -ano`, EDR socket telemetry.
- DNS cache and DNS Client operational logs if enabled.
- Windows Defender Firewall logs, commonly `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log` when configured.
- SRUM network usage.
- Browser/proxy/VPN logs and centralized DNS.
- RDP operational channels, Security logons, Terminal Services logs, and related registry/cache artifacts.
- SMB client/server logs and Security share-access auditing when enabled.
- BITS operational logs and job database context.

RDP investigation should correlate at least:

- Security 4624/4625 with logon type and source.
- TerminalServices RemoteConnectionManager and LocalSessionManager events.
- Network/VPN/NAT evidence.
- User profile artifacts and process execution after session creation.
- Domain controller Kerberos/NTLM events where applicable.

### 5.10 Defender and antivirus evidence

Useful sources:

- `Microsoft-Windows-Windows Defender/Operational` event channel.
- `Get-MpThreatDetection` and `Get-MpComputerStatus` on a live host.
- Defender support logs and quarantine metadata, subject to access controls.
- Microsoft Defender for Endpoint Advanced Hunting and device timeline if licensed.

Microsoft Defender Antivirus event reference: https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus

An antivirus quarantine or detection name is a lead, not a complete malware verdict. Preserve the original alert fields, engine/version, detection time, action, path, hash, and associated process tree.

---

## 6. Persistence locations

Check persistence based on the intrusion hypothesis rather than assuming one mechanism.

| Mechanism | Evidence/location |
|---|---|
| Services | `HKLM\SYSTEM\CurrentControlSet\Services`, System 7045, Security 4697 |
| Scheduled Tasks | `C:\Windows\System32\Tasks\`, TaskCache registry keys, task logs |
| Run/RunOnce keys | HKLM/HKCU `Software\Microsoft\Windows\CurrentVersion\Run*` |
| Startup folders | Per-user and all-users Start Menu `Programs\Startup` |
| Winlogon | `Winlogon\Shell`, `Userinit`, notification-related values |
| WMI subscriptions | Event filters, consumers, and filter-to-consumer bindings |
| Drivers | Services registry, driver files, Code Integrity/System logs |
| PowerShell profiles | User/system PowerShell profile paths |
| Office add-ins/templates | Office registry keys, startup folders, templates |
| Browser extensions | Browser profile extension directories and policy keys |
| COM hijacking | CLSID/InprocServer32 and related per-user overrides |
| AppInit/AppCert DLLs | Session Manager and Windows registry locations |
| IFEO/SilentProcessExit | Image File Execution Options and monitor/debugger values |
| DLL search-order hijacking | Application directories, PATH, manifests, loaded modules |
| Accessibility features abuse | Logon-screen helper binary registry/file replacement |
| BITS jobs | BITS operational logs and job state |
| Logon scripts/GPO | AD Group Policy, SYSVOL, user attributes, local policy |

Broad live enumeration:

```cmd
autorunsc64.exe -accepteula -a * -c -h -s -m > autoruns.csv
```

Autoruns documentation: https://learn.microsoft.com/sysinternals/downloads/autoruns

For each entry, record path, arguments, owner, ACLs, signer, hash, creation/modification context, referenced parent mechanism, and fleet prevalence. Do not delete persistence before preserving it and understanding its role.

---

## 7. Active Directory and identity-focused DFIR

For domain incidents, collect evidence from endpoints, domain controllers, identity providers, VPN, EDR, and cloud services.

### High-value DC evidence

- Security logs: Kerberos, NTLM, account changes, group membership, directory access, and policy changes.
- Directory Service and DNS Server logs where enabled.
- SYSVOL and Group Policy changes.
- AD replication metadata and object attributes.
- Defender for Identity or equivalent identity-sensor telemetry.
- DC memory only when necessary and explicitly authorized; it is extremely sensitive.

### Questions to answer

1. Which identity authenticated, from where, using which protocol and logon type?
2. Was the account expected on that host and at that time?
3. Were privileged groups, delegation, SPNs, keys, certificates, or federation settings changed?
4. Was lateral movement interactive, service-based, scheduled, WMI, SMB, WinRM, or remote management?
5. Were domain replication rights or directory databases targeted?
6. Which credentials, sessions, tokens, and systems must be reset or rebuilt?

Useful Microsoft references:

- Audit account logon events: https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-account-logon
- Audit directory service access: https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-directory-service-access
- Securing privileged access: https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model
- Microsoft Defender for Identity: https://learn.microsoft.com/defender-for-identity/

> Do not export `NTDS.dit`, LSASS memory, DPAPI material, or credential databases as routine triage. Collect highly sensitive credential evidence only when necessary, authorized, encrypted, and access-controlled.

---

## 8. Memory forensics

Volatility 3 is the standard open-source framework: https://github.com/volatilityfoundation/volatility3 and https://volatility3.readthedocs.io/

Basic workflow:

```bash
# Identify kernel/OS information
python3 vol.py -f memory.raw windows.info

# Compare process views and inspect trees
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw windows.psscan
python3 vol.py -f memory.raw windows.pstree

# Command lines, DLLs, handles, and sockets
python3 vol.py -f memory.raw windows.cmdline
python3 vol.py -f memory.raw windows.dlllist --pid <PID>
python3 vol.py -f memory.raw windows.handles --pid <PID>
python3 vol.py -f memory.raw windows.netscan

# Look for suspicious executable memory regions
python3 vol.py -f memory.raw windows.malfind

# Inspect services, drivers, and registry context
python3 vol.py -f memory.raw windows.svcscan
python3 vol.py -f memory.raw windows.driverscan
python3 vol.py -f memory.raw windows.registry.hivelist
```

Analysis method:

1. Verify image hash and acquisition metadata.
2. Establish OS/build and symbol resolution.
3. Compare active and scanned process lists; inspect parent/child relationships and start times.
4. Correlate sockets with process identity and endpoint telemetry.
5. Inspect anomalous memory permissions, injected regions, unbacked code, and suspicious modules.
6. Review handles, tokens, services, drivers, consoles, and registry context as required.
7. Extract suspicious objects to a controlled analysis environment and hash them.
8. Correlate memory findings with disk, logs, and EDR.

Cautions:

- `malfind` output is heuristic; executable private memory is not automatically malicious.
- Process-name or parent anomalies are leads, not verdicts.
- Windows symbols and plugin support can vary by build.
- Memory may contain privileged secrets and unrelated personal data.
- Rootkits and acquisition failures can distort views; compare independent evidence sources.

Additional tools:

- MemProcFS: https://github.com/ufrisk/MemProcFS
- YARA: https://virustotal.github.io/yara/
- capa for capability analysis of extracted binaries: https://github.com/mandiant/capa

---

## 9. Timeline building

A defensible timeline correlates independent artifacts and keeps source semantics.

Potential sources:

- Event logs and EDR events.
- `$MFT`, `$UsnJrnl`, `$LogFile`, and VSS.
- Registry key last-write times and transaction logs.
- Prefetch, Amcache, Shimcache, BAM/DAM, and UserAssist.
- LNK, Jump Lists, Shellbags, RecentDocs, and Recycle Bin.
- Browser, email, collaboration, download, and Mark-of-the-Web evidence.
- SRUM, firewall, DNS, proxy, VPN, and cloud logs.
- Memory process/socket timestamps.

Tools:

- Plaso/log2timeline: https://plaso.readthedocs.io/
- Timesketch: https://timesketch.org/
- Timeline Explorer: https://ericzimmerman.github.io/#!index.md
- Hayabusa CSV timelines: https://github.com/Yamato-Security/hayabusa

Timeline rules:

1. Normalize to UTC but retain original timezone and timestamp source.
2. Label what each timestamp means: creation, modification, event generation, collection, ingestion, or parser-derived.
3. Account for clock drift, delayed forwarding, daylight saving, and source rollover.
4. Avoid inferring causation from close timestamps alone.
5. Mark confidence and alternative explanations.
6. Preserve links to source record IDs, file offsets, hashes, or query identifiers.

---

## 10. Windows malware analysis

### 10.1 Static triage

```powershell
# Hash and signature
Get-FileHash -Algorithm SHA256 .\suspicious.exe
Get-AuthenticodeSignature .\suspicious.exe | Format-List *

# Sysinternals signature/hash inspection
sigcheck64.exe -accepteula -a -h -i .\suspicious.exe

# Alternate data streams / Mark-of-the-Web
Get-Item .\suspicious.exe -Stream *
```

Examine:

- PE headers, architecture, sections, imports/exports, resources, manifest, version metadata, overlay, and entropy.
- Authenticode chain, signer reputation, timestamping, and whether the file changed after signing.
- Strings, URLs, mutexes, paths, commands, registry keys, PDB paths, and embedded configuration.
- Packaging, installer format, scripts, macros, archives, and child payloads.
- Similarity and capability results, without treating reputation services as proof.

Tools:

- PEStudio: https://www.winitor.com/
- Detect It Easy: https://github.com/horsicq/Detect-It-Easy
- FLOSS: https://github.com/mandiant/flare-floss
- capa: https://github.com/mandiant/capa
- Ghidra: https://github.com/NationalSecurityAgency/ghidra
- x64dbg: https://x64dbg.com/
- YARA: https://virustotal.github.io/yara/

### 10.2 Dynamic analysis

Run unknown code only in an isolated, revertible lab designed for malware analysis. Capture:

- Process tree, command lines, modules, and injection behavior.
- Files, registry changes, services, tasks, WMI, and persistence.
- DNS, TCP/UDP, HTTP(S), TLS, named pipes, and IPC.
- API behavior, mutexes, tokens, privileges, and evasion attempts.
- Before/after snapshots and memory at meaningful stages.

Useful tools:

- FLARE-VM: https://github.com/mandiant/flare-vm
- Process Monitor: https://learn.microsoft.com/sysinternals/downloads/procmon
- Process Explorer: https://learn.microsoft.com/sysinternals/downloads/process-explorer
- FakeNet-NG: https://github.com/mandiant/flare-fakenet-ng
- INetSim: https://www.inetsim.org/
- Wireshark: https://www.wireshark.org/

Do not connect a malware lab to production networks, corporate credentials, shared clipboards, host folders, or uncontrolled internet access.

---

## 11. Common attacker TTPs and evidence

Full matrix: https://attack.mitre.org/matrices/enterprise/windows/

| Tactic/technique | Evidence to correlate |
|---|---|
| PowerShell (T1059.001) | 4104/4103, 4688, Sysmon 1, PSReadLine, AMSI/Defender, EDR |
| Windows Command Shell (T1059.003) | Process lineage, 4688/Sysmon 1, console history, EDR |
| Scheduled Task (T1053.005) | Security 4698/4702, Task Scheduler logs, task files, TaskCache |
| Windows Service (T1543.003) | System 7045, Security 4697, services registry, binary path |
| Registry Run Keys (T1060/T1547.001) | Run keys, Autoruns, user hive changes, process execution |
| WMI (T1047) | WMI-Activity, Sysmon 19-21, repository objects, `WmiPrvSE.exe` lineage |
| RDP (T1021.001) | Security logons, Terminal Services logs, network/VPN, profile activity |
| SMB/Admin Shares (T1021.002) | Share access logs when enabled, services/tasks, EDR, network telemetry |
| Credential Dumping (T1003) | LSASS access telemetry, Sysmon 10 where configured, EDR, dump files |
| Process Injection (T1055) | EDR, Sysmon 8/10/25 where configured, memory analysis, anomalous modules |
| Signed Binary Proxy Execution (T1218) | Parent/command line, target content, network, child behavior |
| Ingress Tool Transfer (T1105) | Browser/BITS/PowerShell, MOTW, proxy/DNS, file and execution artifacts |
| File Deletion (T1070.004) | USN, Recycle Bin, Sysmon, EDR, VSS, filesystem metadata |
| Indicator Removal: Clear Logs (T1070.001) | Security 1102, service/log state, forwarding gaps, EDR |
| Account Creation (T1136) | Security 4720, SAM/AD, identity-provider and admin audit logs |
| Group Membership Change | 4728/4732/4756 and corresponding removal events, AD metadata |

ATT&CK mappings describe behavior; they do not replace a finding's evidence or confidence assessment.

---

## 12. Recommended tooling summary

| Category | Tools |
|---|---|
| Memory acquisition | WinPmem, Magnet RAM Capture, Belkasoft RAM Capturer, DumpIt |
| Memory analysis | Volatility 3, MemProcFS, YARA |
| Disk imaging/mounting | FTK Imager, Guymager, libewf, Arsenal Image Mounter |
| Triage collection | KAPE, Velociraptor, CyLR, UAC |
| Event logs | Event Viewer, `Get-WinEvent`, EvtxECmd, Hayabusa, Chainsaw, Sigma |
| Registry | Registry Explorer, RECmd, RegRipper, regipy |
| NTFS | MFTECmd, MFTExplorer, The Sleuth Kit/Autopsy |
| Execution/user activity | PECmd, AmcacheParser, AppCompatCacheParser, LECmd, JLECmd, SBECmd |
| Timeline | Plaso, Timesketch, Timeline Explorer, Hayabusa |
| Live response | Sysinternals Suite, EDR, osquery, Velociraptor |
| Malware triage | PEStudio, Detect It Easy, FLOSS, capa, YARA, Ghidra, x64dbg |
| Network | Wireshark, Zeek, NetworkMiner, EDR, DNS/proxy/VPN telemetry |

Eric Zimmerman's tool index: https://ericzimmerman.github.io/#!index.md  
Sysinternals Suite: https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite  
osquery: https://osquery.io/  
Zeek: https://zeek.org/  
NetworkMiner: https://www.netresec.com/?page=NetworkMiner

Before operational use, validate licensing, hashes/signatures, target OS support, output semantics, and behavior under endpoint security controls.

---

## 13. Repeatable Windows IR checklist

1. **Authorize and classify** - establish incident owner, scope, legal/privacy requirements, severity, and evidence authority.
2. **Start the case log** - record UTC/local time, responders, host/user, source alerts, and all actions.
3. **Choose containment timing** - weigh active harm against evidence loss; preserve EDR/network context before isolation when safe.
4. **Capture volatile evidence** - memory, processes, sessions, sockets, handles, DNS/ARP, services, tasks, and BitLocker status.
5. **Export critical logs** - Security, System, PowerShell, Defender, Sysmon, RDP, WMI, Task Scheduler, BITS, and application-specific channels.
6. **Run targeted triage** - collect registry hives and logs, NTFS metadata, execution artifacts, persistence, browser/download, SRUM, and user activity.
7. **Acquire disk/volume evidence** - when impact, uncertainty, legal need, or suspected anti-forensics justifies it.
8. **Preserve external telemetry** - EDR, SIEM, AD/DC, IdP, DNS, proxy, VPN, email, cloud, firewall, and application logs.
9. **Build a timeline** - normalize time, preserve source semantics, and correlate independent artifacts.
10. **Scope laterally** - pivot on identities, hashes, paths, commands, domains/IPs, certificates, services, tasks, and behavioral fingerprints.
11. **Contain** - isolate hosts, disable/restrict identities, block infrastructure, or stop malicious workloads with documented approvals.
12. **Eradicate** - remove persistence and payloads, close initial-access paths, rotate exposed credentials/tokens, patch, and harden.
13. **Recover** - reimage when trust cannot be restored; monitor closely and validate business service integrity.
14. **Document findings** - distinguish facts, interpretation, assumptions, gaps, and confidence.
15. **Improve defenses** - update detections, logging, playbooks, hardening, training, and response metrics.

### Minimum host triage package

For a typical suspicious Windows endpoint, collect at least:

- Acquisition log, host/build/timezone, user/session, and tool hashes.
- Memory when justified and feasible.
- Process/service/task/network/autorun snapshots.
- Security, System, PowerShell, Defender, Sysmon, RDP, WMI, and Task Scheduler logs where available.
- `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, user `NTUSER.DAT`, `UsrClass.dat`, and registry transaction logs.
- `$MFT`, `$UsnJrnl`, and relevant NTFS metadata.
- Prefetch, Amcache, LNK, Jump Lists, Shellbags, Recycle Bin, and SRUM.
- Browser/download/Mark-of-the-Web evidence relevant to the hypothesis.
- Suspicious binaries/scripts/configuration with SHA-256 hashes.
- EDR process tree and centralized identity/network evidence.

---

## 14. Common analytical mistakes

- Treating one event ID or one tool verdict as proof.
- Claiming execution solely from Shimcache or file presence.
- Assuming missing Prefetch means non-execution.
- Reading timestamps without understanding their field/source semantics.
- Ignoring timezone, clock drift, event-forwarding delay, or log rollover.
- Running cleanup before preserving volatile evidence and persistence details.
- Disabling EDR or antivirus to make collection easier without approval.
- Collecting credentials or sensitive databases by default.
- Uploading confidential samples to public scanning services without authorization.
- Searching only for IOCs and missing behavior, identities, or persistence.
- Failing to scope the same identity and technique across other endpoints.
- Confusing a signed binary with a benign binary.
- Treating ATT&CK mapping as detection validation.
- Using production systems as a malware-analysis lab.

---

## 15. Further learning

- SANS FOR500 - Windows Forensic Analysis: https://www.sans.org/cyber-security-courses/windows-forensic-analysis/
- SANS FOR508 - Advanced Incident Response and Threat Hunting: https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/
- 13Cubed DFIR training: https://www.13cubed.com/
- Windows Internals resources: https://learn.microsoft.com/sysinternals/resources/windows-internals
- Velociraptor training and docs: https://docs.velociraptor.app/training/
- Volatility 3 documentation: https://volatility3.readthedocs.io/
- Eric Zimmerman's tools and documentation: https://ericzimmerman.github.io/#!index.md
- Plaso documentation: https://plaso.readthedocs.io/
- Timesketch documentation: https://timesketch.org/guides/
- MITRE ATT&CK Windows: https://attack.mitre.org/matrices/enterprise/windows/
- Microsoft audit policy recommendations: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
- DFIR community artifact knowledge base: https://www.forensicswiki.org/

> Final reminder: the best artifact is the one that answers the incident question with understood provenance and limitations. Correlate endpoint, identity, network, and control-plane evidence; state uncertainty explicitly; and preserve enough source material for another analyst to reproduce the conclusion.