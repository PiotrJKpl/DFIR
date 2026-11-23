# macOS DFIR — Detailed Field Guide

A practical, resource-linked guide to Digital Forensics & Incident Response on macOS. Built for blue-team / threat-response work (relevant to Mac-fleet environments). Organized by workflow: concepts → acquisition → artifacts → memory → malware → attacker TTPs → tooling → learning.

> **Golden rules:** preserve before you analyze, respect the **order of volatility**, document every command and hash, and work on **copies**. On modern macOS, SIP and TCC will block access to many artifacts unless you have Full Disk Access or a forensic image.

---

## 0. Authoritative starting points

| Resource | Why it matters | Link |
|---|---|---|
| Apple Platform Security Guide | The definitive reference for SIP, Gatekeeper, TCC, Secure Enclave, notarization, APFS encryption | https://support.apple.com/guide/security/welcome/web |
| SANS FOR518 — Mac & iOS Forensic Analysis and IR | The gold-standard macOS DFIR course + poster | https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/ |
| Sarah Edwards — mac4n6.com | Deep blog + tools (APOLLO, pattern-of-life) | https://www.mac4n6.com/ |
| Objective-See (Patrick Wardle) | Free Mac security/DFIR tools + "The Art of Mac Malware" | https://objective-see.org/tools.html |
| The Art of Mac Malware (free book) | Analysis of macOS malware & persistence | https://taomm.org/ |
| MITRE ATT&CK — macOS matrix | TTP mapping for detections & IR | https://attack.mitre.org/matrices/enterprise/macos/ |
| NIST macOS Security (macos_security) | Hardening baselines & compliance | https://github.com/usnistgov/macos_security |

---

## 1. macOS security concepts you must understand first

Understanding these controls tells you **what blocks your access** and **what artifacts they generate**.

- **SIP (System Integrity Protection)** — protects system locations and processes even from root. Status: `csrutil status`. Affects what you can read/modify on a live host.
- **TCC (Transparency, Consent & Control)** — the privacy framework gating access to camera, mic, Documents, Full Disk Access, etc. Stored in `TCC.db`. Attackers abuse TCC bypasses; responders need Full Disk Access to read protected artifacts. Apple ref: https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web
- **Gatekeeper + Notarization** — validates code signing/notarization on first launch of quarantined apps. Bypasses are a key initial-access TTP. https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web
- **XProtect / XProtect Remediator / MRT** — Apple's built-in signature AV & malware removal. Logs are a useful detection artifact.
- **Code signing** — `codesign -dvvv --entitlements - /path/app`; `spctl -a -vvv /path/app` for Gatekeeper assessment. Ad-hoc/unsigned binaries are suspicious.
- **APFS** — copy-on-write filesystem with snapshots (`tmutil`, `diskutil apfs list`). Snapshots can be a goldmine for point-in-time recovery.
- **FileVault** — full-disk encryption. You need the password/recovery key or a live/unlocked image to acquire.

---

## 2. Evidence acquisition

### 2.1 Order of volatility (collect in this order)
1. Memory (RAM) & volatile state (running processes, network connections, logged-in users)
2. Live triage artifacts (unified logs, open files, launchd state)
3. Disk image (or targeted file collection)
4. Snapshots / backups / cloud

### 2.2 Full disk imaging
- **Target Disk Mode / Share Disk** or boot to Recovery, then image the raw device (`/dev/diskN`) with `dd`, `dcfldd`, or a hardware imager. Apple Silicon complicates raw imaging (sealed system volume, encryption) — prefer **logical** collection or a live triage image when full physical imaging isn't feasible.
- Always compute and record hashes (`shasum -a 256`).
- Note: On Apple Silicon + FileVault, a raw image is encrypted; acquire while unlocked or capture a **logical** image.

### 2.3 Triage collection tools (fast, targeted)
| Tool | What it does | Link |
|---|---|---|
| **Jamf Aftermath** | Swift-based IR collection & analysis framework; collects artifacts into a database | https://github.com/jamf/aftermath |
| **CrowdStrike AutoMacTC** | Modular triage collector (bash/zsh history, launchd, quarantine, etc.) | https://github.com/CrowdStrike/automactc |
| **mac_apt** | macOS Artifact Parsing Tool — parses images & live systems into structured output | https://github.com/ydkhatri/mac_apt |
| **Yelp osxcollector** | Older but simple JSON collector | https://github.com/Yelp/osxcollector |
| **sysdiagnose** | Built-in: `sudo sysdiagnose` bundles logs, process lists, network state | Apple built-in |

> Practical tip: for a fast live triage, run **AutoMacTC** or **Aftermath** first (captures volatile + persistence), then decide whether full imaging is warranted.

---

## 3. Live response / volatile state

Capture these **before** anything reboots or rotates:

```bash
# Identity & uptime
sw_vers ; uname -a ; hostname ; uptime ; date -u

# Logged-in users & sessions
who -a ; last -20 ; w

# Running processes (full args + hierarchy)
ps aux
ps -axo pid,ppid,user,lstart,command

# Network state
netstat -anv            # or: lsof -i -n -P
lsof -nP -i             # open network files/sockets
arp -a ; ifconfig -a
scutil --dns            # resolver config (hijack check)

# Loaded kernel extensions / system extensions
kmutil showloaded 2>/dev/null ; systemextensionsctl list

# launchd services currently loaded
launchctl list
```

- **Open files / handles:** `lsof -nP` to map processes → files/sockets.
- **Environment & injected libs:** check `DYLD_INSERT_LIBRARIES` abuse (macOS equivalent of LD_PRELOAD) in process env and plists.
- Objective-See live tools: **Netiquette** (network monitor), **ProcessMonitor** & **FileMonitor** (ESF-based real-time events) — https://objective-see.org/tools.html

---

## 4. Core artifact categories (locations + why they matter)

### 4.1 Unified Logs — the single most important macOS artifact
Apple's consolidated logging system (since macOS 10.12) replaces syslog. Rich process/exec/network/auth telemetry, but **time-limited retention** and stored in a compressed binary tracev3 format.

- **Location:** `/var/db/diagnostics/` (+ `/var/db/uuidtext/` for string lookups)
- **Live query examples:**
```bash
# Last hour of everything (huge — filter!)
log show --last 1h

# Process executions & spawns
log show --predicate 'eventMessage CONTAINS "exec"' --last 24h

# Filter by subsystem/process
log show --predicate 'process == "sudo"' --info --last 24h

# Collect an archive for offline analysis
sudo log collect --output /evidence/host.logarchive
log show /evidence/host.logarchive --predicate '...'
```
- **Offline parsing:** UnifiedLogReader (Yogesh Khatri) — https://github.com/ydkhatri/UnifiedLogReader ; also parsed by mac_apt.
- **Why:** captures process launches, TCC prompts, Gatekeeper/XProtect verdicts, SSH/authentication, network daemons, and more.

### 4.2 FSEvents — filesystem change history
Records file system change events (create/rename/delete) — great for reconstructing attacker file activity even after deletion.
- **Location:** `/.fseventsd/` (per-volume, including external drives)
- **Parse with:** mac_apt, or dedicated FSEvents parsers (e.g., Nicole Ibrahim's FSEventsParser: https://github.com/dlcowen/FSEventsParser)
- **Why:** shows *that* files existed and were modified even if content is gone.

### 4.3 Spotlight metadata
Rich per-file metadata (timestamps, download URLs via `kMDItemWhereFroms`, content type).
```bash
mdls /path/to/suspicious.file      # dump metadata attributes
mdfind "kMDItemWhereFroms == '*'"  # find items with download provenance
```
- **Store:** `.Spotlight-V100/` per volume.

### 4.4 Quarantine database (download provenance)
Gatekeeper tags downloaded files with the `com.apple.quarantine` extended attribute and logs to a DB — tells you **where a file came from, which app downloaded it, and when**.
- **DB:** `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (SQLite)
- **xattr check:** `xattr -l /path/file` → look for `com.apple.quarantine`
```bash
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch') AS ts, \
   LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString \
   FROM LSQuarantineEvent ORDER BY ts DESC;"
```
- **Why:** ties a malicious binary to a phishing URL / browser / email client. Absence of quarantine xattr can itself indicate side-loading or attacker cleanup.

### 4.5 TCC.db — privacy permission grants (attacker-relevant)
Records which apps were granted sensitive permissions (Full Disk Access, Accessibility, Screen Recording, etc.). Accessibility/Screen-Recording grants to odd apps are a red flag (keylogging, screen capture).
- **System:** `/Library/Application Support/com.apple.TCC/TCC.db`
- **User:** `~/Library/Application Support/com.apple.TCC/TCC.db`
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, last_modified FROM access;"
```
- Background: https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive (community deep-dive) and Apple docs above.

### 4.6 KnowledgeC / Biome / PowerLog — pattern of life
`knowledgeC.db` and the newer **Biome** streams record app usage, focus, device activity — excellent for user-activity timelines.
- **User:** `~/Library/Application Support/Knowledge/knowledgeC.db`
- **System:** `/private/var/db/CoreDuet/Knowledge/knowledgeC.db`
- **Tool:** **APOLLO** (Apple Pattern of Life Lazy Output'er) — https://github.com/mac4n6/APOLLO
- Sarah Edwards' KnowledgeC research: https://www.mac4n6.com/blog/2018/8/5/knowledge-is-power-using-the-knowledgec-database-on-macos-and-ios-11-to-determine-precise-user-and-application-usage

### 4.7 User activity & shell history
- **Shell history:** `~/.zsh_history`, `~/.bash_history`, `~/.sh_history` (check `HISTFILE`, and whether history was disabled/cleared — anti-forensics).
- **Recent items / MRU:** `~/Library/Application Support/com.apple.sharedfilelist/` (`.sfl2` files) — parse with macMRU-Parser: https://github.com/mac4n6/macMRU-Parser
- **Bookmarks/aliases**, saved state, and `~/Library/Preferences/*.plist` (use `plutil -p file.plist` to render binary plists).

### 4.8 Browser & communication artifacts
- **Safari:** `~/Library/Safari/History.db`, `Downloads.plist`
- **Chrome:** `~/Library/Application Support/Google/Chrome/Default/History`
- **Firefox:** `~/Library/Application Support/Firefox/Profiles/*/places.sqlite`
- Correlate with quarantine DB for download provenance.

### 4.9 Network configuration artifacts
- Resolver/DNS hijack: `scutil --dns`, `/etc/resolv.conf`, `/etc/hosts`
- Proxy settings: `scutil --proxy`
- Network prefs: `/Library/Preferences/SystemConfiguration/preferences.plist`
- Wi-Fi history: `/Library/Preferences/com.apple.wifi.known-networks.plist` (newer) / `com.apple.airport.preferences.plist`

---

## 5. Persistence locations (attacker footholds) — check every one

Persistence is where most macOS intrusions are caught. Objective-See background: "Methods of Malware Persistence on macOS" and **KnockKnock** enumerates them all: https://objective-see.org/products/knockknock.html

| Mechanism | Location(s) | Notes |
|---|---|---|
| **LaunchAgents (user)** | `~/Library/LaunchAgents/` | Runs at user login; most common malware persistence |
| **LaunchAgents (global)** | `/Library/LaunchAgents/`, `/System/Library/LaunchAgents/` | System-wide; `/System` is SIP-protected |
| **LaunchDaemons** | `/Library/LaunchDaemons/`, `/System/Library/LaunchDaemons/` | Runs as root at boot |
| **Login Items (modern)** | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm` | **BTM** (Background Task Mgmt), Ventura+. `sfltool dumpbtm` to parse |
| **Login Items (legacy)** | `com.apple.loginitems.plist` | Older macOS |
| **Configuration Profiles / MDM** | `/Library/Managed Preferences/`, `profiles list` | Malicious profiles = powerful persistence/control |
| **cron** | `/usr/lib/cron/tabs/`, `crontab -l` | Classic scheduled tasks |
| **periodic / at** | `/etc/periodic/`, `/etc/defaults/periodic.conf`, `atq` | Less common |
| **Login/Logout hooks** | `com.apple.loginwindow` plist (`LoginHook`) | Deprecated but abused |
| **emond** (removed in modern macOS) | `/etc/emond.d/` | Legacy Event Monitor persistence |
| **Dylib hijacking / DYLD_INSERT_LIBRARIES** | app bundles, env, plists | Code injection persistence |
| **Kernel/System extensions** | `systemextensionsctl list`, `kmutil showloaded` | Rare, high-privilege |

Parse each `.plist` with `plutil -p` and inspect `ProgramArguments`, `RunAtLoad`, `KeepAlive`, and the target binary's signature.

```bash
# Enumerate launch items and show their target + signing status
for p in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
  [ -f "$p" ] || continue
  echo "== $p =="; plutil -p "$p" | grep -A3 ProgramArguments
done

# Parse modern Background Task Manager (login items / agents), Ventura+
sudo sfltool dumpbtm
```

---

## 6. Timeline building

Correlate artifacts into a single timeline (super-timeline):
- **plaso / log2timeline** supports many macOS artifacts — https://github.com/log2timeline/plaso
- **mac_apt** produces per-artifact tables you can merge.
- **APOLLO** for pattern-of-life (knowledgeC, biome, powerlog).
- Key timestamps: HFS+/APFS MACB times, FSEvents, unified logs, quarantine, Spotlight `kMDItem*` dates. Beware **timestomping** (T1070.006) — cross-check multiple sources.

---

## 7. Memory forensics

macOS memory is harder than Windows (SIP blocks most acquisition tools; per-kernel profiles needed).
- **Acquisition:** historically OSXPmem/osxpmem (rekall, now largely unmaintained); on modern systems live capture is limited by SIP. Often the practical volatile capture is a thorough **live-response** snapshot (§3) plus process dumps.
- **Analysis:** **Volatility 3** with a matching symbol table — https://github.com/volatilityfoundation/volatility3 (macOS support requires generating an Intermediate Symbol File for the exact kernel).
- **Process dumps:** targeted `lldb`/`vmmap`/`heap` on suspicious PIDs for triage when full RAM capture isn't possible.

> Reality check: for many modern macOS incidents, EDR process telemetry + unified logs + on-disk artifacts substitute for full memory forensics. Set expectations accordingly.

---

## 8. Malware analysis on macOS

Objective-See's toolset is the standard free kit:

| Tool | Purpose | Link |
|---|---|---|
| **KnockKnock** | Enumerate persistently installed items | https://objective-see.org/products/knockknock.html |
| **BlockBlock** | Monitor for new persistence in real time | https://objective-see.org/products/blockblock.html |
| **LuLu** | Open-source host firewall (egress/C2 visibility) | https://objective-see.org/products/lulu.html |
| **ProcessMonitor / FileMonitor** | ESF-based real-time process/file events | https://objective-see.org/tools.html |
| **Netiquette** | Live network connection monitor | https://objective-see.org/products/netiquette.html |
| **What'sYourSign** | Right-click code-signing info | https://objective-see.org/products/whatsyoursign.html |

**Static triage of a Mach-O / app bundle:**
```bash
file suspicious.app/Contents/MacOS/binary       # Mach-O? fat/universal?
codesign -dvvv --entitlements - suspicious.app   # signing + entitlements
spctl -a -vvv suspicious.app                     # Gatekeeper verdict
otool -L binary                                  # linked libraries (dylib deps)
otool -tV binary | head                          # disassembly peek
strings -a binary | less                         # strings, URLs, IOCs
nm binary                                         # symbols
xattr -l suspicious.app                          # quarantine / provenance
```

**Dynamic:** run in an isolated VM (UTM/VMware) with ProcessMonitor + FileMonitor + LuLu capturing process/file/network. The **Endpoint Security Framework (ESF)** is the modern telemetry source underneath these tools — https://developer.apple.com/documentation/endpointsecurity

Reference book (free): **The Art of Mac Malware, Vol. 1 (analysis) & Vol. 2 (detection)** — https://taomm.org/

---

## 9. Attacker TTPs on macOS (map your findings to ATT&CK)

Full matrix: https://attack.mitre.org/matrices/enterprise/macos/. High-frequency techniques to hunt:

- **Initial Access / Execution:** malicious `.dmg`/`.pkg`, trojanized apps, `osascript`/AppleScript (T1059.002), `curl | bash`, Electron/Node app abuse.
- **Persistence:** LaunchAgents/Daemons (T1543.001/.004), Login Items (T1547.015), cron (T1053.003), config profiles, dylib hijacking (T1574.004).
- **Privilege Escalation / Defense Evasion:** TCC bypass, Gatekeeper/quarantine removal (`xattr -d com.apple.quarantine`, T1553.001), code signing abuse, SIP disable attempts.
- **Credential Access:** Keychain dumping (`security dump-keychain`, T1555.001), browser cred stores.
- **Discovery:** `system_profiler`, `sw_vers`, `dscl . -list /Users`.
- **C2 / Exfil:** signed-binary proxying, DNS/HTTPS beacons (correlate with §4.9 + EDR).

---

## 10. Recommended tooling summary

| Category | Tools |
|---|---|
| **Triage collection** | Jamf Aftermath, CrowdStrike AutoMacTC, mac_apt, sysdiagnose |
| **Artifact parsing** | mac_apt, APOLLO, UnifiedLogReader, macMRU-Parser, FSEventsParser, plaso |
| **Live/real-time monitoring** | Objective-See ProcessMonitor/FileMonitor/Netiquette/BlockBlock/LuLu, osquery, crescendo (SentinelLabs) |
| **Malware analysis** | otool, codesign, spctl, strings, Hopper/Ghidra, Objective-See suite |
| **Memory** | Volatility 3 (with custom symbols) |
| **Endpoint telemetry (prod)** | CrowdStrike Falcon, ESF-based EDRs, osquery fleet |
| **Hardening/baseline** | NIST macos_security, CIS macOS Benchmark |

- **osquery:** https://osquery.io/ (live, SQL-queryable endpoint state — great for fleet-wide hunting)
- **crescendo (real-time macOS event viewer):** https://github.com/SentineLabs/crescendo

---

## 11. A repeatable macOS IR checklist

1. **Scope & preserve** — isolate the host (EDR network-contain), note volatility, start a chain-of-custody log.
2. **Volatile capture** — processes, network, logged-in users, launchd state, open files (§3).
3. **Unified log archive** — `sudo log collect` before rotation (§4.1).
4. **Triage collection** — run Aftermath / AutoMacTC (§2.3).
5. **Persistence sweep** — every location in §5 (KnockKnock + manual plist review).
6. **Provenance** — quarantine DB + Spotlight `kMDItemWhereFroms` to trace how it landed (§4.4/§4.3).
7. **Privilege/permission review** — TCC.db for suspicious Accessibility/Screen-Recording/FDA grants (§4.5).
8. **User activity timeline** — APOLLO (knowledgeC/biome), shell history, MRU, browser (§4.6/§4.7/§4.8).
9. **Correlate with EDR** — process lineage, command lines, network events; confirm on-disk.
10. **Contain, eradicate, recover** — remove persistence, revoke creds/keychain items, reimage if needed.
11. **Post-incident** — ATT&CK-mapped detections, playbook updates, IOCs, metrics (MTTD/MTTR).

---

## 12. Further learning

- **SANS macOS/iOS DFIR poster & FOR518** — https://www.sans.org/cyber-security-courses/mac-and-ios-forensic-analysis-and-incident-response/
- **mac4n6.com blog & tools (Sarah Edwards)** — https://www.mac4n6.com/
- **Objective-See blog & "Mac Malware of 20XX" annual reports** — https://objective-see.org/blog.html
- **The Art of Mac Malware (free)** — https://taomm.org/
- **Apple Platform Security Guide** — https://support.apple.com/guide/security/welcome/web
- **MITRE ATT&CK macOS** — https://attack.mitre.org/matrices/enterprise/macos/
- **NIST macos_security** — https://github.com/usnistgov/macos_security
- **mac_apt wiki** (artifact coverage reference) — https://github.com/ydkhatri/mac_apt/wiki

> Note: tool availability and artifact paths shift across macOS releases (especially Ventura/Sonoma+ with BTM, sealed system volume, and Apple Silicon). Always validate paths against the target OS version, and confirm access constraints from SIP/TCC/FileVault before acquisition.
