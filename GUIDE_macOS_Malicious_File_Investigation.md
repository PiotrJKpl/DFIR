# Investigating a Potentially Malicious File on macOS

A complete workflow: interview-ready answer first, then the detailed phase-by-phase guide.

---

## The interview answer (~90 seconds)

> "First I **preserve and identify** the file — I hash it immediately and record the provenance before touching it: the quarantine extended attribute and the `QuarantineEventsV2` database tell me the download URL, the agent that fetched it, and when. Absence of quarantine is itself a signal — it may mean it was side-loaded, created by another process, or deliberately stripped.
>
> Then I do **static triage without executing it**: `codesign -dvvv` and `spctl -a -vvv` for signature and Gatekeeper verdict, `otool -L` for linked libraries, `strings` for IOCs, and I unpack the bundle — a `.app` is just a directory, so I read the `Info.plist` for the executable name and suspicious keys, check for nested scripts or hidden components, and look at entitlements that request powerful capabilities. A signed binary isn't automatically benign — attackers abuse legitimate signed apps, so I verify the Team ID and whether it's notarized.
>
> If static analysis warrants it, I move to **isolated dynamic analysis** in a VM with ProcessMonitor, FileMonitor, and Netiquette from Objective-See capturing process, file, and network events at launch.
>
> Finally I **correlate with telemetry and scope** — EDR process lineage, unified logs, persistence locations — and decide whether to contain and hunt the same hash or behavior across the fleet. The whole approach is: identify and preserve, static triage, dynamic if needed, correlate, then scope."

Then stop and let the interviewer probe. Don't dump the entire guide unprompted.

---

## Detailed guide

### Phase 0 — Preserve & identify (before analysis)

```bash
# Hash immediately — this is your forensic identity for the file
shasum -a 256 /path/to/suspicious.app
md5 /path/to/suspicious.app          # MD5 for legacy intel lookups

# Record metadata without opening it
ls -la@e /path/to/suspicious.app     # size, perms, ACLs, ALL extended attributes
stat /path/to/suspicious.app
mdls /path/to/suspicious.app         # Spotlight metadata (kMDItemWhereFroms = download source)
```

**Critical:** capture the `com.apple.quarantine` xattr and provenance *first* — analysis steps can alter metadata.

| Field | Command | Tells you |
|---|---|---|
| `com.apple.quarantine` xattr | `xattr -l file` | Downloaded? By which app? When? (flags + timestamp + UUID) |
| `kMDItemWhereFroms` | `mdls` | The download URL(s) |
| QuarantineEventsV2 DB | `sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 "..."` | Full download history tied to the xattr UUID |

Query the quarantine DB and join on the UUID from the xattr:

```bash
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName,
   LSQuarantineDataURLString, LSQuarantineOriginURLString FROM LSQuarantineEvent
   WHERE LSQuarantineEventIdentifier = '<uuid-from-xattr>';"
```

**Interpretation cue:** a malicious file that *lacks* quarantine usually means it was dropped by a script/another binary, downloaded via `curl` (no quarantine), or the attacker ran `xattr -d com.apple.quarantine` — check shell history and the parent process.

---

### Phase 1 — Static triage (never execute on the host)

#### Code signature & Gatekeeper

```bash
codesign -dvvv /path/to/suspicious.app            # Team ID, signing authority, flags
codesign --display --entitlements - /path/...      # capabilities the app claims
spctl -a -vvv --type execute /path/...             # Gatekeeper verdict (notarized?)
```

- **Unsigned / ad-hoc signed** (authority line shows "adhoc" or nothing) → suspicious for anything claiming to be legit software.
- **Validly signed** → verify the Team ID against the real vendor; attackers steal/reuse certs. A signature proves *who signed*, not *good intent*.
- **Entitlements** requesting `com.apple.security.get-task-allow`, broad file access, or automation over other apps → escalate scrutiny.

#### File type & structure

```bash
file /path/to/suspicious.app/Contents/MacOS/*      # Mach-O? universal (arm64+x86_64)?
otool -L /path/to/suspicious.app/Contents/MacOS/*  # linked dylibs — look for odd ones
otool -hv /path/to/...                             # Mach-O header
```

#### Unpack the bundle

An `.app` is a folder. Walk it:

```text
suspicious.app/
  Contents/
    Info.plist          ← executable name, bundle ID, URL schemes, suspicious keys
    MacOS/<binary>      ← actual executable
    Resources/          ← scripts, plists, hidden payloads
    Frameworks/         ← embedded dylibs (dylib hijacking spot)
    _CodeSignature/
```

```bash
plutil -p suspicious.app/Contents/Info.plist        # readable plist
find suspicious.app -name '*.plist' -o -name '*.sh' -o -name '*.command' -o -name '*.js'
```

Look for: shell scripts, `osax`/AppleScript, `.js` (JXA) payloads, and Mach-Os hidden in `Resources/`.

#### If it's an installer (`pkg`, `dmg`, or `.nupkg`)

```bash
# Expand a package WITHOUT installing it
pkgutil --expand-full suspicious.pkg ./expanded
ls ./expanded/*/Payload                              # the real contents
ls ./expanded/*/Scripts                              # pre/postinstall scripts = prime malware spot
cat ./expanded/*/Scripts/postinstall                 # READ before ever running

# DMG
hdiutil attach -readonly suspicious.dmg
```

**Post-install scripts are the #1 payload location in malicious packages** — read them with `cat`, never execute.

#### Strings & hashes for IOCs

```bash
strings -a binary | grep -iE 'http|https|\.sh|/tmp/|LaunchAgents|osascript|curl' | head -50
strings -a binary | grep -oE '\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b'   # IPs
```

Check hashes against VirusTotal / MISP / your threat intel.

---

### Phase 2 — Dynamic analysis (isolated VM only)

Run in a **snapshotted, network-controlled VM** (UTM/VMware), never the production host. Objective-See tools give you macOS-native telemetry:

| Tool | Captures |
|---|---|
| **ProcessMonitor** | Every process spawn + args (via Endpoint Security) |
| **FileMonitor** | File creates/modifies — catches dropped payloads |
| **Netiquette** | Network connections per process — C2 callouts |
| **BlockBlock** | Alerts when persistence is installed |
| **LuLu** | Egress firewall — confirms/blocks C2 |

Launch the sample, watch what spawns, what files it writes, whether it beacons, and whether it drops a LaunchAgent. Then snapshot-revert.

---

### Phase 3 — Correlate & scope

Now tie the file to the broader incident:

- **How did it get there?** Quarantine URL → phishing/browser/malvertising. No quarantine → parent process (EDR process tree).
- **Did it persist?** Check LaunchAgents/Daemons, login items (`sfltool dumpbtm`), cron.
- **What did it do?** EDR lineage: child processes, file writes, network connections.
- **Where else is it?** Hunt the SHA-256, Team ID, C2 domain, and behavior across the fleet via EDR/osquery.

---

## Red flags quick-list

| Signal | Why it matters |
|---|---|
| No quarantine xattr on a "downloaded" file | Side-loaded or stripped |
| Ad-hoc/unsigned claiming to be legit | Not notarized = Gatekeeper bypass attempt |
| Team ID doesn't match real vendor | Stolen/fake cert |
| `postinstall` script in a pkg | Classic payload location |
| Mach-O hidden in `Resources/` | Bundled dropper |
| Entitlement `get-task-allow` | Enables debugging/injection |
| Downloads & `chmod +x` then exec | Dropper behavior |
| Writes to `~/Library/LaunchAgents` | Persistence |
| `xattr -d com.apple.quarantine` | Anti-analysis |

---

## Related references

- Companion guide: `GUIDE_macOS_DFIR.md` §8 (malware analysis)
- Objective-See tools — https://objective-see.org/tools.html
- The Art of Mac Malware (free) — https://taomm.org/
- MITRE ATT&CK macOS — https://attack.mitre.org/matrices/enterprise/macos/
