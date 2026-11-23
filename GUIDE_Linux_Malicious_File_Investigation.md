# Investigating a Potentially Malicious File on Linux

A complete workflow: interview-ready answer first, then the detailed phase-by-phase guide.

---

## The interview answer (~90 seconds)

> "First I **preserve and identify** — hash the file immediately with `sha256sum` and record its metadata before touching it: `stat` for timestamps and inode, `ls -la` for permissions and ownership, and check extended attributes. On Linux there's no quarantine database like macOS, so provenance comes from shell history, `~/.wget-hsts`, package-manager logs, journald, and the process that created the file — which EDR or auditd captures.
>
> Then I do **static triage without executing it**: `file` to confirm the format, `readelf -h` and `-d` for ELF headers and linked libraries, `strings` for IOCs and embedded commands, and `checksec` for security properties like PIE and NX. If it's a script — shell, Python, Perl — I read it directly with `cat` rather than run it. A script wrapped in base64 or a downloader one-liner is an immediate red flag.
>
> For anything that warrants it, I move to **isolated dynamic analysis** in a VM with no network or a controlled sinkhole, watching `strace`/`ltrace`, process creation, file writes, and network connections.
>
> Finally I **correlate and scope** — EDR or auditd process lineage to find the parent, check persistence locations like cron, systemd units, shell rc files, and SSH authorized_keys, then hunt the hash and behavior across the fleet. The approach is: identify and preserve, static triage, dynamic if needed, correlate, then scope."

Then stop and let the interviewer probe.

---

## Detailed guide

### Phase 0 — Preserve & identify (before analysis)

```bash
# Hash immediately — forensic identity for the file
sha256sum /path/to/suspicious
md5sum /path/to/suspicious            # legacy intel lookups

# Record metadata without executing
stat /path/to/suspicious              # atime/mtime/ctime/birth, inode, size
ls -la /path/to/suspicious            # perms, owner, group
lsattr /path/to/suspicious 2>/dev/null  # immutable (i) or append-only (a) flags — rootkit tactic
getfattr -d /path/to/suspicious 2>/dev/null  # extended attributes

# Confirm the real type (don't trust the extension)
file /path/to/suspicious
```

**Provenance on Linux** (no quarantine DB — derive it from these):

| Source | Command / path | Tells you |
|---|---|---|
| Shell history | `~/.bash_history`, `~/.zsh_history`, `~/.sh_history` | The exact download/execution command (if not cleared) |
| auditd | `ausearch -f /path/to/suspicious` | Which process/user wrote or executed it |
| journald | `journalctl _EXE=/path/to/suspicious` | Service-context execution |
| Package logs | `/var/log/dpkg.log`, `/var/log/yum.log`, `/var/log/apt/` | Was it installed via a package? |
| Download tools | `~/.wget-hsts`, browser artifacts | Download source |
| EDR telemetry | process-create events | Parent process & command line |

**Interpretation cue:** a file in `/tmp`, `/var/tmp`, `/dev/shm`, or a hidden dir like `~/.config/.cache/` with a random name is a classic dropper/staging location. Check for a parent shell script or cron entry that wrote it.

---

### Phase 1 — Static triage (never execute on the host)

#### ELF binary analysis

```bash
file suspicious                       # ELF? 32/64-bit? static or dynamic? stripped?
readelf -h suspicious                 # ELF header: type, machine, entry point
readelf -d suspicious                 # dynamic section — NEEDED libs (suspicious .so deps)
readelf -S suspicious                 # section headers — look for packed/odd sections
readelf -s suspicious                 # symbols (absent = stripped)
ldd suspicious                        # runtime deps (DANGEROUS on untrusted — prefer readelf -d)
checksec --file=suspicious            # PIE, NX, RELRO, canary — hardening posture
objdump -d suspicious | less          # disassembly peek
```

#### Scripts — read, never run

```bash
cat suspicious.sh                     # read shell scripts directly
cat suspicious.py
# Base64-wrapped payloads are a huge red flag
cat suspicious.sh | grep -oE 'base64 -d|base64 --decode|eval |curl |wget |chmod \+x'
```

Look for: `curl ... | sh`, `wget -O- | bash`, `base64 -d | sh`, `eval "$(...)"`, reverse-shell one-liners (`/dev/tcp/`), and `nohup ... &` backgrounding.

#### Strings & IOC extraction

```bash
strings -a -n 6 suspicious | grep -iE 'http|/tmp/|/dev/tcp|crontab|systemd|/etc/passwd|wget|curl' | head -40
strings -a suspicious | grep -oE '\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b'   # IPs
strings -a suspicious | grep -iE 'ssh-rsa|authorized_keys|BEGIN .*PRIVATE KEY'
```

#### Package files

```bash
# .deb / .rpm — inspect contents & maintainer scripts without installing
dpkg-deb -c suspicious.deb            # list contents
dpkg-deb -e suspicious.deb ./ctrl     # extract control scripts (postinst = payload spot)
cat ./ctrl/postinst                   # READ it
rpm -qlp suspicious.rpm               # list contents
rpm2cpio suspicious.rpm | cpio -idmv  # extract
```

---

### Phase 2 — Dynamic analysis (isolated VM only)

Run in a **snapshotted VM** with no production network (or a sinkhole/INetSim). Capture:

```bash
# Syscall-level tracing
strace -f -o trace.txt ./suspicious       # follow forks, log syscalls
ltrace -f -o ltrace.txt ./suspicious      # library calls

# Watch network + persistence live
ss -tulpn                                  # listening sockets before/after
watch -n1 'ps auxf'                        # process tree as it runs
```

What to watch for:
- Child processes spawned (`strace -f` shows `clone`/`execve`)
- Files written to `/etc/cron.d/`, `~/.config/autostart/`, systemd unit dirs
- Outbound connections (`ss -tulpn`, or `tcpdump -i any -w capture.pcap`)
- Attempts to modify `~/.ssh/authorized_keys` or `/etc/passwd`
- Self-deletion (`unlink` on itself) or process masquerading

---

### Phase 3 — Persistence & scope

After confirming malicious, sweep every persistence surface:

```bash
# Cron
crontab -l ; ls -la /etc/cron* ; cat /etc/crontab

# systemd units (user + system)
systemctl list-units --type=service --state=running
ls -la /etc/systemd/system/ ~/.config/systemd/user/
grep -riE 'suspicious|/tmp/' /etc/systemd/system/ ~/.config/systemd/user/

# Shell init / autostart
cat ~/.bashrc ~/.profile ~/.bash_profile /etc/profile
ls -la ~/.config/autostart/ /etc/xdg/autostart/

# SSH persistence
cat ~/.ssh/authorized_keys
ls -la /etc/ssh/ ; grep -i permitrootlogin /etc/ssh/sshd_config

# SUID/SGID & capabilities
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null

# Loaded kernel modules / rootkits
lsmod ; modinfo <suspicious_module>
```

Then scope across the fleet: hunt the SHA-256, the parent process, the C2 IP/domain, and the persistence mechanism via EDR, osquery, or centralized logs.

---

## Red flags quick-list

| Signal | Why it matters |
|---|---|
| File in `/tmp`, `/dev/shm`, `/var/tmp`, or hidden dir | Classic staging/dropper location |
| `curl ... \| sh` or `base64 -d \| sh` in a script | Downloader / obfuscated payload |
| Immutable/append-only `chattr` flags | Rootkit protecting itself |
| SUID bit on an odd binary | Privilege escalation |
| Writes to `authorized_keys` or `/etc/passwd` | SSH persistence / account creation |
| New systemd unit or cron entry | Persistence |
| `/dev/tcp/` reverse-shell one-liner | C2 / shell |
| Self-deleting binary | Anti-forensics |
| Process name masquerading (`[kthreadd]`) | Kernel-thread disguise |
| Stripped + packed ELF | Evading static analysis |

---

## Related references

- Companion guide: `GUIDE_Linux_DFIR.md`
- MITRE ATT&CK Linux — https://attack.mitre.org/matrices/enterprise/linux/
- checksec — https://github.com/slimm609/checksec.sh
- INetSim (malware-lab sinkhole) — https://www.inetsim.org/
