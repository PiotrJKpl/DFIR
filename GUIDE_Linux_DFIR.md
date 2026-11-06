# Linux DFIR - Detailed Field Guide

A practical, resource-linked guide to Digital Forensics and Incident Response on Linux workstations, servers, cloud instances, containers, and Kubernetes nodes. It is organized by workflow: preparation, acquisition, volatile collection, artifacts, filesystems, identity, containers, memory, malware, attacker TTPs, tooling, and repeatable response.

> **Golden rules:** obtain authorization, preserve before analyzing, follow the order of volatility, record every action and timestamp, hash collected evidence, and analyze verified copies. A live response changes the system. Document that footprint and collect only what the incident requires.

---

## 0. Authoritative starting points

| Resource | Why it matters | Link |
|---|---|---|
| NIST SP 800-86 | Integrating forensic techniques into incident response | https://csrc.nist.gov/pubs/sp/800/86/final |
| NIST SP 800-61 Rev. 3 | Current incident-response recommendations aligned with CSF 2.0 | https://csrc.nist.gov/pubs/sp/800/61/r3/final |
| Linux kernel documentation | `/proc`, filesystems, tracing, security, and kernel internals | https://docs.kernel.org/ |
| systemd manual | Journal, service manager, units, timers, and boot evidence | https://www.freedesktop.org/software/systemd/man/latest/ |
| Linux Audit documentation | Kernel audit framework, `auditd`, records, and rules | https://github.com/linux-audit/audit-documentation |
| MITRE ATT&CK Linux matrix | Map evidence and detections to adversary techniques | https://attack.mitre.org/matrices/enterprise/linux/ |
| SANS FOR577 | Linux incident response and threat-hunting curriculum | https://www.sans.org/cyber-security-courses/linux-threat-hunting-incident-response/ |
| Velociraptor documentation | Endpoint collection, hunting, parsing, and fleet response | https://docs.velociraptor.app/ |
| UAC | Open-source Unix-like artifact and volatile-state collector | https://github.com/tclahr/uac |

> **Distribution caveat:** paths, commands, log formats, package databases, service managers, and security controls vary across Debian/Ubuntu, RHEL/Fedora, SUSE, Arch, Alpine, immutable systems, appliances, and containers. Record the exact distribution, release, kernel, architecture, init system, filesystem, and workload before interpreting evidence.

---

## 1. Linux concepts a responder must understand

These concepts determine what evidence exists, how to acquire it, and what an artifact can prove.

- **Kernel and userspace are separate evidence domains.** `/proc`, `/sys`, eBPF, audit, kernel logs, and memory expose kernel state; shell histories, service logs, application data, and package databases expose userspace activity.
- **Linux has no universal execution cache equivalent to Windows Prefetch.** Reliable execution reconstruction usually requires audit/EDR/eBPF/process accounting, journal/syslog, shell history, application logs, filesystem metadata, and memory correlation.
- **`/proc` is a live virtual filesystem.** It exposes processes, command lines, environments, file descriptors, memory maps, namespaces, mounts, and network-related state. It is volatile and can be manipulated or hidden by rootkits.
- **systemd journal is structured and indexed.** Journals may be persistent under `/var/log/journal/` or volatile under `/run/log/journal/`. Retention, forwarding, sealing, namespace, and storage configuration matter.
- **Traditional syslog is still common.** `rsyslog`, `syslog-ng`, or application-specific logging may duplicate, transform, or forward journal messages into `/var/log/` text files.
- **Linux Audit (`auditd`) is policy-dependent.** It can capture syscalls, authentication, privilege use, file watches, and rule changes, but an absent event can mean missing rules, backlog loss, rotation, or tampering.
- **Filesystems differ substantially.** ext4, XFS, Btrfs, ZFS, overlayfs, tmpfs, NFS, and cloud block devices expose different metadata, journals, snapshots, and deletion behavior.
- **Deletion does not immediately remove every trace.** Directory entries, filesystem journals, unallocated blocks, backups, snapshots, logs, open file descriptors, and page cache may retain evidence.
- **LUKS/dm-crypt protects data at rest.** A powered-off disk may be encrypted; a live unlocked host permits logical collection and may contain key material in memory. Coordinate key collection with legal and system owners.
- **Namespaces and cgroups change process context.** A PID, mount, network interface, or path can look different from the host and inside a container.
- **Secure Boot, kernel lockdown, module signing, SELinux, AppArmor, and IMA** may block acquisition or record security-relevant denials and integrity events.
- **Root compromise breaks trust in local tools and local output.** Compare multiple collection methods, remote telemetry, cloud control-plane evidence, and known-good binaries.
- **Cloud instances are partly ephemeral.** Auto-scaling, instance replacement, ephemeral disks, metadata identities, and managed control planes require rapid collection outside the host.

Useful references:

- proc filesystem: https://docs.kernel.org/filesystems/proc.html
- Linux namespaces: https://man7.org/linux/man-pages/man7/namespaces.7.html
- cgroups v2: https://docs.kernel.org/admin-guide/cgroup-v2.html
- kernel lockdown: https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html
- Linux Integrity Measurement Architecture: https://ima-doc.readthedocs.io/

---

## 2. Preparation and evidence handling

### 2.1 Before an incident

A Linux DFIR program is much stronger when evidence collection is designed in advance:

1. Centralize journal/syslog, authentication, audit, sudo, SSH, web, database, container, orchestrator, EDR, and cloud logs.
2. Configure persistent journaling and appropriate retention where operationally justified.
3. Deploy tested audit rules or eBPF/EDR telemetry for process execution, identity, and sensitive changes.
4. Record cloud instance, image, disk, and service-account relationships in inventory.
5. Maintain signed or hashed response tools for each supported architecture and libc environment.
6. Pre-authorize network isolation, snapshots, memory acquisition, disk imaging, account suspension, and evidence transfer.
7. Document LUKS key/recovery ownership and lawful responder access.
8. Test collection under Secure Boot, lockdown, SELinux/AppArmor, read-only roots, containers, and production workloads.
9. Synchronize time and retain NTP/chrony state, timezone, and clock-offset evidence.
10. Run tabletop and technical exercises on representative hosts, cloud instances, and Kubernetes nodes.

Logging and hardening resources:

- `journald.conf`: https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html
- `systemd-journald.service`: https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html
- Red Hat audit guidance: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening
- Linux Audit rules: https://man7.org/linux/man-pages/man7/audit.rules.7.html
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- osquery: https://osquery.io/
- Falco runtime security: https://falco.org/docs/
- Tetragon eBPF observability: https://tetragon.io/docs/

### 2.2 Case log and chain of custody

Record at minimum:

- Case/incident identifier, authorization, legal/privacy constraints, and incident owner.
- Collector, date, UTC time, local timezone, host, workload, account, and physical/cloud location.
- Exact commands/tools, versions, parameters, architectures, and tool hashes/signatures.
- Source device identifiers, serials, partitions, filesystems, mount options, encryption, and snapshot IDs.
- Output filenames, sizes, SHA-256 hashes, storage destination, and transfer history.
- Every evidence handoff, access, copy, mount, conversion, extraction, and analysis action.
- Known collection errors, skipped files, permission denials, and changes made to the source.

Hash examples:

```bash
sha256sum memory.lime | tee memory.lime.sha256
sha256sum disk.E01 | tee disk.E01.sha256
find evidence -type f -print0 | sort -z | xargs -0 sha256sum > evidence.sha256
```

For courtroom or regulatory matters, follow organizational legal guidance and validated forensic procedures rather than relying on this field guide alone.

---

## 3. Evidence acquisition

### 3.1 Order of volatility

Collect the most transient evidence first when it is safe and proportionate:

1. Memory, processes, threads, namespaces, open file descriptors, sockets, routes, neighbor/ARP state, conntrack, and logged-in sessions.
2. Live security state: loaded modules/eBPF programs, services, timers, cron, firewall, audit rules/status, SELinux/AppArmor, mounts, and encryption state.
3. Targeted triage artifacts: journal/syslog, audit, authentication, shell history, package logs, persistence, filesystem metadata, application and container logs.
4. Full disk, volume, virtual disk, or cloud snapshot.
5. Filesystem snapshots, backups, centralized logs, control-plane telemetry, and adjacent systems.

> Isolation changes network evidence. Shutdown destroys memory and may lock encrypted volumes. During active ransomware, destructive activity, or exfiltration, risk reduction may take priority over perfect evidence preservation.

### 3.2 Memory acquisition

Memory can expose processes, sockets, injected code, fileless payloads, deleted/open files, command fragments, credentials or keys, decrypted content, and kernel rootkits.

| Tool | Notes | Link |
|---|---|---|
| AVML | Rust-based Linux memory acquisition; test against target kernel/hardening | https://github.com/microsoft/avml |
| LiME | Loadable kernel module producing raw/LiME/padded captures | https://github.com/504ensicsLabs/LiME |
| cloud/hypervisor snapshot | Platform-specific memory state when explicitly supported | Consult the platform documentation |

Operational cautions:

- Acquisition changes RAM and may load a kernel module or use privileged kernel interfaces. Record tool/version/hash and start/end times.
- Secure Boot, kernel lockdown, signed-module policy, custom kernels, and endpoint controls may prevent acquisition.
- Compiling LiME on the compromised host adds substantial footprint and trusts its toolchain. Prefer a prebuilt, exact-kernel module from a controlled environment when policy allows.
- Do not disable Secure Boot, lockdown, EDR, or mandatory access controls casually to force acquisition.
- Memory contains credentials, tokens, keys, personal data, and confidential content. Encrypt and restrict evidence storage.
- Validate output size, format, and hash immediately; retain acquisition stdout/stderr and kernel messages.
- A crash dump, hibernation-like mechanism, VM saved state, or `/proc/kcore` is not automatically equivalent to a complete, stable physical-memory image.

Volatility Linux acquisition guidance: https://volatility3.readthedocs.io/en/stable/getting-started-linux-tutorial.html#acquiring-memory

### 3.3 Disk and volume imaging

Use a hardware write blocker for offline media when practical. Acquire the correct source: physical disk, logical volume, partition, virtual disk, cloud volume, RAID/LVM member set, or targeted files.

Common tools:

- Guymager: https://guymager.sourceforge.io/
- `dcfldd`: https://dcfldd.sourceforge.net/
- `ddrescue` for failing media: https://www.gnu.org/software/ddrescue/
- `ewfacquire`/libewf for E01: https://github.com/libyal/libewf
- FTK Imager: https://www.exterro.com/digital-forensics-software/ftk-imager
- NIST CFTT disk-imaging tests: https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/disk-imaging

Example raw acquisition from trusted media:

```bash
sudo dcfldd if=/dev/sdX of=/evidence/host-disk.raw \
  hash=sha256 hashlog=/evidence/host-disk.sha256 \
  errlog=/evidence/host-disk.err conv=noerror,sync
```

Capture and verify:

- Device make/model/serial, sector sizes, partition table, capacity, and RAID/LVM topology.
- Image type (`raw`, `E01`, `qcow2`, `VMDK`, `VHDX`) and sparse/compression behavior.
- Acquisition and verification hashes.
- Read errors, bad sectors, tool output, and source/destination identifiers.
- LUKS/dm-crypt status and whether data was collected encrypted or unlocked.
- Filesystem type, UUID, labels, mount options, and snapshot state.

Do not mount original evidence read-write. Mount verified copies read-only, disable journal replay, or use forensic tooling. A nominally read-only mount can still cause writes through automounters, journal replay, or helpers if not controlled.

### 3.4 LVM, snapshots, and filesystems

- LVM snapshots can provide a point-in-time volume but require enough copy-on-write space and do not capture RAM.
- Btrfs/ZFS snapshots preserve filesystem state according to their own semantics; record snapshot IDs and creation time.
- Cloud snapshots may be crash-consistent rather than application-consistent.
- Databases often require transaction/WAL/binlog evidence in addition to block snapshots.
- Preserve RAID metadata and all member disks where reconstruction is required.

Useful commands for documenting topology:

```bash
lsblk -O -J > lsblk.json
blkid > blkid.txt
findmnt --all --output-all --json > findmnt.json
pvs --reportformat json > pvs.json 2>&1
vgs --reportformat json > vgs.json 2>&1
lvs --all --reportformat json > lvs.json 2>&1
dmsetup ls --tree > dmsetup-tree.txt 2>&1
cryptsetup status <mapping-name> > cryptsetup-status.txt 2>&1
```

### 3.5 Fast triage collection

Full imaging is not always the fastest or most proportionate response. Triage collectors preserve high-value evidence quickly:

| Tool | Best use | Link |
|---|---|---|
| UAC | Portable Unix-like volatile and artifact collection | https://github.com/tclahr/uac |
| Velociraptor | Remote collection, hunts, VQL parsing, and fleet response | https://docs.velociraptor.app/ |
| GRR Rapid Response | Remote live forensics and fleet collection | https://grr-doc.readthedocs.io/ |
| osquery | SQL-queryable live endpoint state and scheduled telemetry | https://osquery.readthedocs.io/ |

Prefer a tested collection profile tied to the incident hypothesis. Collecting everything can waste time, exhaust disks, overload production, and increase privacy exposure.

### 3.6 Virtual machines and cloud hosts

- Coordinate disk snapshots with the cloud/hypervisor and record snapshot time, region, account/project, instance ID, image ID, and volume mapping.
- A disk snapshot does not capture RAM unless the platform explicitly supports memory/saved state.
- Export cloud audit, identity, serial console, flow, firewall, load-balancer, object-access, and metadata-service logs separately.
- Preserve instance/user data, startup scripts, attached identities/roles, security groups, tags, and orchestration history.
- Record auto-scaling and replacement events; the compromised instance may disappear automatically.
- Preserve the original virtual disk format when possible and hash exports.

Cloud audit resources:

- AWS CloudTrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
- AWS EC2 instance identity documents: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
- Google Cloud Audit Logs: https://cloud.google.com/logging/docs/audit
- Azure Activity Log: https://learn.microsoft.com/azure/azure-monitor/platform/activity-log

---

## 4. Live response and volatile state

Run commands from trusted, preferably statically linked response media where authorized. Redirect output to protected evidence storage and record command start/end times. Local commands can be hooked or replaced after root compromise; compare with remote telemetry and direct `/proc` inspection.

### 4.1 Host, time, and environment

```bash
date --iso-8601=ns
date -u --iso-8601=ns
timedatectl status
hostnamectl
uname -a
cat /etc/os-release
uptime
who -a
w
last -Faiwx | head -100
lastb -Faiwx | head -100
```

Preserve time synchronization evidence:

```bash
timedatectl timesync-status 2>&1
chronyc tracking 2>&1
chronyc sources -v 2>&1
ntpq -pn 2>&1
```

### 4.2 Processes, threads, namespaces, and open files

```bash
ps auxwwf
ps -eo pid,ppid,sid,lstart,user,group,stat,comm,args --forest
pstree -alp
top -b -n 1

# Process command line, executable, environment, maps, and namespaces
for pid in /proc/[0-9]*; do
  printf 'PID=%s EXE=' "${pid##*/}"
  readlink "$pid/exe" 2>/dev/null
  tr '\0' ' ' < "$pid/cmdline" 2>/dev/null; echo
done

lsof -nP
lsof +L1                 # open files with link count < 1, often deleted
lsns
```

High-value `/proc/<pid>/` entries:

- `cmdline`, `comm`, `stat`, `status`, `exe`, `cwd`, and `root`.
- `environ` for injected variables, credentials, proxies, and loader abuse.
- `fd/` and `fdinfo/` for files, sockets, pipes, memfd, and deleted binaries.
- `maps`, `smaps`, and `mem` for loaded files and anonymous executable regions.
- `mountinfo`, `cgroup`, `ns/`, and `root` for container/namespace context.
- `loginuid`, `sessionid`, and credentials-related status fields where available.

> Reading `/proc/<pid>/environ` or memory can expose secrets. Collect only when authorized and protect output accordingly.

### 4.3 Network state

```bash
ip -details address
ip route show table all
ip rule show
ip neigh show
ss -H -tunapoe
lsof -nP -i
cat /proc/net/dev
cat /proc/net/route
resolvectl status 2>&1
cat /etc/resolv.conf
cat /etc/hosts

# Firewall and connection tracking, where present
nft list ruleset 2>&1
iptables-save 2>&1
ip6tables-save 2>&1
conntrack -L 2>&1
```

Also preserve:

- NetworkManager/systemd-networkd configuration and leases.
- VPN, proxy, DNS, firewall, load balancer, cloud flow, and service-mesh telemetry.
- Network namespace state for suspicious containers: `nsenter -t <pid> -n ss -tunap` when authorized.

### 4.4 Services, jobs, modules, and security state

```bash
systemctl list-units --type=service --all
systemctl list-unit-files --type=service
systemctl list-timers --all
systemctl --user list-units --all 2>&1

crontab -l 2>&1
atq 2>&1
find /etc/cron* /var/spool/cron* -xdev -ls 2>&1

lsmod
cat /proc/modules
modinfo <module> 2>&1
bpftool prog show 2>&1
bpftool map show 2>&1

auditctl -s 2>&1
auditctl -l 2>&1
getenforce 2>&1
sestatus 2>&1
aa-status 2>&1
cat /sys/kernel/security/lockdown 2>&1
cat /proc/sys/kernel/tainted 2>&1
```

### 4.5 Package and integrity snapshot

```bash
# Debian/Ubuntu
dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' > packages-dpkg.tsv
debsums -s 2>&1 | tee debsums-changes.txt

# RHEL/Fedora/SUSE-style RPM systems
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' > packages-rpm.tsv
rpm -Va 2>&1 | tee rpm-verify.txt

# Alpine
apk info -vv > packages-apk.txt
apk audit --system 2>&1 | tee apk-audit.txt
```

Package verification identifies deviations from package metadata, not necessarily malicious changes. Configuration files, legitimate updates, runtime-generated files, mutable containers, and package database tampering require contextual analysis and known-good comparison.

> Do not kill a suspicious process merely because it looks malicious. Capture lineage, executable/link target, hashes, file descriptors, sockets, memory/maps, namespace/cgroup, service definition, and persistence first when operational risk permits.

---

## 5. Core forensic artifacts

### 5.1 systemd journal

Typical storage:

```text
/var/log/journal/<machine-id>/   # persistent
/run/log/journal/<machine-id>/   # volatile
```

The journal may include kernel, service stdout/stderr, syslog, audit, boot, user-session, and structured metadata. Important fields include `_BOOT_ID`, `_MACHINE_ID`, `_SYSTEMD_UNIT`, `_UID`, `_PID`, `_EXE`, `_CMDLINE`, `SYSLOG_IDENTIFIER`, and monotonic/realtime timestamps.

Collection and query examples:

```bash
# Record journal health and storage usage
journalctl --verify
journalctl --disk-usage
journalctl --list-boots

# Preserve all available records in stable export format
journalctl --output=export > /evidence/journal.export

# Preserve JSON for analysis
journalctl --output=json --all > /evidence/journal.json

# Query a boot, unit, executable, or time window
journalctl -b -1 --utc --no-pager
journalctl -u ssh.service --since '2026-08-15 00:00:00 UTC' --utc
journalctl _EXE=/usr/bin/sudo --utc
journalctl -k --utc
```

For offline analysis, copy the journal directories and machine ID when possible:

```bash
cp -a --reflink=auto /var/log/journal /evidence/ 2>/dev/null
cp -a --reflink=auto /run/log/journal /evidence/run-journal 2>/dev/null
cp -a /etc/machine-id /evidence/ 2>/dev/null
```

Important caveats:

- Volatile journals disappear at reboot.
- Rotation, vacuuming, storage limits, corruption, namespaces, and attacker deletion create gaps.
- `_CMDLINE`, `_EXE`, and other metadata are captured at message ingestion, not a complete process history.
- `journalctl --verify` checks internal consistency and optional sealing; it does not prove completeness or benign content.
- Exported text/JSON is useful for analysis but retain original binary journal files for full provenance.
- Compare local journal records with remote syslog/SIEM and cloud telemetry.

Resources:

- `journalctl`: https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
- Journal file format: https://systemd.io/JOURNAL_FILE_FORMAT/
- Journal export format: https://systemd.io/JOURNAL_EXPORT_FORMATS/
- Forward Secure Sealing: https://www.freedesktop.org/software/systemd/man/latest/journalctl.html#--setup-keys

### 5.2 Syslog and distribution log files

Common locations vary:

| Evidence | Debian/Ubuntu examples | RHEL/Fedora examples |
|---|---|---|
| Authentication | `/var/log/auth.log` | `/var/log/secure` |
| General system | `/var/log/syslog` | `/var/log/messages` |
| Kernel | `/var/log/kern.log` | journal or `/var/log/messages` |
| Package actions | `/var/log/dpkg.log`, `/var/log/apt/` | `/var/log/dnf.log`, `/var/log/yum.log` |
| Audit | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Login records | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | Same/common equivalents |

Also check:

- `/etc/rsyslog.conf`, `/etc/rsyslog.d/`, `/etc/syslog-ng/`.
- Rotated/compressed files such as `.1`, `.gz`, date suffixes, and remote spool queues.
- Service-specific logs under `/var/log/<service>/` and application data directories.
- Forwarder state and queue files for rsyslog, Fluent Bit, Filebeat, Vector, or cloud agents.

Do not assume text-file order equals exact event order; buffering, forwarding, timezone formatting, and multi-line records can reorder or split entries.

### 5.3 Linux Audit (`auditd`)

Typical evidence:

```text
/var/log/audit/audit.log
/etc/audit/auditd.conf
/etc/audit/audit.rules
/etc/audit/rules.d/*.rules
```

Useful commands:

```bash
auditctl -s
auditctl -l
ausearch --start today --interpret
ausearch -m USER_LOGIN,USER_AUTH,USER_ACCT,CRED_ACQ,CRED_DISP --start recent -i
ausearch -m EXECVE,SYSCALL --start recent -i
aureport --summary
aureport --auth --success
aureport --login
aureport --executable
```

Audit records for one action may share a `msg=audit(epoch:serial)` identifier across `SYSCALL`, `EXECVE`, `PATH`, `CWD`, `PROCTITLE`, and identity records. Correlate the full record set before interpreting the event.

Important caveats:

- `auditd` only records configured events plus mandatory audit events.
- Backlog overflow, rate limits, disk-full action, rotation, service failure, or immutable rules affect coverage.
- `auid`/login UID can preserve the original login identity across `sudo`, while `uid`/`euid` describe current credentials. Validate fields carefully.
- Interpreted output (`-i`) is convenient but can resolve IDs using current local state. Retain raw records.
- Attackers with sufficient privilege may stop audit, change rules, or tamper with local files; compare remote copies.

Resources:

- audit userspace repository: https://github.com/linux-audit/audit-userspace
- `auditd(8)`: https://man7.org/linux/man-pages/man8/auditd.8.html
- `ausearch(8)`: https://man7.org/linux/man-pages/man8/ausearch.8.html
- audit record types: https://access.redhat.com/articles/4409591

### 5.4 Authentication, sudo, SSH, and login records

Collect and correlate:

- Journal/syslog SSH authentication and session records.
- `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` and backups such as `passwd-`/`shadow-`.
- `/etc/sudoers`, `/etc/sudoers.d/`, sudo I/O logs, and sudo journal/syslog.
- `/etc/ssh/sshd_config`, included fragments, host keys, and authorized principals.
- User `~/.ssh/authorized_keys`, `known_hosts`, `config`, certificates, control sockets, and key metadata where authorized.
- `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`, utmp, and systemd-logind sessions.
- PAM configuration under `/etc/pam.d/` and security modules under `/usr/lib*/security/`.
- NSS/SSSD/LDAP/Kerberos configuration and logs where enterprise identity is used.

Commands:

```bash
last -Faiwx
lastb -Faiwx
lastlog
loginctl list-sessions
loginctl session-status <session-id>
getent passwd
getent group
sudo -V
sshd -T 2>/dev/null
```

Important caveats:

- `wtmp`, `btmp`, and `lastlog` are mutable binary databases and can be truncated or edited.
- Source addresses may be proxies, bastions, NAT, VPN, or load balancers.
- SSH `Accepted publickey` proves key-based authentication, not necessarily which human controlled the key.
- Container logins and cloud session managers may bypass traditional SSH evidence.
- Correlate identity-provider, bastion, VPN, cloud, and endpoint records.

OpenSSH logging: https://man.openbsd.org/sshd_config

### 5.5 Shell and command history

Potential artifacts:

```text
~/.bash_history
~/.zsh_history
~/.ash_history
~/.local/share/fish/fish_history
/root/.*_history
```

Also inspect:

- `HISTFILE`, `HISTSIZE`, `HISTFILESIZE`, `HISTCONTROL`, `HISTTIMEFORMAT`, `PROMPT_COMMAND`.
- Shell startup files: `/etc/profile`, `/etc/profile.d/`, `/etc/bash*`, `/etc/zsh*`, `~/.profile`, `~/.bashrc`, `~/.zshrc`.
- `sudo` logs, audit `EXECVE`, process accounting, terminal multiplexers, editor histories, and application consoles.
- Cloud-init, configuration management, CI/CD, orchestration, and deployment logs.

History limitations:

- Bash normally writes history at shell exit unless configured otherwise.
- Commands can be excluded, disabled, overwritten, edited, or executed by non-interactive shells.
- Timestamps exist only if configured and may apply to command groups imperfectly.
- History text does not prove successful execution or result.
- Absence of a command is not evidence that it did not run.

### 5.6 Process accounting and execution telemetry

If enabled, BSD process accounting (`acct`/`psacct`) records completed commands:

```bash
systemctl status acct 2>&1
systemctl status psacct 2>&1
lastcomm
sa
```

Common files include `/var/log/account/pacct` or `/var/account/pacct`, depending on distribution.

Other execution sources:

- Linux Audit `EXECVE`/`SYSCALL`/`PROCTITLE`.
- EDR and eBPF telemetry from osquery, Falco, Tetragon, Tracee, or commercial sensors.
- systemd unit invocations and service stdout/stderr.
- Shell history and sudo I/O logging.
- Application, web, database, CI/CD, and container runtime logs.
- Filesystem timestamps, package logs, and downloaded-file evidence.
- Memory and live `/proc` state.

No single source is complete. Define the observed population and known blind spots before making execution claims.

### 5.7 Filesystem metadata and deleted files

Collect or image the filesystem before recovery attempts. Useful evidence includes:

- Inode metadata: mode, UID/GID, size, links, block mapping, and MACB/crtime timestamps where supported.
- Directory entries and filesystem journals/logs.
- Extended attributes, POSIX ACLs, capabilities, SELinux labels, and immutable/append-only flags.
- Sparse files, hard links, symlinks, bind mounts, overlays, and mount namespaces.
- Deleted files still open through `/proc/<pid>/fd/`.
- Unallocated space, slack, snapshots, backups, and application journals.

Commands:

```bash
stat <file>
ls -laZ <path> 2>/dev/null
getfattr -d -m- <file> 2>/dev/null
getfacl -p <file> 2>/dev/null
getcap -r / 2>/dev/null
lsattr -R <path> 2>/dev/null
find /proc/[0-9]*/fd -lname '* (deleted)' -ls 2>/dev/null
```

Filesystem resources:

- ext4 documentation: https://docs.kernel.org/filesystems/ext4/index.html
- XFS documentation: https://docs.kernel.org/filesystems/xfs.html
- Btrfs documentation: https://btrfs.readthedocs.io/
- OpenZFS documentation: https://openzfs.github.io/openzfs-docs/
- The Sleuth Kit: https://www.sleuthkit.org/sleuthkit/
- Autopsy: https://www.autopsy.com/
- ext4magic: https://sourceforge.net/projects/ext4magic/

Critical cautions:

- Mounting ext4 can replay the journal and change evidence; use forensic copies and replay controls.
- Journal entries are finite and overwritten; they are not a complete operation history.
- `ctime` is inode-change time, not file creation time. `btime`/crtime availability varies.
- Atime may be disabled, relatime, lazytime, or altered by collection.
- Root can change timestamps, attributes, ownership, and labels; correlate independent sources.
- Recovery tools can overwrite unallocated evidence if run on the source.

### 5.8 Package, update, and software-installation evidence

Potential evidence:

- Debian/Ubuntu: `/var/log/dpkg.log*`, `/var/log/apt/`, `/var/lib/dpkg/`.
- RHEL/Fedora: `/var/log/dnf*`, `/var/log/yum.log*`, `/var/lib/rpm/`.
- SUSE: `/var/log/zypp/`, RPM database.
- Arch: `/var/log/pacman.log`, `/var/lib/pacman/`.
- Alpine: `/var/log/apk.log`, `/lib/apk/db/`.
- Snap: `/var/lib/snapd/`, snapd journal.
- Flatpak: installation directories and deployment metadata.
- Language/package managers: pip, npm, RubyGems, Go, Cargo, Conda, Composer, and local caches/logs.

Correlate package transactions with filesystem metadata, sudo/audit, shell history, service restarts, repository configuration, signing keys, and remote deployment systems.

### 5.9 Persistence mechanisms

| Mechanism | Evidence/location |
|---|---|
| systemd system units | `/etc/systemd/system/`, `/run/systemd/system/`, vendor unit directories |
| systemd user units | `~/.config/systemd/user/`, `/etc/systemd/user/`, linger state |
| systemd timers | Timer/service unit pairs, `systemctl list-timers --all` |
| cron/anacron | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron*` |
| `at` jobs | `/var/spool/at*`, `atq` |
| SysV init/rc.local | `/etc/init.d/`, `/etc/rc*.d/`, `/etc/rc.local` |
| shell/profile | `/etc/profile*`, shell rc files, environment hooks |
| SSH keys/certs | `authorized_keys`, principals, SSH CA/config changes |
| dynamic linker | `/etc/ld.so.preload`, `LD_PRELOAD`, library search paths |
| PAM/NSS | `/etc/pam.d/`, NSS config/modules, SSSD/LDAP changes |
| kernel modules | `/etc/modules*`, `/etc/modprobe.d/`, initramfs, loaded modules |
| udev | `/etc/udev/rules.d/`, helper programs |
| network hooks | NetworkManager dispatchers, DHCP hooks, if-up scripts |
| package hooks | apt/dpkg/rpm/pacman hooks and maintainer scripts |
| container runtime | Docker restart policies, Compose, containerd/CRI services |
| Kubernetes | DaemonSets, static pods, admission webhooks, privileged workloads |
| cloud startup | cloud-init, instance/user data, metadata scripts, agents |
| web/application | Web shells, plugins, startup modules, scheduled jobs |

For each entry, record path, arguments, owner, permissions/ACLs, capabilities, labels, hash, package ownership, timestamps, service relationships, namespace, and fleet prevalence.

systemd unit references:

- `systemd.unit`: https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
- `systemd.service`: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
- `systemd.timer`: https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html

### 5.10 Web, database, and application evidence

Potential sources:

- Nginx: `/var/log/nginx/`, configured custom paths, systemd journal.
- Apache/httpd: `/var/log/apache2/` or `/var/log/httpd/`, configured virtual-host logs.
- PHP-FPM, application framework, reverse proxy, WAF, CDN, and load-balancer logs.
- PostgreSQL/MySQL/MariaDB audit, query, error, transaction/WAL/binlog, and connection logs.
- Redis, Elasticsearch, message queues, object stores, and service-specific audit logs.
- Application deploy manifests, environment files, secrets references, CI/CD logs, and package lockfiles.

Investigation method:

1. Identify the request/session/account and preserve raw records.
2. Reconstruct proxy/CDN/load-balancer hops and original client-address handling.
3. Correlate application request IDs with process, file, database, identity, and network evidence.
4. Search for web shells, modified plugins, injected startup code, unexpected interpreters, and outbound connections.
5. Scope the same path, hash, request pattern, account, and destination across nodes.

Do not rely solely on source IP fields populated by headers such as `X-Forwarded-For`; validate trusted-proxy configuration and upstream logs.

### 5.11 Kernel, module, eBPF, and rootkit evidence

Collect:

- `dmesg`, journal kernel messages, boot parameters, kernel taint, lockdown, and module-signature state.
- `lsmod`, `/proc/modules`, `/sys/module/`, module files, initramfs, and module-load configuration.
- `bpftool prog/map/link show`, tracing filesystem state, and pinned objects under `/sys/fs/bpf/`.
- Syscall/tracing hooks, suspicious character devices, hidden processes/ports, and discrepancies between views.
- IMA measurements/appraisal logs where enabled.

Useful commands:

```bash
dmesg --ctime --decode 2>&1
cat /proc/cmdline
cat /proc/sys/kernel/tainted
find /sys/module -maxdepth 2 -type f -name taint -o -name srcversion -o -name version
find /sys/fs/bpf -ls 2>&1
bpftool prog show 2>&1
bpftool link show 2>&1
bpftool net show 2>&1
cat /sys/kernel/security/ima/ascii_runtime_measurements 2>&1
```

Rootkit scanners such as rkhunter/chkrootkit can generate leads but are not verdict engines and may be evaded or produce false positives:

- rkhunter: https://rkhunter.sourceforge.net/
- chkrootkit: https://www.chkrootkit.org/

Prefer cross-view comparison, memory forensics, known-good kernel/module hashes, package/image verification, remote EDR, and rebuilding high-trust systems when integrity cannot be established.

### 5.12 SELinux, AppArmor, capabilities, and privilege evidence

Collect:

- SELinux mode/policy, labels, AVC denials, boolean changes, and audit records.
- AppArmor profiles, mode, denials, parser/cache state, and profile modifications.
- File capabilities (`security.capability`), setuid/setgid files, ACLs, and sudo/polkit configuration.
- Namespace/user-namespace settings and container privilege configuration.

```bash
getenforce 2>&1
sestatus 2>&1
ausearch -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -ts recent -i 2>&1
aa-status 2>&1
getcap -r / 2>/dev/null
find / -xdev \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
find /etc/polkit-1 /usr/share/polkit-1 -type f -ls 2>/dev/null
```

Resources:

- SELinux project: https://selinuxproject.org/page/Main_Page
- Red Hat SELinux troubleshooting: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/troubleshooting-problems-related-to-selinux_using-selinux
- AppArmor documentation: https://gitlab.com/apparmor/apparmor/-/wikis/Documentation
- Linux capabilities: https://man7.org/linux/man-pages/man7/capabilities.7.html

---

## 6. Containers and Kubernetes DFIR

Container evidence is split across host, runtime, image, writable layer, orchestrator, application, network, and cloud control plane.

### 6.1 Container runtime evidence

Collect:

- Runtime version/configuration, socket permissions, storage driver, and rootless/rootful mode.
- Container metadata, image digests, command/entrypoint, mounts, capabilities, seccomp/AppArmor/SELinux, namespaces, cgroups, and restart policy.
- Runtime daemon journal/logs for Docker, containerd, CRI-O, and kubelet.
- Writable-layer changes and mounted volume evidence.
- Image manifests, config, provenance/signatures, and registry audit logs.
- Network namespaces, veth pairs, bridges, NAT/firewall, DNS, and service-mesh evidence.

Docker examples:

```bash
docker version
docker info
docker ps --no-trunc --all
docker inspect <container-id>
docker image inspect <image-or-digest>
docker diff <container-id>
docker logs --timestamps <container-id>
```

Containerd/CRI examples:

```bash
ctr version 2>&1
crictl info 2>&1
crictl ps -a 2>&1
crictl inspect <container-id> 2>&1
crictl logs --timestamps <container-id> 2>&1
```

Cautions:

- `docker logs` only exposes the configured logging driver; logs may be remote or absent.
- Exporting a container filesystem does not include all mounted volumes, deleted/open files, runtime metadata, or memory.
- Overlay filesystem paths and layer IDs are implementation-specific; preserve runtime metadata before mapping layers manually.
- Stopping/removing a container can destroy volatile state and writable-layer evidence.
- Container clocks usually follow the host, while applications may format timestamps differently.

Resources:

- Docker logging: https://docs.docker.com/engine/logging/
- Docker storage drivers: https://docs.docker.com/engine/storage/drivers/
- containerd documentation: https://github.com/containerd/containerd/tree/main/docs
- CRI-O documentation: https://github.com/cri-o/cri-o/tree/main/docs

### 6.2 Kubernetes evidence

Preserve:

- Kubernetes audit logs and API server logs.
- Object YAML and managed fields for pods, deployments, DaemonSets, Jobs/CronJobs, RBAC, service accounts, secrets metadata, webhooks, and policies.
- Events, node status, kubelet logs, CRI runtime state, and static pod manifests.
- Admission controller, registry, cloud IAM, workload identity, and CI/CD records.
- NetworkPolicy/CNI, service mesh, DNS, ingress, load balancer, and flow logs.
- etcd snapshots only when necessary, authorized, and carefully protected; they contain cluster secrets/state.

```bash
kubectl get pods -A -o yaml > pods-all.yaml
kubectl get deployments,daemonsets,statefulsets,jobs,cronjobs -A -o yaml > workloads.yaml
kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o yaml > rbac.yaml
kubectl get events -A --sort-by=.metadata.creationTimestamp > events.txt
kubectl describe node <node> > node-describe.txt
```

Kubernetes resources:

- Auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- Logging architecture: https://kubernetes.io/docs/concepts/cluster-administration/logging/
- Node-pressure eviction and ephemeral evidence: https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/
- Falco Kubernetes response: https://falco.org/docs/
- Tetragon: https://tetragon.io/docs/

Do not dump Secret values by default. Gather only the minimum secret material needed, with explicit authorization and protected handling.

---

## 7. Identity, credentials, and lateral movement

Linux identity may be local, LDAP/SSSD, Kerberos, cloud IAM, SSH certificate-based, or orchestrator-managed.

### Questions to answer

1. Which identity authenticated, from where, using which mechanism?
2. Was the account expected on that host/workload and at that time?
3. Was access SSH, console, cloud session manager, sudo, `su`, container exec, Kubernetes API, web, or application-level?
4. Were authorized keys, certificates, PAM/NSS, sudoers, groups, tokens, or cloud roles changed?
5. Which credentials, sessions, keys, certificates, tokens, and hosts must be revoked or rebuilt?
6. Did lateral movement use SSH agent forwarding, shared keys, orchestration, NFS, remote management, or cloud metadata credentials?

Sensitive evidence can include:

- `/etc/shadow`, private keys, SSH agent sockets, Kerberos tickets, keyrings, browser/application tokens, cloud credentials, Kubernetes service-account tokens, and process environments.
- Memory from SSH agents, cloud agents, databases, and privileged services.
- Shell histories and configuration files containing embedded secrets.

Collect credential material only when necessary and authorized. Encrypt it, restrict access, and plan revocation/rotation before broad distribution.

Useful resources:

- OpenSSH certificates: https://man.openbsd.org/ssh-keygen#CERTIFICATES
- SSSD documentation: https://sssd.io/docs/introduction.html
- Kerberos user/admin docs: https://web.mit.edu/kerberos/krb5-latest/doc/
- Linux keyrings: https://man7.org/linux/man-pages/man7/keyrings.7.html

---

## 8. Memory forensics

Volatility 3 is the standard open-source framework: https://github.com/volatilityfoundation/volatility3 and https://volatility3.readthedocs.io/

Linux analysis requires symbols matching the captured kernel. Preserve:

- Exact kernel release/build and architecture.
- Unstripped `vmlinux` with DWARF or suitable debug symbols.
- Distribution kernel/debug packages and configuration.
- Module versions and kernel build identifiers.
- BTF data where relevant and supported by the symbol workflow.

Symbol tooling:

- dwarf2json: https://github.com/volatilityfoundation/dwarf2json
- Volatility Linux tutorial: https://volatility3.readthedocs.io/en/stable/getting-started-linux-tutorial.html

Example workflow:

```bash
# Build an Intermediate Symbol File from a matching unstripped vmlinux
./dwarf2json linux --elf /path/to/vmlinux > linux-kernel.json

# Place/compress according to Volatility symbol directory conventions, then inspect
python3 vol.py -f memory.lime banners
python3 vol.py -f memory.lime linux.boottime
python3 vol.py -f memory.lime linux.pslist
python3 vol.py -f memory.lime linux.pstree
python3 vol.py -f memory.lime linux.psaux
python3 vol.py -f memory.lime linux.lsof
python3 vol.py -f memory.lime linux.sockstat
python3 vol.py -f memory.lime linux.ip.Addr
python3 vol.py -f memory.lime linux.ip.Link
python3 vol.py -f memory.lime linux.mountinfo
python3 vol.py -f memory.lime linux.envars
python3 vol.py -f memory.lime linux.malfind
python3 vol.py -f memory.lime linux.check_modules
```

Analysis method:

1. Verify image hash, format, and acquisition metadata.
2. Establish exact kernel/build, boot time, and symbol resolution.
3. Compare process enumeration methods and inspect lineage, credentials, namespaces, and start times.
4. Correlate sockets, network namespaces, and process identity.
5. Inspect anomalous executable/private memory, mappings, deleted files, environment, and injected code.
6. Compare loaded modules and kernel structures for hidden/inconsistent objects.
7. Review open files, mount namespaces, page cache, tracing/eBPF, and capabilities as required.
8. Extract suspicious objects into a controlled environment and hash them.
9. Correlate memory with disk, logs, EDR, audit, and cloud evidence.

Cautions:

- `malfind` and cross-view anomalies are heuristics, not verdicts.
- Exact-kernel symbols are essential; partial or mismatched symbols can produce misleading output.
- KASLR, custom kernels, stripped symbols, BTF-only builds, modules, and kernel-version changes complicate analysis.
- Memory contains privileged secrets and unrelated personal data.
- Kernel rootkits and acquisition failures can distort views; compare independent evidence sources.

Additional tools:

- MemProcFS: https://github.com/ufrisk/MemProcFS
- YARA: https://virustotal.github.io/yara/
- Volatility plugin documentation: https://volatility3.readthedocs.io/en/stable/volatility3.plugins.linux.html

---

## 9. Timeline building

A defensible timeline correlates independent artifacts and preserves source semantics.

Potential sources:

- Journal, syslog, audit, authentication, sudo, and process accounting.
- Filesystem inode timestamps, journals/logs, snapshots, and deleted/open files.
- Shell history, editors, terminal multiplexers, deployment tools, and package transactions.
- Web, application, database, reverse-proxy, WAF, and CI/CD logs.
- Container runtime, Kubernetes audit/events, CNI, service mesh, and registry logs.
- EDR/eBPF, firewall, DNS, VPN, flow, load balancer, and cloud audit logs.
- Memory process/socket/mount evidence.

Tools:

- Plaso/log2timeline: https://plaso.readthedocs.io/
- Timesketch: https://timesketch.org/
- The Sleuth Kit `fls`/`mactime`: https://www.sleuthkit.org/sleuthkit/man/
- `journalctl --output=json` and `ausearch --format csv`

Timeline rules:

1. Normalize to UTC but retain original timezone, boot ID, clock source, and source format.
2. Label what each timestamp means: inode change, modification, access, birth, event generation, ingestion, boot monotonic time, or parser-derived.
3. Account for clock drift, NTP steps/slewing, VM pause/resume, delayed forwarding, buffering, and rotation.
4. Avoid inferring causation from close timestamps alone.
5. Mark confidence and alternative explanations.
6. Preserve links to source record IDs, audit serials, journal cursors, inode numbers, hashes, snapshot IDs, or query identifiers.

---

## 10. Linux malware analysis

### 10.1 Static triage

```bash
sha256sum suspicious
file suspicious
stat suspicious
readelf -h -l -S -d -n -s suspicious
objdump -x -d suspicious > suspicious.objdump.txt
strings -a -n 6 suspicious > suspicious.strings.txt
ldd suspicious                 # avoid on untrusted binaries; see warning below
getfattr -d -m- suspicious 2>/dev/null
getcap suspicious 2>/dev/null
```

> **Do not run `ldd` on an untrusted executable in an uncontrolled environment.** Historically and depending on implementation/file type, it can execute loader-related code. Prefer `readelf -d`, `objdump -p`, or analyze inside an isolated malware lab.

Examine:

- ELF architecture, type, interpreter, program/section headers, imports/exports, symbols, notes, build ID, RPATH/RUNPATH, and dependencies.
- Stripped/packed indicators, entropy, overlays/appended data, embedded archives, scripts, and interpreters.
- Strings, domains, paths, commands, mutex/lock files, service names, persistence, and configuration.
- Capabilities, setuid/setgid, ownership, ACLs, xattrs, SELinux labels, and package ownership.
- Static vs. dynamic linking, glibc/musl expectations, and architecture-specific behavior.
- Similarity and capability results without treating reputation services as proof.

Tools:

- Detect It Easy: https://github.com/horsicq/Detect-It-Easy
- FLOSS: https://github.com/mandiant/flare-floss
- capa: https://github.com/mandiant/capa
- Ghidra: https://github.com/NationalSecurityAgency/ghidra
- radare2: https://rada.re/n/
- Binary Ninja: https://binary.ninja/
- YARA: https://virustotal.github.io/yara/
- binwalk: https://github.com/ReFirmLabs/binwalk

### 10.2 Dynamic analysis

Run unknown code only in an isolated, revertible lab matching the target architecture/libc/kernel where possible. Capture:

- Process tree, threads, namespaces, cgroups, credentials, capabilities, and seccomp.
- Files, xattrs, services, timers, cron, modules, udev, PAM, and persistence.
- DNS, TCP/UDP, HTTP(S), TLS, Unix sockets, pipes, shared memory, and IPC.
- Syscalls, library calls, memory maps, injected code, ptrace, and anti-analysis behavior.
- Before/after filesystem snapshots and memory at meaningful stages.

Useful tools:

- `strace`: https://strace.io/
- `ltrace`: https://man7.org/linux/man-pages/man1/ltrace.1.html
- GDB: https://sourceware.org/gdb/documentation/
- rr debugger: https://rr-project.org/
- bpftrace: https://bpftrace.org/docs/
- Wireshark: https://www.wireshark.org/
- INetSim: https://www.inetsim.org/
- REMnux: https://remnux.org/

Do not connect a malware lab to production networks, corporate credentials, cloud metadata, shared folders, host sockets, or uncontrolled internet access.

### 10.3 Scripts, web shells, and supply-chain payloads

Linux malware is often shell, Python, Perl, PHP, JavaScript, Java, Go, or a malicious package/container rather than a traditional ELF.

Inspect:

- Shebang, encoding, obfuscation, heredocs, downloaded stages, and environment assumptions.
- Package maintainer/install scripts and repository/signing configuration.
- Python/npm/Ruby/Go/Cargo dependency lockfiles and install hooks.
- Container image layers, entrypoint, build history, provenance, and registry digest.
- Web shells, framework plugins, cron/systemd installers, and cloud startup scripts.

Preserve archives and packages in original form before extraction; extraction changes timestamps and can lose xattrs, hard links, device files, or path-traversal context.

---

## 11. Common attacker TTPs and evidence

Full matrix: https://attack.mitre.org/matrices/enterprise/linux/

| Tactic/technique | Evidence to correlate |
|---|---|
| Unix Shell (T1059.004) | Audit/EDR, shell history, sudo, journal, process accounting, CI/CD |
| Python/other interpreters | Process lineage, script path/content, environment, package logs, network |
| systemd Service (T1543.002) | Unit files/drop-ins, journal, enablement symlinks, audit/filesystem |
| Cron (T1053.003) | Cron files/spools, syslog/journal, audit, executed payload |
| SSH Authorized Keys (T1098.004) | `authorized_keys`, metadata, audit, SSH logs, key/cert inventory |
| External Remote Services: SSH (T1021.004) | SSH logs, wtmp, audit, network/VPN/bastion, user activity |
| Sudo/Setuid (T1548.003) | sudo/audit, setuid/capabilities, policy changes, process lineage |
| Dynamic Linker Hijacking (T1574) | `ld.so.preload`, RPATH/RUNPATH, libraries, env, maps, package integrity |
| Kernel Modules and Extensions (T1547.006) | modules, initramfs, load config, kernel journal, memory analysis |
| Process Injection (T1055) | ptrace/process_vm access, EDR/eBPF, memory maps, anonymous executable pages |
| File and Directory Discovery | shell/audit/EDR, process accounting, application logs |
| Ingress Tool Transfer (T1105) | curl/wget/scp/cloud tools, proxy/DNS, file metadata, shell/audit |
| Web Shell (T1505.003) | web logs, modified webroot, interpreter children, outbound connections |
| Account Creation (T1136.001) | passwd/group/shadow changes, audit, identity system, home/SSH creation |
| Indicator Removal: File Deletion (T1070.004) | audit, filesystem journal, open deleted files, snapshots, EDR |
| Clear Linux Logs (T1070.002) | journal/syslog gaps, truncation metadata, audit, remote mismatch |
| Container Administration Command (T1609.003) | Kubernetes audit, runtime/kubelet, shell/process evidence |
| Cloud Metadata Credentials | HTTP to metadata service, role use, cloud audit, process/network evidence |

ATT&CK mappings describe behavior; they do not replace a finding's evidence or confidence assessment.

---

## 12. Recommended tooling summary

| Category | Tools |
|---|---|
| Memory acquisition | AVML, LiME, approved hypervisor/cloud memory capture |
| Memory analysis | Volatility 3, MemProcFS, YARA |
| Disk imaging | Guymager, dcfldd, ddrescue, libewf |
| Triage collection | UAC, Velociraptor, GRR, osquery |
| Journal/syslog | journalctl, systemd journal-remote tools, standard text/JSON tooling |
| Audit | ausearch, aureport, auditd, go-audit alternatives where deployed |
| Filesystem | The Sleuth Kit, Autopsy, ext4magic, debugfs/xfs tools on copies |
| Timeline | Plaso, Timesketch, Sleuth Kit mactime |
| Live response | trusted coreutils/procps/iproute2, lsof, ss, bpftool, EDR/eBPF |
| Rootkit/integrity | Volatility, package/image verification, IMA, rkhunter/chkrootkit as leads |
| Malware triage | file, readelf, objdump, FLOSS, capa, YARA, Ghidra, radare2 |
| Network | Wireshark, Zeek, tcpdump, NetworkMiner, flow/DNS/proxy/VPN telemetry |
| Containers/Kubernetes | runtime/CRI tools, kubectl, Falco, Tetragon, cloud audit |

Additional resources:

- The Sleuth Kit: https://www.sleuthkit.org/
- Plaso: https://plaso.readthedocs.io/
- Timesketch: https://timesketch.org/
- Zeek: https://zeek.org/
- tcpdump: https://www.tcpdump.org/manpages/tcpdump.1.html
- NetworkMiner: https://www.netresec.com/?page=NetworkMiner
- Tracee: https://aquasecurity.github.io/tracee/latest/
- Sysdig Inspect: https://github.com/draios/sysdig-inspect

Before operational use, validate licensing, hashes/signatures, architecture, libc/kernel support, output semantics, and behavior under endpoint security controls.

---

## 13. Repeatable Linux IR checklist

1. **Authorize and classify** - establish incident owner, scope, legal/privacy requirements, severity, and evidence authority.
2. **Start the case log** - record UTC/local time, responders, host/workload, source alerts, and every action.
3. **Identify context** - distribution, kernel, init, filesystem, cloud/VM, container/namespace, role, and encryption.
4. **Choose containment timing** - weigh active harm against evidence loss; preserve EDR/network/control-plane context before isolation when safe.
5. **Capture volatile evidence** - memory, processes, namespaces, open/deleted files, sockets, routes, neighbors, conntrack, sessions, modules/eBPF, firewall, audit, and security state.
6. **Preserve logs** - binary journal, syslog, audit, authentication, sudo, SSH, application, runtime, Kubernetes, EDR, and forwarder state.
7. **Run targeted triage** - identity, shell, package, persistence, filesystem metadata, service definitions, cloud metadata, and suspicious payloads.
8. **Acquire disk/volume evidence** - when impact, uncertainty, legal need, anti-forensics, or integrity loss justifies it.
9. **Preserve external telemetry** - SIEM, IAM, bastion/VPN, DNS, proxy, flow, cloud audit, CI/CD, registry, load balancer, and orchestration.
10. **Build a timeline** - normalize time, preserve boot/audit/source identifiers, and correlate independent artifacts.
11. **Scope laterally** - pivot on identities, keys/tokens, hashes, paths, commands, units, containers/images, domains/IPs, and behavior.
12. **Contain** - isolate hosts/workloads, suspend identities, revoke keys/tokens, block infrastructure, or quarantine nodes with approvals.
13. **Eradicate** - remove persistence/payloads, close initial access, rotate exposed secrets, patch, rebuild images, and harden.
14. **Recover** - rebuild when trust cannot be restored; validate service/data integrity and monitor closely.
15. **Document findings** - distinguish facts, interpretation, assumptions, gaps, and confidence.
16. **Improve defenses** - update detections, logging, audit/eBPF coverage, playbooks, hardening, images, training, and metrics.

### Minimum host triage package

For a typical suspicious Linux server, collect at least:

- Acquisition log, distro/kernel/timezone/NTP, host/cloud IDs, mount/storage, and tool hashes.
- Memory when justified and feasible.
- Process/thread/namespace/cgroup, file descriptor, socket, route, neighbor, firewall, and conntrack snapshots.
- Service/unit/timer, cron/at, module/eBPF, audit, SELinux/AppArmor, capabilities, and package integrity state.
- Original binary journal directories plus exported JSON/text, syslog, audit, auth/sudo/SSH, and application logs.
- Identity files, sudoers, SSH configuration/authorized keys, PAM/NSS/SSSD/Kerberos context as relevant.
- Shell histories/startup files, package transactions, deployment/cloud-init/configuration-management logs.
- Filesystem metadata or targeted forensic collection, including deleted/open files and xattrs/ACLs/capabilities.
- Container/runtime/Kubernetes metadata and logs where applicable.
- Suspicious binaries/scripts/configuration in original form with SHA-256 hashes.
- EDR process tree and centralized identity/network/control-plane evidence.

---

## 14. Common analytical mistakes

- Trusting local commands after suspected root/kernel compromise without cross-view validation.
- Treating shell history as a complete or authoritative execution log.
- Assuming an absent journal/audit event proves non-execution.
- Parsing only `/var/log/auth.log` on a RHEL host or only `/var/log/secure` on Ubuntu.
- Exporting journal text but failing to preserve original binary files.
- Interpreting `ctime` as creation time.
- Mounting original ext4/XFS evidence and triggering journal/log replay.
- Running recovery tools against the source filesystem.
- Killing a suspicious process before preserving `/proc`, open deleted files, sockets, and memory.
- Disabling Secure Boot, lockdown, SELinux/AppArmor, EDR, or audit to simplify collection.
- Treating rkhunter/chkrootkit or antivirus output as proof.
- Running `ldd` or unknown binaries outside an isolated lab.
- Ignoring namespaces, containers, cloud identities, and orchestrator evidence.
- Collecting credential stores, `/etc/shadow`, etcd, or secrets by default.
- Uploading confidential samples to public scanning services without authorization.
- Searching only for IOCs and missing identities, persistence, image provenance, or behavior.
- Confusing a package-signed file or trusted path with benign behavior.
- Treating ATT&CK mapping as detection validation.

---

## 15. Further learning

- SANS FOR577 - Linux Incident Response and Threat Hunting: https://www.sans.org/cyber-security-courses/linux-threat-hunting-incident-response/
- Linux kernel documentation: https://docs.kernel.org/
- Linux man-pages project: https://man7.org/linux/man-pages/
- systemd manual: https://www.freedesktop.org/software/systemd/man/latest/
- Linux Audit documentation: https://github.com/linux-audit/audit-documentation
- UAC documentation: https://github.com/tclahr/uac/tree/main/docs
- Velociraptor Linux artifacts: https://docs.velociraptor.app/artifact_references/
- Volatility 3 Linux tutorial: https://volatility3.readthedocs.io/en/stable/getting-started-linux-tutorial.html
- Plaso documentation: https://plaso.readthedocs.io/
- Timesketch documentation: https://timesketch.org/guides/
- The Sleuth Kit documentation: https://www.sleuthkit.org/sleuthkit/docs.php
- MITRE ATT&CK Linux: https://attack.mitre.org/matrices/enterprise/linux/
- Docker security and logging: https://docs.docker.com/engine/security/ and https://docs.docker.com/engine/logging/
- Kubernetes auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- REMnux Linux malware-analysis distribution: https://remnux.org/

> Final reminder: the best artifact is the one that answers the incident question with understood provenance and limitations. Correlate host, identity, network, workload, orchestrator, and cloud-control-plane evidence; state uncertainty explicitly; and preserve enough source material for another analyst to reproduce the conclusion.