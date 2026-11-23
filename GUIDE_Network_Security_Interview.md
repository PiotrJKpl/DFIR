# Network Security — Interview Topics, Questions & Detailed Explanations

A study guide for network-focused interview questions, organized by topic. Each entry gives a likely question plus a detailed, defensible explanation you can adapt. Calibrated for someone claiming **Network Security (5)**, **Network Forensics (4)**, and **IDS (4)** — so explanations emphasize architecture, trade-offs, failure modes, and investigative depth, not just definitions.

> **How to use:** For a self-score of 5, Nicholas will probe past definitions into *design trade-offs and failure modes*. Each section includes a "Depth signal" — the kind of statement that distinguishes SME-level from textbook knowledge.

---

## 1. OSI & TCP/IP models

**Q: Walk me through the OSI model and how it maps to real troubleshooting.**

The OSI model has 7 layers; TCP/IP collapses them into 4. The value isn't memorizing the layers — it's using them as a troubleshooting methodology.

| OSI | Layer | TCP/IP | Examples | Troubleshooting question |
|---|---|---|---|---|
| 7 | Application | Application | HTTP, DNS, TLS, SSH | Is the app/protocol behaving correctly? |
| 6 | Presentation | Application | TLS encoding, serialization | Is data encrypted/encoded correctly? |
| 5 | Session | Application | Session establishment | Is the session maintained? |
| 4 | Transport | Transport | TCP, UDP | Are ports open? Reliable vs. fast? |
| 3 | Network | Internet | IP, ICMP, routing | Can packets reach the destination? |
| 2 | Data Link | Link | Ethernet, ARP, switches, MAC | Are frames delivered on the local segment? |
| 1 | Physical | Link | Cables, NICs, radio | Is there a physical link? |

**Troubleshooting method:** work bottom-up. Link light → IP config (`ipconfig`/`ip a`) → local gateway (`ping gateway`) → routing (`traceroute`) → DNS resolution (`nslookup`) → transport (`telnet host 443`) → application (curl/browser). Each layer confirms or eliminates a class of problem.

**Depth signal:** "I don't recite the layers; I use them to bisect a problem. 'It's not DNS' is a meme because people skip layers. If `ping 8.8.8.8` works but `ping google.com` fails, I've isolated it to L7 DNS in two commands — that's the model earning its keep."

---

## 2. TCP vs. UDP & the handshake

**Q: Explain the TCP three-way handshake and why it matters for security.**

```
Client                        Server
  |  ---- SYN (seq=x) ------->  |
  |  <--- SYN-ACK (seq=y, ack=x+1) -- |
  |  ---- ACK (ack=y+1) ------>  |
        Connection established
```

- **SYN** — client proposes a connection with an initial sequence number.
- **SYN-ACK** — server acknowledges and proposes its own sequence number.
- **ACK** — client confirms; connection is established.

**Security relevance:**
- **SYN flood** — attacker sends many SYNs, never completes the handshake, exhausting the server's half-open connection table. Mitigations: SYN cookies, rate limiting, backlog tuning.
- **Port scanning detection** — a SYN with no follow-up ACK (half-open scan), or a SYN to a closed port (RST returned), or to an open port (SYN-ACK) — each generates a distinct signature an IDS keys on.
- **TCP flags abuse** — XMAS scan (FIN+URG+PSH set), NULL scan (no flags). Stateful firewalls and IDS flag these because legitimate traffic never sets them.

**TCP vs. UDP:**

| | TCP | UDP |
|---|---|---|
| Connection | Connection-oriented | Connectionless |
| Reliability | Guaranteed, ordered, retransmitted | Best-effort, no guarantee |
| Overhead | Higher (handshake, ACKs) | Lower (no state) |
| Use cases | HTTP/S, SSH, SMTP | DNS, VoIP, streaming, QUIC |
| Security note | Stateful inspection easy | Harder to statefully inspect; used for DNS tunneling/amplification |

**Depth signal:** "QUIC (HTTP/3) runs over UDP but builds reliability and encryption in userspace — which matters for security because it encrypts transport metadata that middleboxes used to inspect. That's a visibility trade-off worth mentioning."

---

## 3. DNS — the highest-signal protocol

**Q: Why is DNS so valuable for both attackers and defenders?**

DNS resolves names to IPs and is almost always allowed outbound — making it a prime channel for C2, tunneling, and exfiltration, and a goldmine for detection.

**Common record types:** `A` (IPv4), `AAAA` (IPv6), `CNAME` (alias), `MX` (mail), `TXT` (text — abused for tunneling/SPF/verification), `NS` (nameserver), `PTR` (reverse lookup), `SOA` (zone authority).

**Attacker uses & detection:**

| Technique | How it works | Detection signal |
|---|---|---|
| **DNS tunneling** | Encode data in subdomain labels/queries; attacker NS decodes | Long/entropy-high subdomains, high query volume to one domain, unusual record types (TXT), rare domains |
| **DGA (Domain Generation Algorithm)** | Malware generates many domains; attacker registers a few | High NXDOMAIN rate, lexical entropy, many unique domains per host |
| **Fast flux** | Rapidly rotating IPs for one domain | Low TTL + many A records changing rapidly |
| **DNS exfiltration** | Data chunked into queries | Large/encoded TXT or subdomain queries, slow-drip volume |
| **C2 via DNS** | Commands in TXT responses | Periodic TXT lookups to a rare domain |

**Defensive controls:** DNS logging, sinkholing known-bad domains, DNS filtering (Protective DNS), monitoring for TXT/NULL record abuse, entropy analysis on labels, and forcing internal resolvers (block outbound 53 to arbitrary servers).

**Depth signal:** "DNS is my highest-value hunting protocol because it's rarely blocked. A DGA stands out by NXDOMAIN rate and label entropy; tunneling stands out by query length, record type, and volume to a single rare domain. And I always check whether a host is bypassing the internal resolver — outbound 53/853 to a non-standard server is itself an alert, especially with DoH to an unknown provider bypassing DNS controls entirely."

---

## 4. HTTP/HTTPS & web proxies

**Q: How does TLS change what a defender can see in web traffic?**

TLS encrypts the HTTP payload, so a passive observer sees **metadata, not content**:

| Visible (plaintext/metadata) | Encrypted (payload) |
|---|---|
| Destination IP | URL path, query params |
| SNI (hostname) — unless ECH | HTTP method, headers, body |
| TLS handshake, certificate | Response content |
| JA3/JA3S fingerprints | Application data |
| Timing, byte counts, packet sizes | — |

**SNI (Server Name Indication)** reveals the hostname in the TLS ClientHello — valuable for detecting known-bad domains without decrypting. **Encrypted Client Hello (ECH)** hides even that, pushing defenders toward DNS, destination IP reputation, and TLS fingerprinting.

**Forward proxy / SWG role:** a Secure Web Gateway terminates TLS (with enterprise trust), inspects content, applies URL category/reputation policy, then re-encrypts to the destination. This restores visibility at the cost of managing the inspection CA, privacy, and certificate-pinning exceptions.

**HTTP/S headers — the defender's metadata when you *can* see them.** When traffic is inspected (at the SWG, a WAF, or a reverse proxy), HTTP headers become a rich detection and hardening surface. They're plaintext only *inside* the TLS envelope, so you see them at a terminating proxy but not in passive PCAP of encrypted traffic.

*Security-relevant request headers:*

| Header | Security relevance |
|---|---|
| `Host` | Must match SNI; mismatch can indicate evasion or fronting |
| `User-Agent` | Client fingerprint; malware often uses rare/outdated/empty UAs |
| `Referer` | Click-path context in phishing/drive-by investigations |
| `Authorization` / `Cookie` | Session tokens/creds — never log these in cleartext to insecure stores |
| `X-Forwarded-For` | Original client IP behind a proxy — but trivially spoofable, so don't trust it for auth decisions |
| `Content-Type` | Mismatch with actual payload can signal abuse |

*Security response headers (hardening):*

| Header | Protection |
|---|---|
| `Strict-Transport-Security` (HSTS) | Forces HTTPS, blocks protocol downgrade |
| `Content-Security-Policy` (CSP) | Mitigates XSS by restricting script/content sources |
| `X-Frame-Options` / CSP `frame-ancestors` | Blocks clickjacking |
| `X-Content-Type-Options: nosniff` | Prevents MIME-type sniffing |
| `Referrer-Policy` | Controls how much referrer leaks cross-origin |
| `Set-Cookie: HttpOnly; Secure; SameSite` | Cookie theft/CSRF hardening |

*Detection signals in headers:* an empty or rare `User-Agent`, a `Host` header that doesn't match the TLS SNI (possible **domain fronting**), an `X-Forwarded-For` that contradicts the connection source, or an unexpected `Authorization` header. Malware frequently betrays itself with a hard-coded or anomalous User-Agent even when the destination looks benign.

**Depth signal:** "I treat HTTP headers as a detection surface when I have them — an anomalous User-Agent or a Host/SNI mismatch (domain fronting) is high-signal — but I remember they only exist in plaintext at a TLS-terminating point like the SWG. For hardening, HSTS, CSP, and the secure-cookie trio are the highest-value response headers. And I never trust `X-Forwarded-For` for authorization because the client can set it to anything."

**Depth signal:** "With HTTPS I lose the payload but keep JA3, SNI, cert metadata, timing, and destination reputation. That's usually enough to characterize C2. If the org runs TLS inspection at the SWG, I get full content for allowed traffic but must handle certificate pinning and privacy carve-outs deliberately — a blind bypass is both a security gap and a compliance risk."

### 4.1 HTTP protocol mechanics

**Q: Walk me through what actually happens in an HTTP request/response.**

HTTP is a stateless, text-based, request/response application protocol. A client opens a TCP connection (after TLS, for HTTPS), sends a request, the server responds, and (in HTTP/1.1) the connection may be kept alive for reuse.

**Request structure:**
```
GET /login?user=bob HTTP/1.1        ← request line: METHOD  PATH  VERSION
Host: example.com                   ← headers (key: value)
User-Agent: Mozilla/5.0 ...
Cookie: session=abc123
                                    ← blank line ends headers
                                    ← body (empty for GET; present for POST)
```

**Response structure:**
```
HTTP/1.1 200 OK                     ← status line: VERSION  CODE  REASON
Content-Type: text/html             ← headers
Set-Cookie: session=xyz; HttpOnly; Secure
                                    ← blank line
<html>...</html>                    ← body
```

**Core methods (verbs):**

| Method | Purpose | Security note |
|---|---|---|
| `GET` | Retrieve a resource | Params in URL → leak into logs/history; never for sensitive state changes |
| `POST` | Submit data (body) | Preferred for credentials/forms |
| `PUT`/`DELETE` | Replace/remove a resource | Should be restricted; dangerous if exposed unauthenticated |
| `HEAD` | Headers only (no body) | Used in recon to fingerprint servers quietly |
| `OPTIONS` | Allowed methods/CORS preflight | Can reveal enabled methods |
| `TRACE` | Echo the request back | Disable — used in Cross-Site Tracing (XST) |
| `CONNECT` | Establish a tunnel (proxies) | Abused for tunneling through proxies |

**Status codes (know the classes):**
- `1xx` informational · `2xx` success (`200 OK`) · `3xx` redirect (`301`, `302`, `304`) · `4xx` client error (`401` unauthenticated, `403` forbidden, `404`, `429` rate-limited) · `5xx` server error (`500`, `502`, `503`).

**Key properties that matter for security:**
- **Stateless** — each request is independent; sessions are built on top via cookies/tokens. That's why session management is its own attack surface.
- **Plaintext (HTTP)** — fully readable on the wire: credentials, cookies, content. Hence HTTPS.
- **Connection reuse / keep-alive** — one TCP/TLS connection serves many requests (efficiency), which affects how you count "sessions" in forensics.

### 4.2 HTTPS = HTTP over TLS

HTTPS is just HTTP carried inside a TLS-encrypted channel. TLS provides the three guarantees:

| Guarantee | Mechanism |
|---|---|
| **Confidentiality** | Symmetric encryption (AES/ChaCha20) of the payload |
| **Integrity** | AEAD ciphers detect tampering |
| **Authentication** | Server (and optionally client) certificate, validated against a CA chain |

So an observer sees the **TCP/TLS metadata** (IPs, SNI, cert, JA3, timing) but **not** the HTTP method, path, headers, or body — which is exactly why §4's visibility table matters for detection.

### 4.3 HTTP/1.1 vs. HTTP/2 vs. HTTP/3

| | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---|---|---|---|
| Transport | TCP | TCP | **QUIC over UDP** |
| Format | Text | Binary | Binary |
| Multiplexing | No (one request/connection at a time) | Yes (streams) | Yes (streams, no head-of-line blocking) |
| Header compression | No | HPACK | QPACK |
| Encryption | Optional (TLS) | Optional (de facto required) | **Mandatory** (TLS 1.3 inside QUIC) |

**Security relevance of HTTP/3:** QUIC moves reliability and encryption into userspace over UDP and **encrypts transport metadata** that middleboxes used to inspect. For a defender, that reduces passive visibility and can break proxy assumptions — you lean harder on DNS, destination reputation, and endpoint telemetry.

### 4.4 HTTP attack surface (high level)

Because you scored WebAppSec a 2, you want solid recognition-level answers here:

| Attack | Mechanism | Network/host signal |
|---|---|---|
| **Credential sniffing / MITM** | Plaintext HTTP read on the wire | Detectable only if you see the downgrade or rogue proxy |
| **Session hijacking** | Stolen session cookie reused | Impossible-travel, UA/IP change mid-session |
| **SQLi / injection** | Malicious input in params/body | WAF alerts, anomalous query strings, error patterns |
| **XSS / CSRF** | Injected script / forged cross-site request | CSP/report headers, referrer anomalies |
| **Web shell / C2 over HTTP** | POSTs to an uploaded shell; beacons | Periodic small POSTs to a rare path, odd UA |

**Depth signal:** "I know the HTTP request/response anatomy cold — methods, status classes, and that it's stateless with sessions bolted on via cookies. I can investigate web attacks from the telemetry side — WAF logs, anomalous query strings, UA anomalies, session-reuse signals — but I'd partner with an app-security specialist for deep exploitation or secure-code review, which is why I scored WebAppSec a 2 rather than higher."

---

## 5. TLS handshake & certificate validation

**Q: Walk me through the TLS handshake and where certificate validation fits.**

```
Client                               Server
  | --- ClientHello (SNI, cipher suites, JA3) -->
  | <-- ServerHello (chosen cipher, cert, JA3S) --
  |        [Server sends certificate chain]
  | --- key exchange / client auth (optional) -->
  | <-- Finished ---
        Encrypted application data flows
```

**Certificate validation steps the client performs:**
1. **Chain of trust** — leaf cert chains to a trusted root CA via intermediates.
2. **Hostname match** — cert CN/SAN matches the requested hostname.
3. **Validity period** — not expired, not not-yet-valid.
4. **Revocation** — not revoked (CRL/OCSP; often soft-fail).
5. **Signature integrity** — cert signature verifies with the CA's public key.

**Security signals in TLS:**
- **Self-signed / mismatched certs** on unexpected services → possible MITM or rogue service.
- **JA3/JA3S mismatch** — client fingerprint doesn't match the claimed app (e.g., a browser SNI but a non-browser JA3) → malware using its own TLS stack.
- **Rare/recent certs** from free CAs on suspicious domains.

**Depth signal:** "Certificate validation failures are underrated signals. A host suddenly hitting self-signed certs, or a JA3 that doesn't match the SNI's expected client, often indicates malware with its own TLS stack rather than a browser. I treat JA3 as a lead to correlate, not a verdict — fingerprints collide and legitimate apps vary."

---

## 6. Firewall & IDS/IPS

**Q: What's the difference between a stateful firewall, an IDS, and an IPS?**

| | Firewall (stateful) | IDS | IPS |
|---|---|---|---|
| Position | Inline | Passive (span/tap) | Inline |
| Action | Allow/deny by rule | Detect + alert only | Detect + block inline |
| Basis | State, ports, IPs, L7 rules | Signatures + anomaly | Signatures + anomaly |
| Failure risk | Blocks if it fails | None (passive) | Can block legit if it fails |
| Latency | Low | None | Adds latency |

- **Stateful firewall** tracks connection state (the TCP handshake) and allows return traffic automatically; **stateless** filters each packet independently.
- **IDS (e.g., Snort/Suricata)** monitors a copy of traffic and alerts — no blocking, so no inline risk but no prevention.
- **IPS** sits inline and drops malicious traffic — prevents attacks but adds a failure/latency point.

**IDS detection methods:**
- **Signature-based** — known patterns (Snort/Suricata rules). Precise for known attacks, blind to novel ones.
- **Anomaly-based** — baselines normal and flags deviations. Catches novel attacks but noisier.
- **Stateful protocol analysis** — flags protocol violations regardless of payload signature.

**Depth signal:** "An IDS is passive — it can't block, only alert, which makes it safe to deploy broadly. An IPS can prevent but introduces an inline failure point, so I'm conservative about what I let it auto-block. For tuning, I tighten stable protocol fields and flow direction before environment-specific exclusions, and I measure unique-entity volume, not just raw alert count, to judge noise."

---

## 7. Network forensics: NetFlow vs. PCAP

**Q: When do you use NetFlow versus full packet capture?**

| | NetFlow | Full PCAP |
|---|---|---|
| Captures | Metadata per flow | Every packet, full content |
| Content | No payloads | Full payloads |
| Volume | Small (summaries) | Huge (everything) |
| Retention | Long (months) | Short (hours/days) |
| Cost | Low | High (storage/processing) |
| Best for | Scoping, patterns, historical | Deep session analysis, payload extraction |

**NetFlow answers:** who talked to whom, when, how often, how long, how many bytes, which ports/protocols. Ideal for scoping ("did any other host talk to this C2 IP in the last 90 days?") and pattern detection (beaconing periodicity, byte ratios).

**PCAP answers:** exactly what was in the packets — decode the TLS handshake, extract a file, read the HTTP request. Ideal for validating a specific session and pulling artifacts/IOCs.

**Workflow:** flow to find the needle's neighborhood (time window + peers), PCAP to examine the needle, endpoint/DNS/TLS telemetry to recover what encryption hid.

**Beaconing detection in flow:** look for periodicity (regular intervals with jitter), consistent byte counts, and long-lived or frequent short connections to a rare destination. Beacon analysis tools (e.g., RITA) automate this over flow/connection logs.

**Depth signal:** "Flow is my scoping tool — cheap, long-retention, perfect for 'who else beaconing to this ASN.' PCAP is my confirmation tool — expensive, short-retention, but gives me the actual session. In encrypted environments I've learned to lean on flow plus JA3/JA3S and DNS, because the payload often isn't there to be read anyway."

---

## 8. C2 & beaconing analysis

**Q: How do you identify command-and-control traffic?**

C2 is the attacker's channel to control compromised hosts. Detection combines network and endpoint signals.

**Network indicators:**
- **Periodicity** — connections at regular intervals (with jitter to evade naive detection). Look at inter-arrival time distribution.
- **Beacon size consistency** — similar small byte counts each interval.
- **Rare destination** — low prevalence domain/IP across the fleet, recent registration, unusual ASN/geography.
- **TLS anomalies** — JA3 mismatch, self-signed certs, free-CA certs on new domains.
- **DNS-based** — DGA, tunneling, periodic TXT lookups (§3).
- **Protocol misuse** — HTTP on non-standard ports, or non-HTTP on port 80/443.

**Endpoint correlation (critical):** a suspicious destination is only confirmed when you identify **the owning process** — which binary, its parent, signer, and command line. A signed legit app beaconing is very different from an unsigned binary in `%TEMP%`.

**Malleable C2:** frameworks (Cobalt Strike, NightHawk) let attackers shape traffic to blend with legit (e.g., mimic normal web browsing). Defeated by behavioral analysis over time, not single-connection signatures.

**Depth signal:** "I never call C2 on the destination alone. The confirmation is correlating the periodic, machine-driven network pattern with the host process that owns the socket. In one case the implant ran inside a signed Electron app and loaded C2 via steganography — the network beacon plus the unusual process lineage together made the call, not either alone."

---

## 9. Exfiltration detection

**Q: How do you detect data exfiltration over the network?**

| Channel | Technique | Detection |
|---|---|---|
| **HTTPS to cloud storage** | Upload to attacker-controlled Dropbox/S3/mega | Volume anomaly to rare destination, off-hours, unusual user-agent |
| **DNS** | Chunked into queries | Large/encoded subdomains, TXT abuse, high volume to one domain |
| **ICMP** | Data in echo payloads | Large/unusual ICMP payload sizes |
| **Email** | Attachments/webhooks | Volume/recipient anomalies |
| **Steganography** | Data in images/media | Hard — look at destination + volume, not content |

**Volume + destination + timing** is the core triad: a host suddenly sending far more data than baseline, to a destination it never touches, at unusual hours, is the classic exfil signature. DLP at the proxy catches known-sensitive patterns; flow analysis catches the volume anomaly even when encrypted.

**Depth signal:** "Encrypted exfil still leaks through metadata. I don't need to read the payload if a workstation that normally sends megabytes suddenly pushes gigabytes to a rare cloud domain at 3 AM. Baseline deviation in volume + destination rarity + timing is often enough to warrant containment while I confirm."

---

## 10. Network segmentation & Zero Trust

**Q: How do you design segmentation to limit lateral movement?**

Segmentation divides the network so a compromise in one zone can't freely spread.

| Approach | Mechanism | Trade-off |
|---|---|---|
| **VLANs/subnets + firewall rules** | L2/L3 separation, ACLs between zones | Simple, but coarse; east-west within a zone is open |
| **Micro-segmentation** | Per-workload/host policies (host firewalls, SDN) | Fine-grained, but operationally complex |
| **Zero Trust / ZTNA** | No implicit trust by network location; every request authenticated/authorized | Strongest, but requires identity-driven redesign |

**Principles:**
- **Default-deny east-west** — internal hosts shouldn't freely talk to each other; allow only required flows.
- **Separate crown jewels** — isolate DCs, databases, backups, management plane.
- **Ingress/egress filtering** — block spoofed source IPs (BCP 38), restrict outbound to needed destinations.
- **DMZ** — public-facing services in a buffer zone, isolated from internal.

**Zero Trust** shifts the perimeter from network location to identity + device posture: "never trust, always verify." A user on the corporate LAN gets no more implicit trust than one on the internet; access is per-request, authenticated, authorized, and encrypted.

**Depth signal:** "Segmentation is about blast radius, not prevention. I assume breach and ask: if this workstation is compromised, what can it reach? Default-deny east-west is the highest-value control for stopping lateral movement. Zero Trust takes it further by removing network-location trust entirely, but it's a multi-year identity-driven program, not a product you buy."

---

## 11. Proxy, SWG & egress control

**Q: How does a Secure Web Gateway fit into the security architecture?**

An SWG sits between users and the internet as an explicit/transparent proxy, providing:

- **URL filtering** — category + reputation-based allow/block.
- **TLS inspection** — decrypt, inspect, re-encrypt (with enterprise trust).
- **Malware scanning** — AV/sandbox on downloads.
- **DLP** — detect sensitive data leaving.
- **IOC blocking** — threat-intel-driven domain/IP blocklists.

**Egress control** complements this at the firewall: restrict which destinations/ports hosts can reach outbound, forcing traffic through inspection points. Without egress control, malware simply bypasses the proxy.

**Depth signal (ties to your SWG→Palo Alto migration):** "The real work in an SWG isn't the UI — it's preserving control intent across platforms. In a Skyhigh→Panorama migration I had to map TLS inspection policy, URL categories, CONNECT-port restrictions, and ~10,000 dynamic IOC domains, and account for semantic differences — e.g., enforcing domain-list EDLs through DNS security rather than as destination IP objects. Feed churn means you re-export lists at cut-over, not weeks before."

---

## 12. Common network protocols & their risks

**Q: Which protocols do attackers abuse most, and how?**

| Protocol | Port | Abuse | Mitigation |
|---|---|---|---|
| **DNS** | 53 | Tunneling, DGA, exfil | Logging, sinkhole, force internal resolver |
| **HTTP/S** | 80/443 | C2, exfil, drive-by | Proxy/SWG, JA3, destination reputation |
| **SMB** | 445 | Lateral movement, worming (EternalBlue) | Disable SMBv1, segment, sign |
| **RDP** | 3389 | Brute force, lateral movement | MFA/NLA, gateway, restrict exposure |
| **SSH** | 22 | Brute force, tunneling, persistence | Key auth, disable root, restrict |
| **Kerberos** | 88 | Pass-the-ticket, Kerberoasting | Strong SPN passwords, monitor |
| **LDAP/S** | 389/636 | AD enumeration, relay | LDAPS, signing, channel binding |
| **SNMP** | 161 | Enumeration, weak community strings | v3, strong strings, restrict |
| **NTP** | 123 | Amplification DDoS | Restrict, rate-limit |

**Depth signal:** "The lateral-movement trio on Windows is SMB, RDP, and WinRM — I hunt all three. SMB 445 is wormable (EternalBlue) and used for admin-share lateral movement; RDP 3389 is the brute-force and hands-on-keyboard vector. I correlate the network connection with the destination's authentication logs to confirm the logon type."

---

## 13. VPN, NAT & remote access

**Q: How do VPNs and NAT complicate network forensics?**

- **NAT (Network Address Translation)** maps many internal IPs to one/few public IPs. Forensically, a public IP + port + timestamp must be mapped back to the internal host via NAT/connection logs — without them, attribution to a specific internal host is impossible.
- **VPN** encrypts traffic between the client and concentrator and assigns a virtual IP. The VPN logs are the authoritative record of who connected, when, from where, and what internal IP they got.

**Forensic implication:** to attribute activity, correlate the external observation (destination IP + port + time) with NAT/PAT logs and VPN/concentrator logs. Time synchronization across these systems is essential or the correlation breaks.

**Depth signal:** "NAT and VPN are attribution chokepoints. An external IP means nothing without the NAT translation table and VPN session log at that exact timestamp — which is why time sync (NTP) across network devices is a forensic prerequisite, not just good hygiene."

---

## 14. Email & web attack delivery

**Q: How do most network-delivered intrusions start?**

The dominant initial-access vectors are email and web:

- **Phishing email** — malicious link or attachment. Network artifacts: the clicked URL (proxy/DNS), the download (MOTW/quarantine), the C2 that follows.
- **Drive-by / malvertising** — compromised or malicious sites delivering exploits or lures.
- **Malicious attachment** — doc/ISO/LNK delivering a payload, which then beacons out.

**Investigation path:** email gateway logs (who got it) → proxy/DNS (who clicked) → endpoint (what executed) → network (where it beaconed). Each hop is a distinct telemetry source.

**Depth signal:** "Email-delivered intrusions are a network story as much as an endpoint one. The proxy shows me the click, DNS shows the resolution, and the subsequent beacon confirms execution — I can scope 'who else clicked this URL' purely from proxy logs before touching a single endpoint."

### 14.1 How email actually works

Email is a **store-and-forward** system built on three protocols. Understanding the relay chain is what makes header analysis possible.

| Protocol | Role | Port(s) |
|---|---|---|
| **SMTP** | *Sending* — pushes mail from client → server and **server → server** | 25 (relay), 587 (submission), 465 (implicit TLS) |
| **IMAP** | *Reading* — mail stays on the server, synced to clients | 143 / 993 (TLS) |
| **POP3** | *Reading* — downloads mail to the client, usually deletes from server | 110 / 995 (TLS) |

**The flow of a message:**
```
Sender MUA (mail client)
  → Sender's SMTP server (submission, 587)
  → recipient's MX server (SMTP relay, 25)   ← lookup via DNS MX record
  → Recipient's mailbox (stored)
  → Recipient reads via IMAP/POP3
```

Each server that handles the message prepends a **`Received:` header** on top. Reading the headers **bottom-to-top** reconstructs the relay path from origin to destination — this is the core of email forensics.

**Key headers for analysis:**
- `Received:` — the relay chain (originating IP, each hop, timestamps). The **topmost** `Received` is the last hop; the **bottom-most** (closest to the body) is nearest the true origin.
- `Return-Path` — the bounce/envelope-from address (where the *envelope* said it came from).
- `From:` — the *display* sender, trivially spoofed.
- `Message-ID` — unique message identifier; ties a message across logs.
- `Received-SPF`, `Authentication-Results`, `DKIM-Signature`, `ARC-*` — authentication verdicts.
- `X-Originating-IP` / `X-*` — non-standard headers some providers add (may reveal the true client IP).

### 14.2 Email authentication — SPF, DKIM, DMARC

These three DNS-based controls exist because SMTP has **no built-in sender authentication**. They defend against spoofing.

| Control | What it does | How it works | Weakness |
|---|---|---|---|
| **SPF** | Says *which IPs/hosts* may send for a domain | DNS TXT record lists authorized senders; receiver checks the connecting IP against it | Only checks the *envelope* `Return-Path`, not the visible `From:`; breaks on forwarding |
| **DKIM** | Cryptographically *signs* the message | Sender signs headers/body with a private key; receiver verifies via public key in DNS | Validates integrity/that a domain signed it — but doesn't by itself tie to the visible `From:` |
| **DMARC** | *Aligns* SPF/DKIM with the visible `From:` and sets a policy | DNS TXT record with `p=none/quarantine/reject` + reporting (`rua`) | Only as strong as the policy; `p=none` monitors but doesn't block |

**DMARC is the enforcement layer** — it requires SPF *or* DKIM to pass **and** align with the `From:` domain, then tells receivers what to do with failures. `p=reject` is the goal; many orgs stall at `p=none` (monitor-only), which stops nothing.

### 14.3 Email attacks

| Attack | How it works | Key indicators |
|---|---|---|
| **Spoofing** | Forged `From:` (display name or domain) | SPF/DKIM/DMARC failure; `From:` domain ≠ `Return-Path` |
| **Phishing** | Deceptive lure to steal creds or deliver malware | Lookalike domains, urgency, mismatched links, credential-harvest pages |
| **Spear phishing / whaling** | Targeted at an individual/exec | Recon detail, personalized context |
| **BEC** | Impersonated exec/vendor requests payment/change | Often *no malware* — pure social engineering; reply-to manipulation, payment-change lures |
| **Malicious attachment** | Doc/ISO/LNK/HTML delivering a payload | Sandboxed detonation result, MOTW, macro/auto-run behavior |
| **Malicious link** | URL to exploit or phish | Proxy/DNS click telemetry, redirect chains |
| **Lookalike / typosquat domains** | `examp1e.com`, `example.co`, IDN homoglyphs | Newly registered domain, visual similarity |
| **Display-name spoofing** | `From: CEO Name <attacker@gmail.com>` | Display name matches a real person but the address is external |
| **Thread hijacking** | Attacker replies into a real compromised thread | Real prior context; sudden bank-detail/attachment change |

**BEC deserves emphasis:** it's frequently the highest-dollar-impact email attack and often carries **no payload at all** — detection leans on anomaly signals (reply-to mismatch, new domain, payment-change language, unusual timing) rather than malware artifacts.

### 14.4 Email security measures

**Inbound (gateway/stack):**
- **Secure Email Gateway (SEG)** / cloud email security — spam + malware filtering, URL rewriting + time-of-click protection, attachment sandboxing.
- **SPF/DKIM/DMARC** enforcement on inbound.
- **Attachment detonation** in a sandbox before delivery.
- **Impersonation protection** — display-name and lookalike-domain detection, exec protection.

**Outbound / domain protection:**
- Publish **SPF, DKIM, DMARC (`p=reject`)** for your own domains so others can reject spoofing of *you*.
- **DMARC reporting (`rua`)** to see who's sending as your domain.

**User & process:**
- **Report-phishing** button + a triage workflow.
- **Out-of-band verification** for payment/BEC-style requests (call a known number, never reply to the email).
- Phishing-resistant **MFA** so stolen creds are less useful.

### 14.5 Investigating a suspicious email — workflow

1. **Header analysis** — reconstruct the `Received:` chain (bottom-up) to find the true origin IP; read `Authentication-Results` for SPF/DKIM/DMARC verdicts; compare `From:` vs. `Return-Path` vs. reply-to.
2. **Extract IOCs** — sender, origin IP, URLs, attachment hashes, `Message-ID`.
3. **Detonate safely** — sandbox the attachment/URL (never on a production host).
4. **Scope** — email gateway logs: **who else received** the same sender/subject/URL/hash. Proxy/DNS: **who clicked**.
5. **Assess impact** — if a credential-harvest link was clicked, check for logon success + reset creds; if a payload executed, move to endpoint IR.
6. **Remediate** — purge the message from all mailboxes, block sender/domain/URL/hash, and update detections.

**Depth signal:** "Email is store-and-forward over SMTP with no native authentication, which is exactly why SPF/DKIM/DMARC exist — and why I read the `Received:` chain bottom-up to find the true origin. The important nuance is that these controls authenticate the *envelope*, not the display name, so display-name spoofing and reply-to manipulation slip through — and BEC often has no payload at all, so I detect it on anomalies like reply-to mismatch and payment-change language rather than malware artifacts. For scoping, the gateway tells me who received it and the proxy tells me who clicked, before I touch an endpoint."

---

## 15. DDoS & availability attacks

**Q: How do you distinguish and mitigate DDoS types?**

| Type | Layer | Example | Mitigation |
|---|---|---|---|
| **Volumetric** | L3/L4 | UDP/amplification floods (DNS, NTP, memcached) | Upstream scrubbing, anycast, rate-limit |
| **Protocol** | L3/L4 | SYN flood, fragmented packet attacks | SYN cookies, stateful filtering |
| **Application** | L7 | HTTP floods, Slowloris | WAF, rate-limit, challenge (CAPTCHA/JS) |

**Amplification** abuses UDP services that reply larger than the request (DNS, NTP, memcached) with a spoofed victim source — the victim gets flooded by the replies. Reflection + amplification multiplies attacker bandwidth.

**Depth signal:** "The key split is volumetric vs. application. Volumetric floods must be absorbed upstream — your firewall can't help if the pipe is full. L7 attacks need a WAF and application-aware rate-limiting. And amplification is why we restrict open recursive resolvers and rate-limit UDP services at the edge."

---

## 16. Wireless security

**Q: What are the core wireless security concerns?**

- **WPA2 vs. WPA3** — WPA3 adds SAE (Simultaneous Authentication of Equals) replacing the PSK handshake, protecting against offline dictionary attacks and adding forward secrecy.
- **Rogue APs / evil twins** — attacker AP mimicking a legitimate SSID to harvest credentials or MITM.
- **Deauth attacks** — forged deauthentication frames to force reconnection and capture handshakes.
- **Enterprise auth (802.1X/EAP)** — per-user auth via RADIUS instead of a shared PSK, so individual creds can be revoked.

**Depth signal:** "WPA2-PSK's four-way handshake can be captured and cracked offline; WPA3's SAE closes that. For corporate, 802.1X with EAP-TLS is the answer — per-device certificates, no shared password, and revocable creds. The rogue-AP / evil-twin risk is why certificate validation on the supplicant matters."

---

## 17. Nmap & network reconnaissance (defender's view)

**Q: How do attackers map a network, and how do you detect it?**

Attackers use scanning to enumerate hosts, ports, and services before moving.

| Scan type | Technique | Detection |
|---|---|---|
| **SYN (half-open)** | SYN, no completion | Many SYNs to many ports, no handshake |
| **Connect** | Full TCP handshake | Completed connections to many ports |
| **UDP** | UDP probe, infer from ICMP unreachable | UDP scans are slow/noisy |
| **NULL/FIN/XMAS** | Abnormal flags | RFC violation — easy IDS signature |
| **Version/OS** | Service banners, TCP fingerprint | Follows initial scan |

**Internal recon** post-compromise is often quieter: AD enumeration (LDAP), SMB share discovery, `net`/`nltest`/`arp` on the host rather than raw scanning. Detect via host telemetry + authentication logs, not just network IDS.

**Depth signal:** "External port scans are noisy and mostly filtered at the perimeter. The higher-signal hunt is *internal* recon — a host suddenly touching many SMB shares or doing broad LDAP queries it never did before. That behavior stands out in host and authentication telemetry better than in raw network scans."

---

## 18. High-yield rapid-fire Q&A

**Q: What's the difference between a hub, switch, and router?**
Hub repeats to all ports (L1, shared, insecure — enables sniffing). Switch forwards by MAC to the right port (L2). Router forwards between networks by IP (L3).

**Q: What is ARP and ARP poisoning?**
ARP maps IP→MAC on a local segment. ARP poisoning sends forged replies to associate the attacker's MAC with the gateway's IP, enabling MITM. Detect via ARP watch/dynamic ARP inspection.

**Q: Subnetting — what does /24 mean?**
/24 = 24 network bits, 8 host bits = 254 usable hosts (e.g., 192.168.1.0/24). Smaller subnets = better segmentation.

**Q: What's the difference between symmetric and asymmetric encryption in transit?**
Symmetric (AES) is fast, used for bulk data. Asymmetric (RSA/EC) is slow, used for key exchange and signatures. TLS uses asymmetric to establish a shared symmetric session key (hybrid).

**Q: How does traceroute work?**
Sends packets with incrementing TTL; each router that decrements TTL to 0 returns an ICMP "time exceeded," revealing the path hop-by-hop.

**Q: What's a VLAN and why use it?**
Logical L2 segmentation on shared physical switches (802.1Q tags). Separates broadcast domains and enables policy between segments.

**Q: What's a HIDS vs. a NIDS?**
Host-based IDS monitors a single host's activity/logs. Network IDS monitors traffic on the wire. They're complementary — NIDS sees network behavior, HIDS sees host execution.

---

## 19. How to signal "5" (SME) in the room

A self-score of 5 means "I've trained others and set direction." Beyond correct answers, demonstrate:

1. **Trade-off reasoning** — "TLS inspection restores visibility but costs privacy, key-management, and pinning compatibility; I'd scope bypasses deliberately."
2. **Failure modes** — "An IPS can block legit traffic if it fails closed; an IDS is passive so safe but only alerts."
3. **Tool-agnostic principles** — "Whether it's Suricata or Zeek, the discipline is the same: tighten stable protocol fields before environment exclusions, and measure unique-entity volume."
4. **Investigative synthesis** — "I confirm C2 by correlating the periodic network pattern with the host process that owns the socket — neither alone is a verdict."
5. **Ownership/teaching** — have a real story of setting a network standard, being the escalation point, or training analysts on traffic analysis.

---

## Related references

- MITRE ATT&CK Network / C2 techniques — https://attack.mitre.org/
- Zeek (network security monitoring) — https://zeek.org/
- Suricata (IDS/IPS) — https://suricata.io/
- Wireshark — https://www.wireshark.org/
- RITA (beacon detection) — https://github.com/activecm/rita
- SANS Network Forensics / SEC503 — https://www.sans.org/cyber-security-courses/network-forensics/
- Companion: `GUIDE_Windows_DFIR.md` §5.9 (network evidence), interview prep §5 (network security)
