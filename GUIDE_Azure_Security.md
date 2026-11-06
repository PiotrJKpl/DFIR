# Azure — Core Concepts & Security Features

A practical, resource-linked guide to Microsoft Azure fundamentals and its security stack — written for a security engineer with a cloud background (Cloud Security = 3, GCP SCC experience). Includes cross-cloud translations so you can map what you already know, plus a blue-team angle on detection and response.

> **Scope:** Azure core architecture and identity, then the security services a threat-response engineer is most likely to operate or investigate — Entra ID, RBAC, network security, and the Defender/Sentinel detection stack.

---

## 0. Authoritative starting points

| Resource | Why it matters | Link |
|---|---|---|
| Azure fundamentals (AZ-900) learning path | Structured intro to core concepts | https://learn.microsoft.com/training/paths/microsoft-azure-fundamentals-describe-cloud-concepts/ |
| Azure security documentation | Hub for all security services | https://learn.microsoft.com/azure/security/ |
| Microsoft Entra documentation | Identity (the new perimeter) | https://learn.microsoft.com/entra/ |
| Microsoft Cloud Security Benchmark (MCSB) | Azure's control baseline (CIS-style) | https://learn.microsoft.com/security/benchmark/azure/ |
| Microsoft Sentinel documentation | SIEM/SOAR | https://learn.microsoft.com/azure/sentinel/ |
| MITRE ATT&CK (IaaS / SaaS / Azure AD) | Cloud TTP mapping | https://attack.mitre.org/matrices/enterprise/cloud/ |

---

## 1. Cloud fundamentals (shared-responsibility first)

**Service models** — and who secures what:

| Model | You manage | Microsoft manages | Security implication |
|---|---|---|---|
| **IaaS** (VMs) | OS, middleware, runtime, data, apps | Virtualization, hardware, network fabric | Largest your-responsibility surface |
| **PaaS** (App Service, SQL) | Apps + data, some config | OS, runtime, infra | Microsoft patches the platform |
| **SaaS** (M365, Entra) | Data, identities, access config | Nearly everything | Your job = identity + config + data |

**The shared-responsibility model is the #1 cloud interview concept:** the cloud provider secures the cloud *of* the cloud; you secure what's *in* it — always data, identities, and access config, regardless of model. Most cloud breaches are customer-side misconfigurations, not provider failures.

**Regions & Availability Zones:** a **region** is a geographic cluster of datacenters; **Availability Zones** are physically separate datacenters within a region (for high availability). A **Region Pair** is a linked second region for disaster recovery.

---

## 2. Azure core architecture & resource hierarchy

The management hierarchy is where access control and policy attach — understanding it is essential for scoping "who can affect what."

```
Management Group          ← governance across subscriptions
  └── Subscription        ← billing + policy boundary
        └── Resource Group  ← logical container for related resources
              └── Resources (VM, Storage, SQL, VNet, ...)
```

| Level | Purpose | Security relevance |
|---|---|---|
| **Management Group** | Group subscriptions for governance | Apply RBAC/policy at scale (inheritance) |
| **Subscription** | Billing + a security/policy boundary | Blast-radius boundary; separate prod/dev |
| **Resource Group** | Lifecycle container for related resources | RBAC scoping, deployment unit |
| **Resource** | The actual service instance | Inherits locks/tags/RBAC from above |

**Key governance services:**
- **Azure Resource Manager (ARM)** — the deployment/management layer; every create/update/delete flows through it and is logged.
- **Azure Policy** — enforce/audit configuration rules (e.g., "no public IPs," "require encryption").
- **Azure Blueprints / Landing Zones** — repeatable governed environments.

**Interview signal:** "Azure access control and policy are *hierarchical* — RBAC and policy set at a management group inherit down to subscriptions, resource groups, and resources. That's powerful for governance but means a high-scope role assignment is a high-blast-radius risk, which is exactly what I'd hunt in an IR scoping question."

---

## 3. Identity — Microsoft Entra ID (the real perimeter)

Entra ID (formerly **Azure AD**) is the cloud identity and access backbone. In cloud, **identity is the primary attack surface and the primary log source.**

### 3.1 Core identity concepts

| Concept | What it is |
|---|---|
| **Tenant** | A dedicated Entra ID instance = the org's identity boundary |
| **User / Group** | People and collections for assigning access |
| **Service Principal** | Identity for an app/service (non-human) |
| **Managed Identity** | Azure-managed service identity — no stored credentials to leak (preferred over SP + secret) |
| **App Registration** | Registering an app to integrate with Entra (defines permissions/consent) |
| **Roles (Entra roles)** | Directory roles (Global Admin, etc.) — distinct from Azure RBAC |
| **PIM** | Privileged Identity Management — just-in-time elevation instead of standing admin |

**Critical distinction — Entra roles vs. Azure RBAC:**
- **Entra ID roles** govern the *directory* (manage users, apps, tenants).
- **Azure RBAC roles** govern *resources* (who can manage VMs/storage at a scope).
Confusing these is a common misconfiguration and a common interview trap.

### 3.2 Authentication & access controls

| Feature | Purpose | Security note |
|---|---|---|
| **MFA** | Second factor | Phishing-resistant MFA (FIDO2/passkeys) > SMS |
| **Conditional Access** | Policy engine: *if* user/device/location/risk *then* require/block | The central access-policy control — evaluate sign-in risk, device compliance, location |
| **Identity Protection** | Detects risky sign-ins/users (impossible travel, leaked creds) | Feeds detections; can auto-remediate via CA |
| **SSO / federation** | Single sign-on across apps | Federation misconfig = token-forgery risk |
| **Access Reviews** | Periodic recertification of access | Reduces privilege creep |

**High-value identity attack detections:**
- **Impossible travel** — sign-ins from distant geographies in impossible time.
- **Token theft / pass-the-cookie** — session replayed from an unusual IP/ASN/device.
- **Consent phishing** — malicious app registration granted broad Graph permissions.
- **Privilege escalation** — new Global Admin, role assignment, or PIM activation outside a change window.
- **Legacy auth / basic auth** — bypasses MFA; should be blocked via Conditional Access.

**Interview signal:** "In Azure I'd anchor detection on Entra ID sign-in and audit logs the same way I anchored on GCP IAM audit logs — impossible travel, anomalous token use, new privileged role assignments, and consent grants. Conditional Access is the enforcement counterpart: it's where I'd push phishing-resistant MFA and block legacy auth, which is the single highest-value identity hardening move."

---

## 4. Azure RBAC (resource access control)

Azure RBAC controls **who can do what on which resources**, assigned at a **scope**.

```
Security principal (user/group/SP/managed identity)
   + Role definition (what actions: Owner, Contributor, Reader, custom)
   + Scope (MG → subscription → RG → resource)
   = Role assignment
```

**Built-in roles (most common):**

| Role | Power |
|---|---|
| **Owner** | Full control incl. assigning access — highest risk |
| **Contributor** | Manage resources, but **not** assign access |
| **Reader** | View only |
| **User Access Administrator** | Manage access/role assignments |

**Security principles:**
- **Least privilege** — grant the narrowest role at the narrowest scope.
- **Limit Owners** — Owner at subscription scope is a high-blast-radius assignment.
- **Use PIM** for just-in-time privileged roles rather than standing assignment.
- **Prefer groups** over per-user assignments for manageability.
- Watch **custom roles** with wildcard (`*`) actions — equivalent to Owner.

---

## 5. Network security in Azure

| Service / feature | What it does |
|---|---|
| **VNet** | Isolated virtual network; the container for subnets |
| **NSG (Network Security Group)** | Stateful L3/L4 allow/deny rules on subnets/NICs — the core micro-filter |
| **Azure Firewall** | Managed, stateful L3–L7 firewall with threat intel and FQDN filtering |
| **Azure Firewall Manager** | Central policy across firewalls |
| **WAF (Web Application Firewall)** | L7 protection on App Gateway / Front Door — OWASP rules |
| **DDoS Protection** | Network (basic, auto) / Standard (adaptive tuning, mitigation) |
| **Private Link / Private Endpoint** | Private connectivity to PaaS over the VNet — no public exposure |
| **Service Endpoints** | Direct VNet-to-service path (less isolated than Private Link) |
| **Azure Bastion** | Managed, browser-based RDP/SSH — no public VM ports |
| **Flow logs / NSG flow logs** | Network metadata for forensics |

**Security patterns:**
- **Default-deny with NSGs**, allow only required flows (segmentation).
- **Private Endpoint over public endpoints** for PaaS data services — removes public attack surface.
- **No public RDP/SSH** — use Bastion or JIT (just-in-time) VM access.
- **Hub-and-spoke** topology — centralize shared services/egress/inspection in a hub VNet, workloads in spokes.

**Interview signal:** "Azure network security is NSG + Azure Firewall + Private Link + Bastion. My default posture is default-deny NSGs, private endpoints for data services so nothing is publicly reachable, no public RDP/SSH, and NSG flow logs for forensics — the flow logs are the Azure equivalent of the NetFlow I'd use to scope 'who talked to this IP.'"

---

## 6. Data & secrets protection

| Service | Purpose |
|---|---|
| **Azure Key Vault** | Centralized secrets, keys, certs with RBAC + logging + HSM options |
| **Managed HSM** | FIPS 140-2 Level 3 HSM for high-assurance keys |
| **Encryption at rest** | Enabled by default on most services (SSE); CMK (customer-managed keys) optional |
| **Encryption in transit** | TLS enforced on Azure endpoints |
| **Microsoft Purview** | Data governance, classification, DLP |
| **Storage security** | SAS tokens, access keys, disable public blob access |

**Key practice:** never store secrets in code/config — use **Key Vault + Managed Identity** so workloads fetch secrets with an identity, no stored credential. This is the Azure equivalent of the "no secrets in images / use workload identity" rule from container security.

---

## 7. The detection & response stack (your core interest)

This is where a Threat Response engineer lives in Azure. The stack layers posture management, workload protection, and SIEM/SOAR.

### 7.1 Microsoft Defender for Cloud (CSPM + CWPP)
- **CSPM (Cloud Security Posture Management)** — continuously assesses Azure (and multi-cloud) config against the **Microsoft Cloud Security Benchmark**, producing a **Secure Score**.
- **CWPP (Cloud Workload Protection)** — per-workload Defender plans: VMs, storage, SQL, containers, Key Vault, etc.
- Surfaces misconfigurations and threats as **recommendations** and **alerts**.

### 7.2 Microsoft Sentinel (SIEM + SOAR)
Sentinel is Azure's cloud-native SIEM/SOAR — the direct analog to Panther/Splunk in your JD.

| Component | Function |
|---|---|
| **Data connectors** | Ingest logs (Entra ID, Defender, activity logs, third-party) |
| **Analytics rules** | Detections (KQL scheduled queries, or ML/fusion) |
| **KQL (Kusto Query Language)** | The query language — core skill |
| **Hunting** | Interactive KQL queries + bookmarks |
| **Incidents** | Correlated groups of alerts |
| **Playbooks (Logic Apps)** | SOAR automation |
| **UEBA / Fusion** | Behavior analytics + multi-stage correlation |

**KQL is the key transferable skill** (analogous to XQL you've used):

```kusto
// Anomalous sign-ins from new locations in the last day
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| summarize Locations = make_set(Location) by UserPrincipalName
| where array_length(Locations) > 3

// New privileged role assignments (priv-esc)
AuditLogs
| where OperationName has "Add member to role"
| where TargetResources has "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

### 7.3 Key log sources for IR

| Log | What it captures |
|---|---|
| **Entra sign-in logs** | Every authentication — source, result, device, CA applied |
| **Entra audit logs** | Directory changes — role assignments, app consents, user changes |
| **Azure Activity Log** | Control-plane operations (ARM) — who created/changed/deleted what resource |
| **NSG flow logs** | Network traffic metadata |
| **Defender alerts** | Workload threat detections |
| **Resource/diagnostic logs** | Data-plane operations per service |

**Interview signal:** "In Azure my IR anchor points are Entra sign-in + audit logs for identity, the Activity Log for control-plane 'who changed what,' and NSG flow logs for network. Sentinel is the SIEM/SOAR layer with KQL as the query language and Logic Apps for playbooks — directly analogous to how I've used a SIEM plus SOAR elsewhere. Defender for Cloud gives me posture (Secure Score) and workload alerts. The translation from my GCP SCC work is near one-to-one: anomalous-identity findings, severity-based triage, and SOAR-driven enrichment."

---

## 8. Threat scenarios & the ATT&CK mapping

| Scenario | Key telemetry | Response lever |
|---|---|---|
| **Credential theft / account takeover** | Sign-in logs (impossible travel, token replay) | Conditional Access block, revoke sessions, reset creds, MFA |
| **Privilege escalation** | Audit logs (role add, PIM activation) | Remove role, investigate actor, review PIM |
| **Consent phishing** | Audit logs (app consent granted) | Revoke app consent, disable app, hunt granted scopes |
| **Data exfiltration from storage** | Storage diagnostic logs, NSG flow | Revoke SAS/keys, private endpoint, Conditional Access |
| **VM compromise** | Defender for Servers, NSG flow, Activity Log | Isolate VM, snapshot, reimage |
| **Malicious resource creation (cryptomining)** | Activity Log (VM create), flow logs | Delete resources, lock subscription, investigate identity |

---

## 9. Cross-cloud translation (leverage your GCP knowledge)

| Concept | GCP | Azure |
|---|---|---|
| Identity | Cloud IAM / Identity | **Microsoft Entra ID** |
| Resource hierarchy | Org → Folder → Project | **Management Group → Subscription → Resource Group** |
| Access control | IAM roles | **Azure RBAC** |
| Audit logs | Cloud Audit Logs (Admin Activity) | **Azure Activity Log + Entra audit logs** |
| Posture/CSPM | Security Command Center | **Microsoft Defender for Cloud** |
| SIEM/SOAR | Chronicle / SCC+SOAR | **Microsoft Sentinel** |
| Secrets | Secret Manager | **Azure Key Vault** |
| Network filter | VPC firewall rules | **NSG / Azure Firewall** |
| Managed identity | Service accounts | **Managed Identities** |

**The one-liner:** "Entra ID ≈ GCP IAM, Defender for Cloud ≈ SCC, Sentinel ≈ Chronicle, Activity Log ≈ Admin Activity audit logs, NSG ≈ VPC firewall. The concepts transfer; the service names and the query language (KQL vs. SQL/XQL) are what I'd ramp on."

---

## 10. Interview framing (Cloud Security = 3, honest + strong)

> "My hands-on cloud depth is GCP — I built detection and SOAR response for anomalous IAM grants off Security Command Center and audit logs. The Azure model translates cleanly: Entra ID is the identity plane and primary log source, RBAC is hierarchical access control, Defender for Cloud is the CSPM/secure-score layer, and Sentinel is the SIEM/SOAR with KQL. What I'd ramp on is the Azure-specific service behavior and KQL fluency. The detection methodology — identity-first, audit-log-anchored, severity-based triage, human-approved containment — is platform-agnostic and directly carries over."

**Depth signals to drop:**
- "Identity is the perimeter — I'd anchor on Entra sign-in and audit logs."
- "Owner at subscription scope is a high-blast-radius role assignment I'd hunt."
- "Conditional Access with phishing-resistant MFA and blocking legacy auth is the highest-value identity hardening."
- "Managed Identity removes stored-credential risk — same principle as workload identity in containers."
- "Sentinel + KQL + Logic Apps maps to my SIEM/SOAR experience; the query language is the main ramp."

---

## 11. Quick reference — security services cheat sheet

| Need | Azure service |
|---|---|
| Identity & access | Microsoft Entra ID |
| Privileged access (JIT) | Entra PIM |
| Access policy engine | Conditional Access |
| Risky sign-in detection | Entra ID Protection |
| Posture / CSPM / Secure Score | Microsoft Defender for Cloud |
| SIEM / SOAR | Microsoft Sentinel |
| Endpoint/XDR | Microsoft Defender for Endpoint |
| Cloud app broker (CASB) | Microsoft Defender for Cloud Apps |
| Secrets/keys/certs | Azure Key Vault |
| Network filtering | NSG + Azure Firewall |
| Web app protection | WAF (App Gateway/Front Door) |
| DDoS | Azure DDoS Protection |
| Private PaaS access | Private Link / Private Endpoint |
| Secure admin access | Azure Bastion |
| Governance/policy | Azure Policy + Management Groups |
| Data governance/DLP | Microsoft Purview |

---

## 12. Further learning

- **AZ-900 Azure Fundamentals path** — https://learn.microsoft.com/training/paths/microsoft-azure-fundamentals-describe-cloud-concepts/
- **SC-900 (Security, Compliance, Identity)** — https://learn.microsoft.com/credentials/certifications/security-compliance-and-identity-fundamentals/
- **Microsoft Cloud Security Benchmark** — https://learn.microsoft.com/security/benchmark/azure/
- **Entra ID docs** — https://learn.microsoft.com/entra/identity/
- **Sentinel docs + KQL** — https://learn.microsoft.com/azure/sentinel/
- **KQL quick reference** — https://learn.microsoft.com/azure/data-explorer/kusto/query/
- **Defender for Cloud** — https://learn.microsoft.com/azure/defender-for-cloud/
- **MITRE ATT&CK Cloud** — https://attack.mitre.org/matrices/enterprise/cloud/
- **Azure security best practices** — https://learn.microsoft.com/azure/security/fundamentals/best-practices-and-patterns
