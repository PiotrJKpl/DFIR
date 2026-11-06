# AWS DFIR - Detailed Field Guide

A practical guide to Digital Forensics and Incident Response in Amazon Web Services (AWS). It covers identity compromise, control-plane investigation, EC2 and EBS forensics, S3 and data-store exfiltration, containers, serverless, generative AI services, and organization-level response. Sections follow the response workflow: preparation, triage, log analysis, identity investigation, containment, acquisition, service-specific analysis, timelining, eradication, and recovery.

> **Golden rules:** obtain authorization and confirm account ownership, preserve evidence before analyzing it, work from a dedicated IR identity in a dedicated forensic account, record every action with a UTC timestamp, hash everything, and never assume a log exists until you have verified its configuration. In AWS, the **control plane is evidence**. Every describe, snapshot, share, or containment API call you make is also written to CloudTrail. Name your IR sessions so analysts can tell your actions from the attacker's.

> **Currency note:** last reviewed 2026-10-31. AWS changes quickly. Verify service names, finding types, event names, and defaults against current AWS documentation before using them in an incident or in detection logic.

Related host-level guides in this folder: [Linux DFIR](./GUIDE_Linux_DFIR.md), [Windows DFIR](./GUIDE_Windows_DFIR.md), [Kubernetes DFIR](./GUIDE_Kubernetes_DFIR.md), [Container DFIR](./GUIDE_Container_DFIR.md).

---

## 0. Authoritative starting points

| Resource | Why it matters | Link |
|---|---|---|
| AWS Security Incident Response Guide | AWS's IR whitepaper: preparation, operations, and post-incident activity | https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html |
| AWS Security Incident Response (service) | Managed triage, AWS CIRT access, case management, and containment runbooks | https://docs.aws.amazon.com/security-ir/latest/userguide/ |
| CloudTrail record contents | Field-by-field meaning of CloudTrail events | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html |
| CloudTrail `userIdentity` element | Interpreting principals, sessions, and credential types | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html |
| Querying CloudTrail with Athena | Table DDL, partition projection, and examples | https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html |
| GuardDuty finding types | Current finding catalog, including attack sequences | https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html |
| GuardDuty: remediating compromised credentials | AWS's remediation guidance for credential findings | https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html |
| IAM: revoking role session credentials | `aws:TokenIssueTime` revocation mechanics | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html |
| VPC Flow Log records | Field definitions, versions, and logging gaps | https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html |
| EC2 security group connection tracking | Why changing a security group does not close existing sessions | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html |
| AWS incident response playbooks | Sample playbooks for common AWS incident types | https://github.com/aws-samples/aws-incident-response-playbooks |
| AWS Customer Playbook Framework | Template playbooks aligned to AWS services | https://github.com/aws-samples/aws-customer-playbook-framework |
| AWS Security Services Best Practices | Configuration guidance for GuardDuty, Security Hub, Detective, and related services | https://aws.github.io/aws-security-services-best-practices/ |
| MITRE ATT&CK IaaS matrix | Map cloud evidence and detections to adversary techniques | https://attack.mitre.org/matrices/enterprise/cloud/iaas/ |
| SANS FOR509 | Enterprise cloud forensics and incident response curriculum | https://www.sans.org/cyber-security-courses/enterprise-cloud-forensics-incident-response/ |
| Hacking the Cloud | Offensive AWS techniques that explain the evidence you will find | https://hackingthe.cloud/ |
| NIST SP 800-61 Rev. 3 | Incident-response recommendations aligned with CSF 2.0 | https://csrc.nist.gov/pubs/sp/800/61/r3/final |

---

## 1. AWS concepts a responder must understand

These concepts determine what evidence exists, where it is stored, and what it can prove.

- **Shared responsibility defines what you can collect.** You can collect evidence from guest operating systems, your configuration, and the logs you enabled. You cannot collect hypervisor memory, AWS-internal network captures, or physical media. On Nitro instances, guest memory is accessible only from inside the guest or through hibernation.
- **The control plane and data plane are separate evidence domains.** Control-plane calls such as `RunInstances`, `PutBucketPolicy`, and `AssumeRole` appear in CloudTrail management events by default. Data-plane access such as S3 `GetObject`, DynamoDB item reads, and Lambda `Invoke` appears only when you enable data events. If these events were not enabled before the incident, you cannot recover that evidence.
- **The account is the primary blast-radius boundary.** AWS Organizations groups accounts into organizational units (OUs). Service control policies (SCPs) cap what principals in member accounts can do. Resource control policies (RCPs) cap what can be done to supported resources. Neither applies to the management account.
- **Regions are isolated, and attackers use that isolation.** Most resources and their logs are regional. Attackers often create resources in regions you do not monitor. Global services such as IAM, Organizations, and CloudFront, and STS calls to the global endpoint, log to `us-east-1`. Always scope **all enabled regions**.
- **Identity is the new perimeter.** Principals include the root user, IAM users (long-term credentials), IAM roles (temporary credentials), IAM Identity Center users, federated SAML or OIDC identities, service principals, and service-linked roles. Most AWS incidents start with a stolen credential, not a software exploit.
- **You cannot revoke individual temporary credentials.** STS credentials remain valid until they expire, which can be 15 minutes to 12 hours for roles and up to 36 hours for `GetFederationToken` or `GetSessionToken`. Containment therefore uses deny policies conditioned on `aws:TokenIssueTime`, not deletion.
- **Policies are evaluated at request time.** An explicit deny in any applicable policy wins. These policy types include SCPs, RCPs, permissions boundaries, session policies, identity policies, and resource policies. This is why attaching a deny policy is the fastest effective containment action.
- **Resource-based policies create invisible trust.** S3 bucket policies, KMS key policies, role trust policies, Lambda resource policies, SNS and SQS policies, and snapshot or AMI launch permissions can grant access to external accounts without any IAM user existing in your account.
- **Instance Metadata Service (IMDS) delivers instance-role credentials.** IMDSv1 is vulnerable to server-side request forgery (SSRF) credential theft. IMDSv2 requires a session token obtained through a PUT request. IMDS calls are **not** logged anywhere by default.
- **Logging is largely opt-in and has retention limits.** CloudTrail Event history keeps 90 days of management events per region. Everything else must be configured: trails, data events, VPC Flow Logs, DNS query logs, S3 access logs, EKS audit logs, and application logs. Verify each source before relying on it.
- **Logs are delayed and eventually consistent.** CloudTrail typically delivers events within about 5 minutes, but delivery is not guaranteed in real time. VPC Flow Logs aggregate traffic over 1-minute or 10-minute intervals. A missing event in the last few minutes is not evidence of absence.
- **Ephemeral compute destroys evidence by design.** Auto Scaling scale-in, Spot interruption, Fargate task stop, Lambda environment recycling, and instance-store volumes on stop or terminate all destroy evidence. Prevent automated cleanup before you investigate.

### 1.1 Credential and identifier prefixes

| Prefix | Meaning | DFIR use |
|---|---|---|
| `AKIA` | Long-term access key (IAM user or root) | Persistent until deactivated. Check `get-access-key-last-used` and exposure sources. |
| `ASIA` | Temporary STS access key | Trace back to the `AssumeRole`, `GetSessionToken`, or `GetFederationToken` event that issued it (`responseElements.credentials.accessKeyId`). |
| `AIDA` | IAM user unique ID | Survives user rename. Delete-and-recreate gives a new ID. |
| `AROA` | IAM role unique ID | Appears in `principalId` as `AROA...:role-session-name`. |
| `AIPA` | EC2 instance profile ID | Links an instance to its role. |
| `AGPA` / `ANPA` | IAM group / managed policy IDs | Policy and group change tracking. |
| `APKA` | Public key ID | CloudFront key pairs and signing material. |

```bash
# Which account owns an access key (works for keys from any account)
aws sts get-access-key-info --access-key-id AKIAEXAMPLEEXAMPLE
```

### 1.2 Role session naming as evidence

| Session source | Typical `role-session-name` / principal pattern |
|---|---|
| EC2 instance role | `AROA...:i-0123456789abcdef0` (instance ID) |
| Lambda execution role | `AROA...:<function-name>` |
| IAM Identity Center | `AROA...:<username or email>` on an `AWSReservedSSO_<PermissionSet>_<hash>` role |
| EKS Pod Identity / IRSA | Pod Identity uses `eks-<cluster>-<pod>-...`. IRSA uses `AssumeRoleWithWebIdentity` from the cluster OIDC provider. |
| GitHub Actions OIDC | `AssumeRoleWithWebIdentity` with provider `token.actions.githubusercontent.com` |
| AWS services | `userIdentity.invokedBy` such as `cloudformation.amazonaws.com` |

Role session names are chosen by the caller, so attackers can set them freely. Use `sourceIdentity` when your organization enforces it, because it persists across role chaining.

---

## 2. Preparation and evidence handling

### 2.1 Account architecture for IR

Use a multi-account landing zone with these dedicated accounts:

| Account | Purpose | Key controls |
|---|---|---|
| **Management** | Organizations, billing, SCPs and RCPs. No workloads. | Minimal human access. Hardware MFA on root. |
| **Log Archive** | Organization CloudTrail trail, Config, VPC Flow Logs, DNS logs, and S3 access logs | S3 Object Lock, versioning, KMS customer managed key (CMK), and bucket policy that denies deletes. Readable by IR, writable only by log services. |
| **Security Tooling** | Delegated administrator for GuardDuty, Security Hub, Detective, Inspector, Macie, Access Analyzer, and Security Lake | Organization-wide enablement with auto-enable for new accounts. |
| **Forensics** | Isolated analysis VPC, forensic workstations, and evidence buckets | No internet egress by default. VPC endpoints for S3, EC2, SSM, KMS, and STS. Separate KMS keys. |

Pre-provision these items:

- **IR roles** in every account, deployed with StackSets, that the Security account can assume. Use read-only investigation roles and a separate, tightly monitored containment role. Require MFA and a `sourceIdentity` or session-name convention such as `IR-<case>-<analyst>`.
- **Break-glass access** that does not depend on the identity provider (IdP) you may be investigating.
- **A forensic AMI** with SIFT or your toolset, plus a **tools EBS snapshot** containing static binaries such as AVML, UAC, and WinPmem that you can attach to suspect instances.
- **An evidence bucket** with Object Lock enabled at creation, versioning, SSE-KMS with an IR-only CMK, access logging, and a deny-delete bucket policy.
- **SSM Automation and Run Command documents** for containment and collection, tested before you need them.
- **An isolation security group** in each VPC with no inbound rules and egress only to the SSM interface endpoints, so you can still collect data after isolation.
- **Contacts**: AWS Support plan escalation path, AWS Security Incident Response subscription (if used), legal, privacy, and service owners.

```bash
# Evidence bucket with Object Lock (enable at creation). COMPLIANCE mode cannot be shortened by anyone, including root.
aws s3api create-bucket --bucket acme-ir-evidence-111122223333-eu-central-1 \
  --region eu-central-1 --create-bucket-configuration LocationConstraint=eu-central-1 \
  --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration --bucket acme-ir-evidence-111122223333-eu-central-1 \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":365}}}'
```

Use `GOVERNANCE` mode while testing. Switch to `COMPLIANCE` mode for real evidence only after legal agrees on the retention period.

### 2.2 Logging baseline

| Source | Default state | What it proves | Recommendation |
|---|---|---|---|
| CloudTrail Event history | On, 90 days, management events, per region | Who called which control-plane API, when, and from where | Do not rely on it. Use an organization trail. |
| CloudTrail organization trail | Off | Same, long-term and multi-account, with integrity digests | All regions, log file validation on, delivered to the Log Archive account. Retain 1+ years. |
| CloudTrail data events | Off | S3 object, Lambda invoke, DynamoDB, Secrets Manager, and other data-plane access | Enable at least for crown-jewel buckets and tables. Use advanced event selectors to control cost. |
| CloudTrail network activity events | Off | API calls through VPC endpoints, including `VpceAccessDenied` | Enable for data-perimeter endpoints. |
| CloudTrail Insights | Off | Unusual API call or error rates | Optional. Useful for spotting enumeration bursts. |
| VPC Flow Logs | Off | IP-level flows (5-tuple, bytes, accept or reject) | Enable for all VPCs with a custom format (Section 4.4). |
| Route 53 Resolver query logs | Off | DNS lookups by instances, containers, and Lambda in VPC | Enable for all VPCs. Essential for C2 and mining-pool detection. |
| S3 server access logs | Off | Best-effort per-request S3 access, including anonymous requests | Enable for sensitive buckets as a complement to data events. |
| ELB, CloudFront, WAF, API Gateway logs | Off | HTTP requests, client IPs, and exploit attempts | Enable on internet-facing entry points. |
| EKS control plane logs | Off | Kubernetes API audit and authenticator decisions | Enable `audit` and `authenticator` at minimum. |
| AWS Config | Off | Point-in-time configuration history of resources | Enable organization-wide. Records "what it looked like before". |
| GuardDuty | Off | Threat findings across CloudTrail, VPC, DNS, EKS, runtime, S3, malware, and RDS | Enable organization-wide with all relevant protection plans. Export findings to S3 (90-day retention otherwise). |
| SSM Session Manager logging | Off | Interactive session transcripts | Send to S3 or CloudWatch Logs with KMS encryption. |
| Bedrock model invocation logging | Off | Prompt and response content and token use | Enable where Bedrock is used. |
| Host logs (CloudWatch agent or EDR) | Off | OS-level process, auth, and application events | Ship off-host. Attackers clear local logs. |

### 2.3 Detection and investigation services

| Service | IR role |
|---|---|
| **Amazon GuardDuty** | Primary threat detection. Includes Extended Threat Detection (multi-stage `AttackSequence:*` findings), Runtime Monitoring (EKS, ECS, EC2), Malware Protection (EC2, S3, and AWS Backup), S3 Protection, EKS Protection, Lambda Protection, and RDS Protection. |
| **AWS Security Hub** | Aggregates findings from GuardDuty, Inspector, Macie, Access Analyzer, and partners. Security Hub CSPM provides posture checks. Watch for suppression automation rules. |
| **Amazon Detective** | Behavior graph built from CloudTrail, VPC Flow Logs, GuardDuty, and EKS audit data, with up to 1 year of history. Fast pivoting on IP addresses, principals, and roles. |
| **Amazon Security Lake** | Centralizes logs in Open Cybersecurity Schema Framework (OCSF) format in S3. Query with Athena or a SIEM. |
| **IAM Access Analyzer** | External-access findings show what is shared outside your zone of trust. Unused-access findings show stale credentials and permissions. |
| **Amazon Inspector** | Vulnerability context for EC2, ECR images, and Lambda. Useful when you suspect the initial access vector was an exploit. |
| **Amazon Macie** | Sensitive-data discovery. Tells you what data an attacker could have read from S3. |
| **AWS Security Incident Response** | Subscription service. Provides automated triage, 24/7 AWS Customer Incident Response Team (CIRT) engagement, case management, and reversible containment runbooks. |

> **CloudTrail Lake availability:** AWS closed CloudTrail Lake to new customers on 2026-05-31. Existing customers can keep using it. For new deployments, use Athena over the S3 trail, Security Lake, or the CloudWatch-based alternatives AWS recommends.

### 2.4 Guardrails that protect evidence

Apply an SCP that prevents anyone except the security team from disabling telemetry. Test it in a sandbox OU first, because SCPs affect every principal in the target accounts, including root, but not the management account or service-linked roles.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectSecurityTelemetry",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        "guardduty:DeleteDetector",
        "guardduty:UpdateDetector",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:CreateFilter",
        "guardduty:UpdateFilter",
        "guardduty:CreateIPSet",
        "guardduty:UpdateIPSet",
        "securityhub:DisableSecurityHub",
        "config:StopConfigurationRecorder",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "ec2:DeleteFlowLogs",
        "route53resolver:DeleteResolverQueryLogConfig",
        "route53resolver:DisassociateResolverQueryLogConfig",
        "organizations:LeaveOrganization"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/SecurityBreakGlass",
            "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAdmin_*"
          ]
        }
      }
    }
  ]
}
```

Also consider these guardrails:

- Enforce IMDSv2 with EC2 account-level metadata defaults or an organization declarative policy.
- Turn on block public access for S3 (account level), EBS snapshots, and AMIs.
- Use centralized root access management to remove root credentials from member accounts.
- Use RCPs to block access to S3, KMS, STS, SQS, and Secrets Manager resources from outside your organization.

### 2.5 Case log and chain of custody

Record these details for every action:

- UTC timestamp, analyst, and the **IR principal ARN and session name** used.
- Account ID, region, and resource ARN or ID.
- The exact command or console action and its result. Save request and response JSON where possible.
- The evidence item produced: S3 URI or snapshot ID, SHA-256 hash, size, and KMS key.
- The reason for the action: preservation, containment, or analysis.

Snapshot sharing, volume creation, policy attachment, and tagging done by IR look identical to attacker activity in CloudTrail. A disciplined case log and consistent `ir-case` tags let a later reviewer separate the two.

---

## 3. Triage: the first hour

### 3.1 Scoping questions

1. **What triggered the response?** Examples: a GuardDuty finding, an AWS Health or abuse notification, a billing spike, a leaked key report, a ransom note, or a third-party report.
2. **Which principal is involved?** Identify the access key ID, role ARN, Identity Center user, or federated identity.
3. **Which accounts and regions are affected?** Check whether the principal has cross-account trust paths.
4. **Is the activity ongoing?** Check for events in the last 15 minutes, live sessions, or running resources.
5. **What can the principal reach?** Review its effective permissions, data stores, secrets, and other roles it can assume.
6. **What logs exist for the window?** Check trail coverage, data events, Flow Logs, DNS logs, and their retention.
7. **Are there business constraints?** Consider production availability, legal hold, regulator notification clocks, and customer data.

### 3.2 Orient yourself

```bash
# Confirm which identity and account the CLI is using before running anything else
aws sts get-caller-identity

# Organization context and enabled regions
aws organizations describe-organization
aws account list-regions --region-opt-status-contains ENABLED ENABLED_BY_DEFAULT \
  --query 'Regions[].RegionName' --output text

# Trail coverage and status (shadow trails reveal organization trails)
aws cloudtrail describe-trails --include-shadow-trails
aws cloudtrail get-trail-status --name <trail-name-or-arn>
aws cloudtrail get-event-selectors --trail-name <trail-name-or-arn>

# GuardDuty status and high-severity findings
DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "$DET"
aws guardduty list-findings --detector-id "$DET" \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'

# Suppression is an attacker technique. Check filters and trusted IP lists.
aws guardduty list-filters --detector-id "$DET"
aws guardduty list-ip-sets --detector-id "$DET"
```

### 3.3 Fast Event history lookup (no trail required)

Event history is per region, covers 90 days of management events only, and allows one lookup attribute per call. Loop over regions.

```bash
KEY=AKIAEXAMPLEEXAMPLE
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws cloudtrail lookup-events --region "$R" \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$KEY" \
    --start-time 2026-10-01T00:00:00Z --end-time 2026-10-31T23:59:59Z \
    --output json > "lookup_${KEY}_${R}.json"
done
```

Supported lookup attributes are `EventId`, `EventName`, `ReadOnly`, `Username`, `ResourceType`, `ResourceName`, `EventSource`, and `AccessKeyId`.

### 3.4 Rapid multi-region inventory

```bash
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $R"
  aws ec2 describe-instances --region "$R" \
    --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType,LaunchTime,KeyName,IamInstanceProfile.Arn]' \
    --output text
  aws lambda list-functions --region "$R" --query 'Functions[].[FunctionName,LastModified,Role]' --output text
  aws ecs list-clusters --region "$R" --output text
  aws eks list-clusters --region "$R" --output text
done

# IAM is global
aws iam generate-credential-report >/dev/null; sleep 10
aws iam get-credential-report --query Content --output text | base64 --decode > credential_report.csv
aws iam get-account-authorization-details > iam_account_authorization_details.json
```

### 3.5 Preserve-or-contain decision

| Situation | Bias |
|---|---|
| Active data exfiltration, ransomware, or destructive actions in progress | **Contain first.** Use identity deny policies or an organization quarantine SCP, then preserve. |
| Credential abuse limited to control-plane enumeration | Preserve the logs and inventory quickly (minutes), then contain the identity. |
| Compromised EC2 instance with no active spread | Preserve volatile data first: tag, set termination protection, snapshot, then capture memory. Isolate the network next. |
| Cryptomining or resource abuse | Contain the identity, then stop the abusive resources after snapshot and metadata capture. Cost grows quickly. |
| Insider or legal-hold matter | Preserve covertly. Avoid visible containment until legal approves. |

---

## 4. Log sources and what they prove

### 4.1 AWS CloudTrail

**Event categories:**

- **Management events** cover control-plane operations. They are logged by default and include read-only `Describe*`, `List*`, and `Get*` calls.
- **Data events** cover resource-level operations such as S3 object operations, Lambda `Invoke`, DynamoDB items, and Secrets Manager `GetSecretValue` on specific secrets through advanced selectors. They are opt-in and billed.
- **Network activity events** cover API calls that traverse VPC endpoints, including denied attempts (`errorCode: VpceAccessDenied`). They are opt-in.
- **Insights events** cover anomalous API call rates or error rates.

**Key fields:**

| Field | Investigative value |
|---|---|
| `eventTime` | UTC. When AWS received the request. |
| `eventSource` / `eventName` | Service endpoint and API. Lambda names carry version suffixes such as `UpdateFunctionCode20150331v2`, so match with `LIKE`. |
| `awsRegion` | Region of the call. Global services usually appear as `us-east-1`. |
| `sourceIPAddress` | Caller IP, or an AWS service name such as `ec2.amazonaws.com`, or `AWS Internal`. |
| `userAgent` | SDK, CLI, console, or tool string. Attackers can spoof it, but it is still useful for clustering. |
| `userIdentity.type` | `Root`, `IAMUser`, `AssumedRole`, `FederatedUser`, `AWSService`, `AWSAccount`, `IdentityCenterUser`, `SAMLUser`, `WebIdentityUser`, and others. |
| `userIdentity.arn` / `principalId` | The acting principal. For roles, `AROA...:session-name`. |
| `userIdentity.accessKeyId` | `AKIA` or `ASIA` key used. This is the strongest pivot. |
| `userIdentity.sessionContext.sessionIssuer` | The role behind an assumed-role session. |
| `userIdentity.sessionContext.attributes.mfaAuthenticated` / `creationDate` | Whether MFA was used and when the session was issued. |
| `userIdentity.sessionContext.ec2RoleDelivery` | `1.0` means IMDSv1 delivered the credentials. `2.0` means IMDSv2. |
| `userIdentity.sessionContext.sourceIdentity` | Persistent identity across role chaining, when set. |
| `userIdentity.invokedBy` | AWS service acting on the principal's behalf. |
| `errorCode` / `errorMessage` | `AccessDenied` bursts indicate enumeration or privilege probing. |
| `requestParameters` / `responseElements` | What was asked for and what was returned, such as new key IDs, instance IDs, or policy documents. Secrets are redacted. |
| `additionalEventData` | `MFAUsed` and `LoginTo` for console sign-in. S3 data events include `bytesTransferredOut`, `AuthenticationMethod` (`QueryString` means a presigned URL), and `SSEApplied`. |
| `recipientAccountId` / `sharedEventID` | Cross-account events appear in both accounts with the same `sharedEventID`. |
| `vpcEndpointId` | The request came through a VPC endpoint. |
| `tlsDetails` | TLS version, cipher, and client-provided host header. |
| `readOnly` / `eventCategory` | Filter read versus write, and management versus data versus network activity. |

**Integrity:** If the trail has log file validation enabled, verify integrity before analysis and record the output.

```bash
aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:eu-central-1:111122223333:trail/org-trail \
  --start-time 2026-10-01T00:00:00Z --end-time 2026-10-31T23:59:59Z --verbose > validate-logs.txt
```

**Layout in S3:** `s3://<bucket>/[prefix/]AWSLogs/[<org-id>/]<account-id>/CloudTrail/<region>/YYYY/MM/DD/*.json.gz`, with digests under `CloudTrail-Digest/`.

**What CloudTrail does not show:**

- Data-plane access unless you enabled data events.
- IMDS requests.
- OS-level activity.
- Traffic content.
- Secret values (redacted).
- Some service-specific operations.

Always confirm event coverage for the specific service and API in the AWS documentation.

### 4.2 Analyzing CloudTrail with Athena

Create the table once in the Log Archive or Forensics account. Partition projection avoids partition maintenance.

```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
  eventversion STRING,
  useridentity STRUCT<
    type: STRING, principalid: STRING, arn: STRING, accountid: STRING,
    invokedby: STRING, accesskeyid: STRING, username: STRING,
    sessioncontext: STRUCT<
      attributes: STRUCT<mfaauthenticated: STRING, creationdate: STRING>,
      sessionissuer: STRUCT<type: STRING, principalid: STRING, arn: STRING, accountid: STRING, username: STRING>,
      ec2roledelivery: STRING,
      sourceidentity: STRING>>,
  eventtime STRING,
  eventsource STRING,
  eventname STRING,
  awsregion STRING,
  sourceipaddress STRING,
  useragent STRING,
  errorcode STRING,
  errormessage STRING,
  requestparameters STRING,
  responseelements STRING,
  additionaleventdata STRING,
  requestid STRING,
  eventid STRING,
  readonly STRING,
  resources ARRAY<STRUCT<arn: STRING, accountid: STRING, type: STRING>>,
  eventtype STRING,
  recipientaccountid STRING,
  sharedeventid STRING,
  vpcendpointid STRING,
  eventcategory STRING
)
PARTITIONED BY (account STRING, region STRING, day STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<trail-bucket>/AWSLogs/<org-id>/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.account.type'='enum',
  'projection.account.values'='111122223333,444455556666',
  'projection.region.type'='enum',
  'projection.region.values'='us-east-1,eu-west-1,eu-central-1',
  'projection.day.type'='date',
  'projection.day.range'='2025/01/01,NOW',
  'projection.day.format'='yyyy/MM/dd',
  'projection.day.interval'='1',
  'projection.day.interval.unit'='DAYS',
  'storage.location.template'='s3://<trail-bucket>/AWSLogs/<org-id>/${account}/CloudTrail/${region}/${day}'
);
```

List **every enabled region** in `projection.region.values`. Otherwise, activity in unexpected regions is silently excluded.

**Q1. Everything a key did:**

```sql
SELECT eventtime, recipientaccountid, awsregion, eventsource, eventname,
       sourceipaddress, useragent, errorcode
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND useridentity.accesskeyid = 'AKIAEXAMPLEEXAMPLE'
ORDER BY eventtime;
```

**Q2. Temporary keys minted from a compromised key, and their activity:**

```sql
WITH issued AS (
  SELECT json_extract_scalar(responseelements, '$.credentials.accessKeyId') AS sts_key,
         eventname AS issued_by, eventtime AS issued_at
  FROM cloudtrail_logs
  WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
    AND eventsource = 'sts.amazonaws.com'
    AND useridentity.accesskeyid = 'AKIAEXAMPLEEXAMPLE'
    AND errorcode IS NULL
)
SELECT i.issued_by, i.issued_at, c.eventtime, c.awsregion, c.eventname,
       c.useridentity.arn, c.sourceipaddress
FROM cloudtrail_logs c
JOIN issued i ON c.useridentity.accesskeyid = i.sts_key
WHERE c.day BETWEEN '2026/10/01' AND '2026/10/31'
ORDER BY c.eventtime;
```

Repeat the pivot recursively for role chaining. Each `AssumeRole` issues a new `ASIA` key.

**Q3. Everything from an attacker IP, across all principals:**

```sql
SELECT eventtime, recipientaccountid, useridentity.arn, useridentity.accesskeyid,
       eventname, awsregion, useragent, errorcode
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND sourceipaddress = '203.0.113.50'
ORDER BY eventtime;
```

**Q4. Enumeration and privilege probing (AccessDenied bursts):**

```sql
SELECT useridentity.arn, sourceipaddress, date_trunc('hour', from_iso8601_timestamp(eventtime)) AS hr,
       count(*) AS denied, count(DISTINCT eventname) AS distinct_apis
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND errorcode IN ('AccessDenied', 'Client.UnauthorizedOperation', 'AccessDeniedException', 'UnauthorizedOperation')
GROUP BY 1, 2, 3
HAVING count(DISTINCT eventname) > 15
ORDER BY denied DESC;
```

**Q5. Telemetry tampering:**

```sql
SELECT eventtime, recipientaccountid, awsregion, useridentity.arn, eventname, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND eventname IN ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors','DeleteEventDataStore',
                    'DeleteDetector','UpdateDetector','CreateFilter','UpdateFilter','CreateIPSet','UpdateIPSet',
                    'DisassociateFromAdministratorAccount','DisableSecurityHub','CreateAutomationRule',
                    'StopConfigurationRecorder','DeleteConfigurationRecorder','DeleteDeliveryChannel',
                    'DeleteFlowLogs','DeleteResolverQueryLogConfig','DisassociateResolverQueryLogConfig',
                    'DeleteLogGroup','DeleteLogStream','PutRetentionPolicy','DeleteModelInvocationLoggingConfiguration')
ORDER BY eventtime;
```

**Q6. IAM persistence and privilege escalation:**

```sql
SELECT eventtime, recipientaccountid, useridentity.arn, eventname, sourceipaddress,
       requestparameters, responseelements
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND eventsource IN ('iam.amazonaws.com','sso.amazonaws.com','identitystore.amazonaws.com',
                      'sso-directory.amazonaws.com','rolesanywhere.amazonaws.com')
  AND readonly = 'false'
ORDER BY eventtime;
```

**Q7. Console sign-ins (failures, no MFA, root):**

```sql
SELECT eventtime, awsregion, useridentity.type, useridentity.arn, sourceipaddress, useragent,
       json_extract_scalar(responseelements, '$.ConsoleLogin') AS result,
       json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used,
       errormessage
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND eventname = 'ConsoleLogin'
ORDER BY eventtime;
```

**Q8. S3 egress volume per principal for a bucket (requires S3 data events):**

```sql
SELECT useridentity.arn, sourceipaddress,
       json_extract_scalar(additionaleventdata, '$.AuthenticationMethod') AS auth_method,
       count(*) AS gets,
       round(sum(CAST(json_extract_scalar(additionaleventdata, '$.bytesTransferredOut') AS double)) / 1e9, 2) AS gb_out
FROM cloudtrail_logs
WHERE day BETWEEN '2026/10/01' AND '2026/10/31'
  AND eventsource = 's3.amazonaws.com' AND eventname = 'GetObject'
  AND json_extract_scalar(requestparameters, '$.bucketName') = 'crown-jewels-bucket'
GROUP BY 1, 2, 3
ORDER BY gb_out DESC;
```

**Q9. First-seen IPs and user agents per principal (baseline deviation):**

```sql
SELECT useridentity.arn, sourceipaddress, useragent,
       min(eventtime) AS first_seen, max(eventtime) AS last_seen, count(*) AS events
FROM cloudtrail_logs
WHERE day BETWEEN '2026/09/01' AND '2026/10/31'
  AND useridentity.arn LIKE '%:user/%'
GROUP BY 1, 2, 3
ORDER BY first_seen DESC;
```

### 4.3 Offline CloudTrail analysis with jq or DuckDB

Use offline analysis when Athena is unavailable or you are working from an evidence copy.

```bash
# Flatten gzipped CloudTrail files into one JSON record per line
find ./cloudtrail -name '*.json.gz' -exec gzip -dc {} + | jq -c '.Records[]' > ct_records.jsonl

# Quick timeline for one key
jq -r 'select(.userIdentity.accessKeyId=="ASIAEXAMPLEEXAMPLE")
       | [.eventTime,.awsRegion,.eventSource,.eventName,.sourceIPAddress,(.errorCode // "")] | @tsv' \
  ct_records.jsonl | sort
```

```sql
-- DuckDB: keep variable sub-documents as JSON to avoid schema explosion
CREATE TABLE ct AS
SELECT * FROM read_json('ct_records.jsonl', format = 'newline_delimited',
  columns = {eventTime: 'VARCHAR', eventSource: 'VARCHAR', eventName: 'VARCHAR', awsRegion: 'VARCHAR',
             sourceIPAddress: 'VARCHAR', userAgent: 'VARCHAR', errorCode: 'VARCHAR',
             recipientAccountId: 'VARCHAR', userIdentity: 'JSON', requestParameters: 'JSON',
             responseElements: 'JSON', additionalEventData: 'JSON'});

SELECT eventTime, eventName, userIdentity->>'$.arn' AS arn, sourceIPAddress, errorCode
FROM ct
WHERE userIdentity->>'$.accessKeyId' = 'ASIAEXAMPLEEXAMPLE'
ORDER BY eventTime;
```

### 4.4 VPC Flow Logs

The default (version 2) format is `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status`. For IR, use a custom format that adds these fields:

`vpc-id subnet-id instance-id interface-id type pkt-srcaddr pkt-dstaddr tcp-flags flow-direction traffic-path pkt-src-aws-service pkt-dst-aws-service az-id ecs-cluster-name ecs-task-id reject-reason`

| Point | Detail |
|---|---|
| NAT and load balancers | `srcaddr` and `dstaddr` show the interface view. `pkt-srcaddr` and `pkt-dstaddr` show the original packet addresses behind NAT gateways and other intermediaries. |
| Direction | `flow-direction` (`ingress` or `egress`) avoids guessing from ports. |
| Volume | `bytes` per aggregation window. Sum the windows for exfiltration estimates. |
| `start` / `end` | Unix epoch seconds for the aggregation window, not exact connection times. |
| `action` | `ACCEPT` or `REJECT` by security group or network ACL. Rejected outbound attempts often reveal C2 retries after containment. |
| Gaps | Flow Logs do **not** capture IMDS (`169.254.169.254`), Amazon Time Sync (`169.254.169.123`), queries to the Amazon-provided DNS resolver, DHCP, Windows license activation, or mirrored traffic. Use Route 53 Resolver query logs for DNS. |
| No payload | Use VPC Traffic Mirroring (supported Nitro instances) or host capture for packet content. |

CloudWatch Logs Insights query, for Flow Logs delivered to CloudWatch Logs in the default format:

```text
fields @timestamp, srcAddr, dstAddr, dstPort, protocol, action, bytes
| filter srcAddr = "10.20.1.37" and action = "ACCEPT"
| stats sum(bytes) as totalBytes, count(*) as flows by dstAddr, dstPort
| sort totalBytes desc
| limit 50
```

### 4.5 Route 53 Resolver query logs

These logs record DNS queries from resources in associated VPCs that use the Amazon-provided resolver. Key fields include `query_timestamp`, `query_name`, `query_type`, `rcode`, `answers`, `srcaddr`, and `srcids.instance` (or other resource IDs).

Use them to find:

- Mining pools, C2 domains, and paste or file-sharing sites.
- DNS tunneling (high-entropy subdomains, high volume to a single parent domain).
- First-seen domains in the incident window.

Route 53 Resolver DNS Firewall logs show blocked and alerted lookups.

```text
fields @timestamp, query_name, query_type, rcode, srcaddr, srcids.instance
| filter srcids.instance = "i-0123456789abcdef0"
| stats count(*) as queries, earliest(@timestamp) as first_seen by query_name
| sort first_seen asc
```

### 4.6 S3 server access logs compared with CloudTrail data events

| Aspect | S3 server access logs | CloudTrail S3 data events |
|---|---|---|
| Delivery | Best effort, can be delayed or incomplete | Reliable, with integrity validation |
| Anonymous or public access | Logged | Logged for some anonymous requests |
| Identity detail | Requester canonical ID or ARN | Full `userIdentity` including session context |
| Bytes transferred | `Bytes Sent` | `additionalEventData.bytesTransferredOut` |
| Presigned URLs | Query-string authentication visible | `AuthenticationMethod = QueryString` |
| Cost | Storage only | Per-event charges |

If neither was enabled, look for indirect evidence:

- GuardDuty S3 Protection findings. GuardDuty analyzes S3 data events even when your trail does not record them.
- CloudWatch S3 request metrics, if enabled.
- S3 Storage Lens.
- Billing data-transfer line items.
- VPC Flow Logs to S3 prefix lists.
- Downstream logs (CloudFront, ELB).

### 4.7 Edge, application, and service logs

| Source | Location | Use |
|---|---|---|
| ALB / NLB access logs | S3 | Client IPs, request paths, user agents, exploit attempts, and the TLS SNI or host header |
| CloudFront standard logs | S3 or CloudWatch Logs | Edge requests and origin behaviour |
| AWS WAF logs | CloudWatch Logs, S3, or Firehose | Matched rules and full request headers |
| API Gateway access and execution logs | CloudWatch Logs | Caller identity, authorizer results, and integration errors |
| AWS Network Firewall logs | CloudWatch Logs, S3, or Firehose | Alert and flow logs, including TLS SNI for egress filtering |
| EKS control plane | `/aws/eks/<cluster>/cluster` | Kubernetes audit, authenticator, and scheduler logs |
| Lambda | `/aws/lambda/<function>` | Function output, errors, and attacker `print()` debugging |
| RDS / Aurora | CloudWatch Logs (if exported) | Engine audit, error, general, and slow logs. Database Activity Streams for high assurance. |
| SSM Session Manager | S3 or CloudWatch Logs (if configured) | Full interactive session transcripts |
| AWS Config | Log Archive S3 bucket and API | Configuration history and relationships over time |
| Bedrock invocation logs | S3 or CloudWatch Logs (if configured) | Prompts, responses, model IDs, and token counts |
| SES event publishing | Firehose, SNS, or CloudWatch | Sends, bounces, and complaints. Since 2025, SES email-sending API calls can also be recorded as CloudTrail data events if enabled. |

### 4.8 Security Lake and CloudTrail Lake

- **Security Lake** stores CloudTrail management events, S3 and Lambda data events, VPC Flow Logs, Route 53 Resolver logs, Security Hub findings, EKS audit logs, and WAF logs in OCSF Parquet format. Query them through Athena tables named `amazon_security_lake_table_<region>_<source>_<version>`. Map CloudTrail fields to OCSF equivalents. For example, `actor.user.uid` and `api.operation` replace `userIdentity` and `eventName`.
- **CloudTrail Lake** (existing customers only) supports SQL directly against event data stores:

```sql
SELECT eventTime, eventSource, eventName, userIdentity.arn, sourceIPAddress, errorCode
FROM <event-data-store-id>
WHERE eventTime > '2026-10-01 00:00:00'
  AND userIdentity.accessKeyId = 'ASIAEXAMPLEEXAMPLE'
ORDER BY eventTime
```

### 4.9 GuardDuty findings as evidence

GuardDuty keeps findings for 90 days. Export them to the evidence bucket (findings publishing destination) and snapshot them at case start:

```bash
aws guardduty list-findings --detector-id "$DET" --output json > gd_finding_ids.json
jq -r '.FindingIds[]' gd_finding_ids.json | xargs -n 50 \
  aws guardduty get-findings --detector-id "$DET" --output json --finding-ids > gd_findings_$(date -u +%Y%m%dT%H%M%SZ).json
```

`get-findings` accepts up to 50 IDs per call. If there are more than 50 findings, `xargs` writes multiple JSON documents into one file. Use a per-batch file name for strict JSON.

Useful finding fields:

- `service.eventFirstSeen` and `service.eventLastSeen`
- `service.count`
- `service.action` (API, network, DNS, or Kubernetes details)
- `service.evidence` (threat-intel matches)
- `resource` (principal, instance, bucket, or cluster)
- `service.runtimeDetails` (process lineage)

| Category | Representative finding types |
|---|---|
| Multi-stage (Extended Threat Detection) | `AttackSequence:IAM/CompromisedCredentials`, `AttackSequence:S3/CompromisedData`, `AttackSequence:EKS/CompromisedCluster`, `AttackSequence:ECS/CompromisedCluster`, `AttackSequence:EC2/CompromisedInstanceGroup` |
| Credential theft | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, `...InstanceCredentialExfiltration.InsideAWS` |
| Anomalous IAM behaviour | `Discovery:IAMUser/AnomalousBehavior`, `Persistence:IAMUser/AnomalousBehavior`, `PrivilegeEscalation:IAMUser/AnomalousBehavior`, `DefenseEvasion:IAMUser/AnomalousBehavior`, `Exfiltration:IAMUser/AnomalousBehavior`, `Impact:IAMUser/AnomalousBehavior` |
| Malicious infrastructure | `Recon:IAMUser/MaliciousIPCaller`, `UnauthorizedAccess:IAMUser/MaliciousIPCaller`, `UnauthorizedAccess:IAMUser/TorIPCaller`, `PenTest:IAMUser/KaliLinux` |
| Evasion and policy | `Stealth:IAMUser/CloudTrailLoggingDisabled`, `Stealth:IAMUser/PasswordPolicyChange`, `Policy:IAMUser/RootCredentialUsage`, `Policy:S3/BucketBlockPublicAccessDisabled` |
| S3 | `Exfiltration:S3/AnomalousBehavior`, `Impact:S3/AnomalousBehavior.Delete`, `Impact:S3/AnomalousBehavior.Permission`, `Discovery:S3/MaliciousIPCaller` |
| EC2 network and DNS | `CryptoCurrency:EC2/BitcoinTool.B!DNS`, `Backdoor:EC2/C&CActivity.B!DNS`, `Trojan:EC2/DNSDataExfiltration`, `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/TorClient` |
| Runtime | `Execution:Runtime/NewBinaryExecuted`, `Execution:Runtime/ReverseShell`, `PrivilegeEscalation:Runtime/ContainerMountsHostDirectory`, `DefenseEvasion:Runtime/ProcessInjection.Ptrace`, `CryptoCurrency:Runtime/BitcoinTool.B` |
| Kubernetes | `Policy:Kubernetes/AnonymousAccessGranted`, `PrivilegeEscalation:Kubernetes/PrivilegedContainer`, `Execution:Kubernetes/ExecInKubeSystemPod`, `Persistence:Kubernetes/ContainerWithSensitiveMount` |
| Malware | `Execution:EC2/MaliciousFile`, `Execution:S3/MaliciousFile`, `Execution:ECS/MaliciousFile`, `Execution:Kubernetes/MaliciousFile` |

> GuardDuty silence is not proof of a clean environment. Check protection-plan coverage, Runtime Monitoring agent health, suppression filters (`list-filters`), trusted IP lists (`list-ip-sets`), and whether the region had a detector.

---

## 5. Identity investigation

### 5.1 Reconstruct a credential's full activity

1. **Identify the key and its owner.** Run `sts get-access-key-info` to get the account. In that account, use the credential report or `iam list-access-keys` to find the user.
2. **Establish the exposure window.** Use `iam get-access-key-last-used` (last service, region, and time), the key creation date, and the first suspicious `eventTime`.
3. **Pull all activity** for the `AKIA` key across all regions (Q1).
4. **Follow minted sessions.** Find `GetSessionToken`, `GetFederationToken`, and `AssumeRole` events, extract `responseElements.credentials.accessKeyId`, and repeat the search for each `ASIA` key (Q2). Continue recursively through role chains and across accounts using `sharedEventID`.
5. **Pivot on infrastructure.** Search all events from attacker IPs and user agents across all principals (Q3). Attackers often hold several credentials.
6. **Classify actions** by tactic: discovery, privilege escalation, persistence, defense evasion, collection, exfiltration, and impact (Section 11).
7. **List every write action** (`readonly = 'false'`). Each one is either attacker persistence or impact that must be reverted, or IR activity.

### 5.2 Role chaining and cross-account movement

- `AssumeRole` is logged in the **caller's account** and in the **role owner's account**, with the same `sharedEventID`.
- In the target account, the session's events carry `userIdentity.sessionContext.sessionIssuer.arn` set to the assumed role. Match `principalId` (`AROA...:session-name`) and the `ASIA` key.
- Role chaining limits sessions to 1 hour. A steady pattern of `AssumeRole` calls every hour suggests automation or attacker tooling that refreshes credentials.
- Check role trust policies for external accounts, `"Principal": {"AWS": "*"}` with weak conditions, and OIDC trusts with broad `sub` claims. A common misconfiguration is GitHub OIDC trusting `repo:org/*` or any repository.

### 5.3 Console and federated sign-in

| Event (source) | Meaning |
|---|---|
| `ConsoleLogin` (`signin.amazonaws.com`) | IAM user, root, or federated console sign-in. `responseElements.ConsoleLogin` is `Success` or `Failure`, and `additionalEventData.MFAUsed` is `Yes` or `No`. User names for non-existent users appear as `HIDDEN_DUE_TO_SECURITY_REASONS`. |
| `GetSigninToken` (`signin.amazonaws.com`) | A federation URL was generated from temporary credentials. Attackers use this to turn stolen `ASIA` keys into console sessions. |
| `CheckMfa`, `PasswordRecoveryRequested`, `PasswordRecoveryCompleted` | MFA checks and root password reset activity |
| `CredentialChallenge`, `CredentialVerification`, `UserAuthentication` | IAM Identity Center sign-in steps for its own directory |
| `Federate`, `GetRoleCredentials` | Identity Center access portal federation and CLI or SDK role credential retrieval |
| `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` | External IdP or OIDC federation. Correlate with IdP logs such as Entra ID or Okta. |
| `AssumeRoot` (`sts.amazonaws.com`) | Centralized root access: a privileged root task run in a member account from the management or delegated admin account |

`ConsoleLogin` may be recorded in `us-east-1` or in the region of the regional sign-in endpoint. Query all regions. For identities federated from an external IdP, the IdP's sign-in logs (conditional access, device, and location) are part of the evidence set.

### 5.4 Identity inventory for the case file

```bash
mkdir -p iam && cd iam
aws iam get-account-authorization-details > account_authorization_details.json
aws iam get-credential-report --query Content --output text | base64 --decode > credential_report.csv
aws iam get-account-summary > account_summary.json
aws iam list-saml-providers > saml_providers.json
aws iam list-open-id-connect-providers > oidc_providers.json
aws iam list-virtual-mfa-devices > virtual_mfa_devices.json
aws rolesanywhere list-trust-anchors > rolesanywhere_trust_anchors.json 2>/dev/null

U=suspect-user
aws iam list-access-keys --user-name "$U" > "${U}_keys.json"
aws iam list-mfa-devices --user-name "$U" > "${U}_mfa.json"
aws iam list-service-specific-credentials --user-name "$U" > "${U}_service_creds.json"
aws iam list-ssh-public-keys --user-name "$U" > "${U}_ssh_keys.json"
aws iam list-signing-certificates --user-name "$U" > "${U}_signing_certs.json"
aws iam get-login-profile --user-name "$U" > "${U}_login_profile.json" 2>&1

# Service last accessed: which services the principal actually used
JOB=$(aws iam generate-service-last-accessed-details --arn arn:aws:iam::111122223333:user/$U --query JobId --output text)
sleep 10; aws iam get-service-last-accessed-details --job-id "$JOB" > "${U}_service_last_accessed.json"

# External and unused access findings
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings-v2 --analyzer-arn <analyzer-arn> > access_analyzer_findings.json
```

If AWS detects a publicly exposed access key, it may attach an `AWSCompromisedKeyQuarantine*` managed policy to the IAM user and raise an AWS Health event (`AWS_RISK_CREDENTIALS_EXPOSED`). Either one is a strong initial-access indicator. Find the attachment time in CloudTrail.

### 5.5 Identity persistence checklist

| Mechanism | CloudTrail evidence | Verify with |
|---|---|---|
| New IAM user, keys, or console password | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` | Credential report |
| Policy escalation | `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`, `AttachGroupPolicy`, `AddUserToGroup`, `CreatePolicyVersion`, `SetDefaultPolicyVersion` | `get-account-authorization-details` diff against IaC |
| Role trust backdoor | `UpdateAssumeRolePolicy`, `CreateRole` | Trust policies naming external accounts or `*` |
| Federation backdoor | `CreateSAMLProvider`, `UpdateSAMLProvider`, `CreateOpenIDConnectProvider`, `AddClientIDToOpenIDConnectProvider`, `UpdateOpenIDConnectProviderThumbprint` | Provider list and metadata |
| Identity Center | `CreateUser`, `CreateGroupMembership` (`identitystore` or `sso-directory` event sources), `CreateAccountAssignment`, `CreatePermissionSet`, `PutInlinePolicyToPermissionSet`, `AttachManagedPolicyToPermissionSet`, identity-source changes | Identity Center assignments and IdP |
| IAM Roles Anywhere | `CreateTrustAnchor`, `CreateProfile`, `UpdateTrustAnchor` | Attacker-controlled certificate authority (CA) |
| Attacker MFA | `CreateVirtualMFADevice`, `EnableMFADevice`, `DeactivateMFADevice`, `ResyncMFADevice` | MFA device serials and creation dates |
| Service-specific credentials | `CreateServiceSpecificCredential` (CodeCommit, Keyspaces, Bedrock API keys) | `list-service-specific-credentials` |
| SSH and signing material | `UploadSSHPublicKey`, `UploadSigningCertificate`, `ImportKeyPair`, `CreateKeyPair` | Key lists |
| Hybrid managed node | `CreateActivation` (SSM), then `RegisterManagedInstance` | `ssm describe-activations`, `mi-*` instances |
| Cognito | `CreateIdentityPool`, `SetIdentityPoolRoles` with unauthenticated roles | Identity pool role mappings |
| Long-lived sessions | `GetFederationToken` or `GetSessionToken` with up to 36-hour duration | `requestParameters.durationSeconds` |

---

## 6. Containment

### 6.1 Principles

- **Deny, don't delete.** Deactivate keys and attach deny policies. Deleting users, keys, roles, or instances destroys evidence such as creation dates, IDs, and attached policies, and can break the trail you need to follow.
- **Contain every credential path at once.** Revoking one key while the attacker holds `ASIA` sessions, an attacker-created user, and a backdoored role only alerts them. Build the full credential and persistence list first (Section 5), then contain in one coordinated window.
- **Expect the attacker to notice.** Watch CloudTrail during and after containment for `AccessDenied` from attacker IPs, which confirms containment, and for new principals, which means you missed a path.
- **Mind business impact.** Revoking sessions on a shared role affects every workload using it. Quarantine SCPs stop the whole account.
- **Log every IR action** with the case ID in tags and in session names.

### 6.2 IAM user (long-term credentials)

```bash
U=suspect-user; CASE=IR-2026-0042
aws iam get-login-profile --user-name "$U" > "${CASE}_${U}_login_profile.json" 2>&1   # record before change

# 1. Block everything immediately. This also neutralises GetSessionToken and GetFederationToken
#    credentials derived from this user, because those are evaluated against the user's policies at request time.
aws iam attach-user-policy --user-name "$U" --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# 2. Deactivate (do not delete) every access key
for K in $(aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
done

# 3. Remove console access, and deactivate service-specific credentials and SSH keys if present
aws iam delete-login-profile --user-name "$U"
aws iam tag-user --user-name "$U" --tags Key=ir-case,Value="$CASE" Key=ir-status,Value=contained
```

Also remove attacker-registered MFA devices, after recording their serials, and check for attacker-created users with the same procedure.

### 6.3 IAM roles and temporary credentials

Revoke all sessions issued before now. The console's **Revoke active sessions** button does the same thing.

```bash
ROLE=CompromisedRole
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > revoke.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["*"],
    "Resource": ["*"],
    "Condition": {"DateLessThan": {"aws:TokenIssueTime": "$NOW"}}
  }]
}
EOF
aws iam put-role-policy --role-name "$ROLE" --policy-name AWSRevokeOlderSessions --policy-document file://revoke.json
```

Keep these caveats in mind:

- **Legitimate sessions are revoked too.** Workloads using the role must obtain new credentials. EC2 and SDKs usually refresh automatically within minutes. Long-running jobs may fail.
- **The attacker can re-assume the role** if they still hold whatever let them assume it in the first place, such as a user key, a trust-policy backdoor, a compromised instance, or OIDC trust. Fix the source first, or at the same time.
- **Service-linked roles cannot be modified.** Contain the principal that uses them instead.
- **`AWSReservedSSO_*` roles** are managed by Identity Center and cannot be edited in IAM. Add the deny to the **permission set** inline policy, then re-provision. `put-inline-policy-to-permission-set` *replaces* the existing inline policy, so merge statements first.
- **Stolen EC2 instance-role credentials** (GuardDuty `InstanceCredentialExfiltration`): revoke the role sessions, and restrict where the role's credentials can be used. The `aws:ec2InstanceSourceVPC` and `aws:ec2InstanceSourcePrivateIPv4` condition keys support data-perimeter policies. Then fix the root cause, such as SSRF, IMDSv1, or host compromise.

### 6.4 IAM Identity Center and external IdP identities

1. Disable the user in the **source of truth**, either the external IdP (Entra ID, Okta) or the Identity Center directory, and revoke IdP sessions and refresh tokens.
2. In Identity Center, delete the user's **active sessions** and remove account assignments if needed.
3. Portal sessions and already-issued role credentials stay valid until expiry. Revoke them with `aws:TokenIssueTime` on the affected permission sets (Section 6.3).
4. Review the identity-source configuration, SCIM tokens, and any recently added users, groups, or assignments.

### 6.5 Root user

- In standalone accounts, secure the root email account first, then reset the root password, replace MFA with hardware MFA, and delete any root access keys.
- In organizations with **centralized root access management**, use `sts:AssumeRoot` from the management or delegated administrator account with the relevant task policy:
  - `IAMAuditRootUserCredentials` to inspect root credentials.
  - `IAMDeleteRootUserCredentials` to delete root credentials.
  - `S3UnlockBucketPolicy` and `SQSUnlockQueuePolicy` to recover resources whose policies deny all principals. Attackers use deny-all policies to lock owners out.
- Open an AWS Support case if you cannot regain control of root. Ownership verification is required.

### 6.6 EC2 instance

Follow this order to preserve evidence and contain the instance. Steps 1-4 do not touch the guest.

```bash
I=i-0123456789abcdef0; R=eu-central-1; CASE=IR-2026-0042

# 1. Tag and prevent accidental or automated destruction
aws ec2 create-tags --region $R --resources $I --tags Key=ir-case,Value=$CASE Key=ir-status,Value=preserving
aws ec2 modify-instance-attribute --region $R --instance-id $I --disable-api-termination
aws ec2 modify-instance-attribute --region $R --instance-id $I --instance-initiated-shutdown-behavior Value=stop
#    Keep EBS volumes if someone terminates the instance anyway (repeat for each device name)
aws ec2 modify-instance-attribute --region $R --instance-id $I \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"DeleteOnTermination":false}}]'

# 2. Remove it from Auto Scaling and load balancing so it is not replaced or terminated, and stops serving traffic
aws autoscaling describe-auto-scaling-instances --region $R --instance-ids $I
aws autoscaling detach-instances --region $R --auto-scaling-group-name <asg> --instance-ids $I \
  --no-should-decrement-desired-capacity
aws elbv2 deregister-targets --region $R --target-group-arn <tg-arn> --targets Id=$I

# 3. Capture metadata (Section 7.2) and start EBS snapshots (Section 7.4)

# 4. Network isolation. Use a pre-created SG with no inbound rules, and egress only to the
#    SSM interface endpoints' SG on tcp/443, so you can still acquire memory with Run Command.
#    modify-instance-attribute --groups affects the primary ENI only. Repeat for every ENI.
for ENI in $(aws ec2 describe-instances --region $R --instance-ids $I \
  --query 'Reservations[].Instances[].NetworkInterfaces[].NetworkInterfaceId' --output text); do
  aws ec2 modify-network-interface-attribute --region $R --network-interface-id "$ENI" --groups sg-0isolation0000000
done

# 5. After SSM-based collection (Sections 7.3 and 7.5), detach the instance profile (record the association first),
#    then revoke the role's sessions (Section 6.3). Without an instance profile, the SSM Agent goes offline
#    unless Default Host Management Configuration is enabled.
aws ec2 describe-iam-instance-profile-associations --region $R --filters Name=instance-id,Values=$I
aws ec2 disassociate-iam-instance-profile --region $R --association-id iip-assoc-0123456789abcdef0
```

> **Security groups do not cut existing connections.** Security groups are stateful. Changing them blocks *new* flows, but **tracked connections already established continue** until they time out. Only flows that were *untracked* (allowed by all-traffic `0.0.0.0/0` rules in both directions) are cut immediately. To terminate an active attacker session:
>
> - Add **network ACL** deny entries for the attacker's IP addresses. NACLs are stateless and take effect immediately, but they apply to the whole subnet.
> - Or terminate the session at the OS level **after** memory acquisition.
> - Or, as a last resort, stop the instance. This loses memory and instance-store data.

Additional EC2 considerations:

- **Instance store volumes** are lost when the instance stops, hibernates, or terminates. Image them live before any stop.
- Capture console output and a screenshot before and after isolation. They can show kernel messages and ransom notes without logging in.
- Do **not** log in interactively with a privileged account unless necessary. Prefer SSM Run Command with output to the evidence bucket.
- If SSM is unavailable and the host must stay up, coordinate EDR-based collection, such as an EDR live-response session.

### 6.7 S3 bucket

```bash
B=victim-bucket
aws s3api get-bucket-policy --bucket $B > ${B}_policy.json 2>&1
aws s3api get-bucket-acl --bucket $B > ${B}_acl.json
aws s3api get-public-access-block --bucket $B > ${B}_pab.json 2>&1
aws s3api get-bucket-replication --bucket $B > ${B}_replication.json 2>&1
aws s3api get-bucket-lifecycle-configuration --bucket $B > ${B}_lifecycle.json 2>&1
aws s3api get-bucket-encryption --bucket $B > ${B}_encryption.json 2>&1
aws s3api get-bucket-versioning --bucket $B > ${B}_versioning.json
aws s3api get-bucket-notification-configuration --bucket $B > ${B}_notifications.json
aws s3api list-bucket-inventory-configurations --bucket $B > ${B}_inventory.json
aws s3control list-access-points --account-id 111122223333 --bucket $B > ${B}_access_points.json

# Contain: block public access, then remove external grants in the bucket policy (keep a copy)
aws s3api put-public-access-block --bucket $B \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Also check for these attacker techniques:

- Malicious lifecycle rules that expire objects (ransomware).
- Replication or inventory configurations that deliver to external accounts.
- Suspended versioning.
- Presigned URLs, which stay valid until expiry or until the signing credential is revoked.

### 6.8 Containers and serverless

| Workload | Containment |
|---|---|
| **EKS pod or node** | Apply a deny-all `NetworkPolicy` to the pod, cordon the node, and remove or revoke service-account IAM bindings (Pod Identity association or IRSA trust). Capture first: see [Kubernetes DFIR](./GUIDE_Kubernetes_DFIR.md). |
| **ECS task (EC2 launch type)** | Isolate the ENI security group for awsvpc mode, or the host instance. Capture the container from the host. Revoke task-role sessions. |
| **ECS on Fargate** | No host access. Collect through ECS Exec if it is enabled. Isolate by changing the task ENI security group. Stopping the task destroys its ephemeral storage. |
| **Lambda** | Set reserved concurrency to `0` (`put-function-concurrency --reserved-concurrent-executions 0`) to stop invocations without deleting code. Download all versions first (Section 9.3). Revoke execution-role sessions. Remove malicious resource policies, function URLs, and event source mappings. |

### 6.9 Organization-level emergency containment

For an account-wide compromise, move the account into a pre-created **Quarantine OU** with an SCP that denies everything except the IR role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "QuarantineDenyAllExceptIR",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass"}
    }
  }]
}
```

```bash
aws organizations move-account --account-id 444455556666 \
  --source-parent-id ou-abcd-workloads --destination-parent-id ou-abcd-quarantine
```

SCPs apply to the member account's root and to every IAM principal, but not to service-linked roles or the management account. RCPs can additionally block external principals from reaching supported resources in the account. Expect a full production outage in the quarantined account.

### 6.10 AWS-provided containment runbooks

AWS Security Incident Response uses reversible SSM Automation runbooks. Review their parameters and behaviour before use:

| Runbook | Action |
|---|---|
| `AWSSupport-ContainEC2Instance` | Replaces the instance's security groups with a restrictive containment group. Existing tracked connections are **not** shut down. |
| `AWSSupport-ContainIAMPrincipal` | Attaches a deny-all policy to an IAM user or role, preserving the principal for forensics. |
| `AWSSupport-ContainS3Resource` | Modifies bucket or object access policies to deny external access. |

---

## 7. Evidence acquisition

### 7.1 Order of volatility in AWS

1. **Short-retention service data.** This includes CloudTrail Event history (90 days), GuardDuty findings (90 days), SSM command history (30 days), CloudWatch log groups with short retention, and log buckets with expiring lifecycle rules. Extend retention or copy these sources immediately.
2. **Ephemeral compute.** This includes Auto Scaling or Spot instances, Fargate tasks, Lambda environments, and Kubernetes pods. Prevent automated replacement.
3. **Guest memory** of running instances and containers.
4. **Instance store volumes.** They are lost on stop or terminate, and EBS snapshots do not cover them.
5. **Mutable configuration.** This includes IAM, security groups, bucket policies, and key policies. Capture it before you or the attacker change it.
6. **EBS volumes.** Snapshot them.
7. **Long-retention logs** in S3 and the Log Archive account.

### 7.2 Control-plane metadata for an instance

```bash
I=i-0123456789abcdef0; R=eu-central-1; CASE=IR-2026-0042
OUT="./$CASE/$I"; mkdir -p "$OUT"

aws ec2 describe-instances --region $R --instance-ids $I > "$OUT/describe-instances.json"
aws ec2 describe-instance-attribute --region $R --instance-id $I --attribute userData \
  --query UserData.Value --output text | base64 --decode > "$OUT/user-data.bin"   # may be gzip or MIME multipart
aws ec2 get-console-output --region $R --instance-id $I --latest --query Output --output text > "$OUT/console-output.txt"
aws ec2 get-console-screenshot --region $R --instance-id $I --query ImageData --output text | base64 --decode > "$OUT/console.jpg"
aws ec2 describe-network-interfaces --region $R --filters Name=attachment.instance-id,Values=$I > "$OUT/enis.json"
aws ec2 describe-volumes --region $R --filters Name=attachment.instance-id,Values=$I > "$OUT/volumes.json"
aws ec2 describe-security-groups --region $R \
  --group-ids $(jq -r '.Reservations[].Instances[].SecurityGroups[].GroupId' "$OUT/describe-instances.json") > "$OUT/security-groups.json"
aws ec2 describe-iam-instance-profile-associations --region $R --filters Name=instance-id,Values=$I > "$OUT/instance-profile.json"
aws ec2 describe-instance-attribute --region $R --instance-id $I --attribute disableApiTermination > "$OUT/termination-protection.json"
aws ssm describe-instance-information --region $R --filters Key=InstanceIds,Values=$I > "$OUT/ssm-instance.json"
aws ssm list-command-invocations --region $R --instance-id $I --details > "$OUT/ssm-commands.json"
aws ssm describe-sessions --region $R --state History --filters key=Target,value=$I > "$OUT/ssm-sessions.json"
aws configservice get-resource-config-history --region $R --resource-type AWS::EC2::Instance --resource-id $I \
  > "$OUT/config-history.json" 2>&1
shasum -a 256 "$OUT"/* > "$OUT/SHA256SUMS"
```

Also record the AMI (`describe-images`), launch template version, Auto Scaling group, VPC, subnet, route tables, and NACLs.

### 7.3 Memory acquisition

AWS provides no hypervisor-level memory dump. Use one of these methods:

| Method | When | Notes |
|---|---|---|
| **In-guest acquisition through SSM Run Command** | Default | Run tools from an attached IR volume. Write output to that volume, not to the suspect disk or over the suspect's network. |
| **EDR live response** | EDR deployed with memory-capture capability | Follow vendor procedure. Record the tool version. |
| **EC2 hibernation** | Only if the instance was launched with hibernation enabled | `stop-instances --hibernate` writes RAM to the encrypted root EBS volume. Snapshot the volume afterwards. This also stops the instance, so image instance-store data first. |

**Linux with AVML and an attached IR tools and evidence volume:**

```bash
# Create the volume in the instance's AZ from a pre-staged tools snapshot that is larger than the instance's RAM
AZ=$(aws ec2 describe-instances --region $R --instance-ids $I \
  --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
VOL=$(aws ec2 create-volume --region $R --availability-zone "$AZ" --snapshot-id snap-0irtools00000000 \
  --volume-type gp3 --tag-specifications "ResourceType=volume,Tags=[{Key=ir-case,Value=$CASE},{Key=purpose,Value=ir-evidence}]" \
  --query VolumeId --output text)
aws ec2 wait volume-available --region $R --volume-ids "$VOL"
aws ec2 attach-volume --region $R --volume-id "$VOL" --instance-id $I --device /dev/sdz

# On Nitro, the EBS volume ID appears in /dev/disk/by-id without the dash
VOLID=${VOL/-/}
aws ssm send-command --region $R --instance-ids $I --document-name AWS-RunShellScript \
  --comment "$CASE memory acquisition" --timeout-seconds 7200 \
  --parameters "commands=[\"mkdir -p /mnt/ir\",\"mount /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${VOLID} /mnt/ir\",\"/mnt/ir/bin/ir_memory.sh $CASE\"]"
```

Example `ir_memory.sh` stored on the tools snapshot:

```sh
#!/bin/sh
set -eu
CASE="$1"
IID=$(cat /sys/devices/virtual/dmi/id/board_asset_tag 2>/dev/null || hostname)   # Nitro exposes the instance ID here
OUT="/mnt/ir/evidence/$CASE/$IID"
mkdir -p "$OUT"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/memory_start_utc.txt"
uname -a > "$OUT/uname.txt"
/mnt/ir/bin/avml "$OUT/memory.lime"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/memory_end_utc.txt"
sha256sum "$OUT/memory.lime" > "$OUT/memory.lime.sha256"
sync
```

Then unmount (`umount /mnt/ir` through Run Command), detach the volume, snapshot it, and lock the snapshot.

> SSM `--output-s3-bucket-name` and CloudWatch output both upload **with the instance's own role**. Avoid them if that role is compromised or detached. Write results to the attached evidence volume instead.

**Windows:** Attach the evidence volume, bring it online (`Get-Disk`, `Set-Disk -IsOffline $false`, and assign a drive letter), and run WinPmem or a similar tool through `AWS-RunPowerShellScript`. Hash the result with `Get-FileHash -Algorithm SHA256`.

**Analysis notes:**

- Volatility 3 needs a symbol table (ISF) matching the exact Linux kernel. On Amazon Linux, install the matching `kernel-debuginfo` package on a forensic instance and build the ISF with `dwarf2json` from the `vmlinux` file.
- Record the kernel version (`uname -r`) during acquisition.
- AVML output compressed with `--compress` must be converted with `avml-convert` before analysis.

### 7.4 EBS snapshots and disk images

```bash
# 1. Crash-consistent snapshot set of all attached volumes
aws ec2 create-snapshots --region $R --instance-specification InstanceId=$I,ExcludeBootVolume=false \
  --description "$CASE $I" --copy-tags-from-source volume \
  --tag-specifications "ResourceType=snapshot,Tags=[{Key=ir-case,Value=$CASE},{Key=source-instance,Value=$I}]"
aws ec2 wait snapshot-completed --region $R --snapshot-ids snap-0aaaaaaaaaaaaaaaa

# 2. Lock against deletion. GOVERNANCE can be lifted by authorized users. COMPLIANCE cannot after its cool-off period.
aws ec2 lock-snapshot --region $R --snapshot-id snap-0aaaaaaaaaaaaaaaa --lock-mode governance --lock-duration 365
```

**Move evidence to the Forensics account (999988887777):**

```bash
# Snapshots encrypted with the AWS managed key (aws/ebs) cannot be shared.
# Re-encrypt with a customer managed key whose key policy allows the forensic account.
aws ec2 copy-snapshot --region $R --source-region $R --source-snapshot-id snap-0aaaaaaaaaaaaaaaa \
  --encrypted --kms-key-id arn:aws:kms:$R:111122223333:key/<ir-share-cmk> --description "$CASE share copy"
aws ec2 modify-snapshot-attribute --region $R --snapshot-id snap-0bbbbbbbbbbbbbbbb \
  --attribute createVolumePermission --operation-type add --user-ids 999988887777

# In the Forensics account: take ownership with your own key, then create and attach a volume to the workstation
aws ec2 copy-snapshot --region $R --source-region $R --source-snapshot-id snap-0bbbbbbbbbbbbbbbb \
  --encrypted --kms-key-id arn:aws:kms:$R:999988887777:key/<forensic-cmk> --description "$CASE evidence"
aws ec2 create-volume --region $R --availability-zone ${R}a --snapshot-id snap-0cccccccccccccccc --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[{Key=ir-case,Value=$CASE}]"
aws ec2 attach-volume --region $R --volume-id vol-0dddddddddddddddd --instance-id i-0forensicws000000 --device /dev/sdf
```

The share key policy must allow the forensic account `kms:DescribeKey`, `kms:CreateGrant`, `kms:Decrypt`, `kms:ReEncrypt*`, and `kms:GenerateDataKey*`. The `ModifySnapshotAttribute` call you make here looks identical to attacker exfiltration in CloudTrail, so log it in the case file.

**On the forensic workstation:**

```bash
lsblk -o NAME,SIZE,SERIAL,FSTYPE,LABEL,MOUNTPOINT          # NVMe SERIAL "vol0ddd..." identifies the EBS volume
for p in /dev/nvme1n1*; do sudo blockdev --setro "$p"; done  # read-only at the block layer, disk and partitions

# Full image with hashing (also forces lazy-loaded snapshot blocks to download)
sudo dc3dd if=/dev/nvme1n1 of=/evidence/$CASE/vol-0abc.raw hash=sha256 log=/evidence/$CASE/vol-0abc.dc3dd.log
# or: sudo ewfacquire -t /evidence/$CASE/vol-0abc /dev/nvme1n1

# Read-only triage mounts
sudo mount -o ro,noload,noexec,nodev /dev/nvme1n1p1 /mnt/case             # ext4: noload skips journal replay
sudo mount -o ro,norecovery,nouuid,noexec,nodev /dev/nvme1n1p1 /mnt/case  # XFS: nouuid avoids clashing with the workstation's AMI
# LVM with duplicate VG names (same AMI lineage): vgimportclone before activation
```

**Alternatives:**

- `coldsnap download snap-... disk.img` reads a snapshot through the EBS direct APIs without creating a volume. It needs `ebs:ListSnapshotBlocks`, `ebs:GetSnapshotBlock`, and KMS decrypt permissions.
- The AWS **Automated Forensic Orchestrator for Amazon EC2** solution and Google's **cloud-forensics-utils** automate snapshot, copy, and attach workflows.
- **Instance store:** image it live with `dc3dd` to the attached evidence volume through Run Command, before any stop.

### 7.5 Live triage collection through SSM

Run triage collectors from the IR volume and write to the IR volume:

```bash
aws ssm send-command --region $R --instance-ids $I --document-name AWS-RunShellScript \
  --comment "$CASE UAC triage" --timeout-seconds 7200 \
  --parameters 'commands=["/mnt/ir/bin/uac/uac -p ir_triage /mnt/ir/evidence/"]'
```

On Windows, use a Velociraptor offline collector or KAPE from the attached volume through `AWS-RunPowerShellScript`. See [Linux DFIR](./GUIDE_Linux_DFIR.md) and [Windows DFIR](./GUIDE_Windows_DFIR.md) for what to collect and how to interpret it.

SSM leaves its own artefacts on the host: agent logs, orchestration directories, and the `ssm-user` account for Session Manager. Expect them, and document that they came from IR.

### 7.6 Preserve logs and service data

```bash
EVID=s3://acme-ir-evidence-999988887777-eu-central-1/$CASE
# CloudTrail logs and digests for the window (validate-logs first, Section 4.1)
aws s3 sync s3://org-trail-bucket/AWSLogs/o-abc123example/444455556666/CloudTrail/ "$EVID/cloudtrail/444455556666/" \
  --exclude "*" --include "*/2026/10/*"
aws s3 sync s3://org-trail-bucket/AWSLogs/o-abc123example/444455556666/CloudTrail-Digest/ "$EVID/cloudtrail-digest/444455556666/" \
  --exclude "*" --include "*/2026/10/*"

# Stop CloudWatch log groups from expiring during the case
aws logs put-retention-policy --log-group-name /aws/eks/prod/cluster --retention-in-days 3653
aws logs put-retention-policy --log-group-name /aws/lambda/suspicious-fn --retention-in-days 3653
```

Also preserve these sources:

- GuardDuty findings JSON (Section 4.9) and Detective exports.
- AWS Config snapshots and history.
- VPC Flow Logs and Resolver query logs.
- ELB, CloudFront, and WAF logs.
- Security Hub findings.
- Organizations SCP, RCP, and OU state.
- IAM authorization details (Section 5.4).
- Billing and Cost Explorer data for the window.

Suspend or lengthen lifecycle rules on log buckets for the case duration.

### 7.7 Hashing and evidence storage

- Hash at acquisition (`sha256sum` or `shasum -a 256`) and record the hash in the case log.
- Upload with `aws s3 cp <file> <s3-uri> --checksum-algorithm SHA256` so S3 verifies integrity in transit. For multipart uploads, S3 stores a composite checksum-of-checksums, so keep your own full-file SHA-256 manifest.
- Store evidence in the Object Lock bucket with SSE-KMS using the forensic CMK, plus versioning and access logging. Restrict reads to named analysts.
- Keep snapshots in the Forensics account, locked and tagged with case ID, source account, source resource, and acquisition time.

---

## 8. EC2 host artefacts specific to AWS

Standard OS forensics applies. See [Linux DFIR](./GUIDE_Linux_DFIR.md) and [Windows DFIR](./GUIDE_Windows_DFIR.md). The artefacts below are specific to AWS.

### 8.1 Linux

| Artefact | Location | Value |
|---|---|---|
| cloud-init logs | `/var/log/cloud-init.log`, `/var/log/cloud-init-output.log` | Boot-time execution of user data, including its output |
| User data as delivered | `/var/lib/cloud/instances/<instance-id>/user-data.txt`, `.../scripts/` | Compare with `describe-instance-attribute userData`. Attackers modify user data for persistence on next boot. |
| SSM Agent logs | `/var/log/amazon/ssm/amazon-ssm-agent.log`, `errors.log` | Commands, sessions, and agent registration |
| SSM command payloads and output | `/var/lib/amazon/ssm/<instance-id>/document/orchestration/<command-id>/` | Exact scripts run through Run Command, plus stdout and stderr |
| Session Manager | `ssm-user` in `/etc/passwd` and `/etc/sudoers.d/ssm-agent-users` | Evidence that Session Manager was used. Correlate with `StartSession` events. |
| EC2 Instance Connect | `/var/log/secure` or `/var/log/auth.log` lines showing `AuthorizedKeysCommand` (`eic_run_authorized_keys`) | Correlate with `SendSSHPublicKey` events (`ec2-instance-connect.amazonaws.com`) |
| AWS CLI and SDK credentials | `~/.aws/credentials`, `~/.aws/config` | Stored long-term keys, profiles, and role ARNs |
| Cached credentials | `~/.aws/cli/cache/*.json`, `~/.aws/sso/cache/*.json` | Temporary credentials and Identity Center tokens, sometimes still valid |
| AWS CLI history | `~/.aws/cli/history/history.db` (only if `cli_history = enabled`) | SQLite database of CLI commands and responses |
| Environment and app config | `/etc/environment`, systemd unit `Environment=`, `.env` files, container env | Embedded keys. Search for `AKIA` and `ASIA` patterns. |
| Shell history | `~/.bash_history`, `~/.zsh_history` | `curl http://169.254.169.254/...`, `aws sts get-caller-identity`, and `aws s3 cp` commands |
| Journal (Amazon Linux 2023) | `/var/log/journal/` | AL2023 uses journald and does not install rsyslog by default, so `/var/log/messages` may not exist |

### 8.2 Windows

| Artefact | Location | Value |
|---|---|---|
| SSM Agent logs | `C:\ProgramData\Amazon\SSM\Logs\amazon-ssm-agent.log`, `errors.log` | Run Command and Session Manager activity |
| SSM command payloads | `C:\ProgramData\Amazon\SSM\InstanceData\<instance-id>\document\orchestration\<command-id>\` | Exact scripts and output |
| EC2Launch v2 | `C:\ProgramData\Amazon\EC2Launch\log\` (`agent.log` and others) | User-data execution and launch tasks |
| EC2Launch v1 / EC2Config (legacy) | `C:\ProgramData\Amazon\EC2-Windows\Launch\Log\`, `C:\Program Files\Amazon\Ec2ConfigService\Logs\` | Older AMIs |
| Session Manager user | Local account `ssm-user` | Interactive SSM sessions |
| AWS credentials | `%USERPROFILE%\.aws\credentials`, `config`, and `cli\cache` | Stored and cached keys |
| Administrator password retrieval | CloudTrail `GetPasswordData` | Someone retrieved the encrypted initial Administrator password |

### 8.3 IMDS and instance credentials

- **IMDS requests are not logged by AWS.** Evidence of IMDS use comes from:
  - Shell history, web server logs (SSRF payloads containing `169.254.169.254` or the IPv6 IMDS address `fd00:ec2::254`), and EDR or process network telemetry.
  - The `ec2RoleDelivery` field in CloudTrail (`1.0` means the credentials came from IMDSv1).
  - GuardDuty `InstanceCredentialExfiltration` findings.
- To capture IMDS calls going forward, AWS publishes **aws-imds-packet-analyzer**, an eBPF-based tool that attributes IMDS calls to processes.
- Instance-role sessions use the instance ID as the session name. Any use of `...:i-0123...` credentials from an IP address outside your VPC, NAT, or endpoints is a strong theft indicator.
- Check `HttpTokens` (`required` means IMDSv2 only) and `HttpPutResponseHopLimit` in `describe-instances`. A hop limit greater than 1 lets containers on the host reach IMDS.

---

## 9. Service-specific investigations

### 9.1 Amazon S3

**Questions to answer:** What was read, written, or deleted, by whom, from where, and how much? Were policies changed to allow access? Is the data recoverable?

| Activity | Evidence |
|---|---|
| Discovery | `ListBuckets`, `GetBucketAcl`, `GetBucketPolicy`, `GetBucketLocation`, and `ListObjects` / `ListObjectsV2` (data events) |
| Exfiltration | `GetObject` volume (Q8), `PutBucketReplication` to external buckets, `PutBucketPolicy` or ACLs granting external principals, `PutBucketInventoryConfiguration` to external destinations, presigned URLs (`AuthenticationMethod=QueryString`), and `CopyObject` to external buckets |
| Exposure | `DeletePublicAccessBlock`, `PutPublicAccessBlock` with false values, `PutBucketAcl` with `AllUsers`, and `PutBucketPolicy` with `"Principal":"*"` |
| Ransomware and destruction | Mass `DeleteObject` / `DeleteObjects`, `PutBucketVersioning` (Suspended), `PutBucketLifecycleConfiguration` with short expirations, re-encryption with **SSE-C** (attacker-held keys, `additionalEventData.SSEApplied = SSE_C`), KMS key policy changes or `ScheduleKeyDeletion` on SSE-KMS keys, and ransom-note objects |

**Recovery:**

```bash
# Deleted objects in versioned buckets: list versions and delete markers
aws s3api list-object-versions --bucket victim-bucket --prefix data/ > versions.json
# Restore by copying a prior version over the current key, or by deleting the delete marker
aws s3api delete-object --bucket victim-bucket --key data/file.csv --version-id <delete-marker-version-id>
```

- Since April 2026, Amazon S3 disables SSE-C by default for new buckets, and for existing buckets in accounts that have no SSE-C objects. Check `get-bucket-encryption` for `BlockedEncryptionTypes`. Unexpected SSE-C enablement is itself an indicator.
- Objects encrypted with an attacker-supplied SSE-C key cannot be decrypted by AWS. Recovery depends on earlier versions, replication, or AWS Backup recovery points.
- S3 Object Lock and AWS Backup logically air-gapped vaults are the strongest pre-incident protections.

### 9.2 KMS, Secrets Manager, and Parameter Store

| Activity | Events |
|---|---|
| Secret access | `GetSecretValue`, `BatchGetSecretValue`, `ListSecrets`, `DescribeSecret` |
| Parameter access | `GetParameter`, `GetParameters`, `GetParametersByPath` (check `requestParameters.withDecryption`) |
| Decryption | `Decrypt`, `GenerateDataKey`. The `encryptionContext` often names the secret, parameter, bucket, or volume. |
| Key tampering | `PutKeyPolicy`, `CreateGrant`, `DisableKey`, `ScheduleKeyDeletion` (cancel with `CancelKeyDeletion` within the 7-30 day window), `ImportKeyMaterial`, `DeleteImportedKeyMaterial` |
| Secret policy | `PutResourcePolicy` on secrets that grant external accounts |

Treat every secret the attacker could read as compromised, whether or not you can prove it was read. Rotate it and find where it is used outside AWS.

### 9.3 AWS Lambda

```bash
F=suspicious-fn; R=eu-central-1
aws lambda get-function-configuration --region $R --function-name $F > ${F}_config.json   # env vars, role, layers, VPC
aws lambda list-versions-by-function --region $R --function-name $F > ${F}_versions.json
aws lambda list-aliases --region $R --function-name $F > ${F}_aliases.json
aws lambda get-policy --region $R --function-name $F > ${F}_resource_policy.json 2>&1
aws lambda list-function-url-configs --region $R --function-name $F > ${F}_urls.json
aws lambda list-event-source-mappings --region $R --function-name $F > ${F}_event_sources.json
aws events list-rule-names-by-target --region $R --target-arn arn:aws:lambda:$R:111122223333:function:$F

# Download code for every version. Code.Location is a short-lived presigned URL.
for V in $(jq -r '.Versions[].Version' ${F}_versions.json); do
  curl -sS -o "${F}_${V}.zip" "$(aws lambda get-function --region $R --function-name $F --qualifier $V --query Code.Location --output text)"
done
shasum -a 256 ${F}_*.zip > ${F}_SHA256SUMS
```

- For container-image functions, `Code.ImageUri` points to ECR. Pull and preserve the image digest.
- Attacker indicators include:
  - `CreateFunction20150331`, `UpdateFunctionCode20150331v2`, `UpdateFunctionConfiguration20150331v2` (new layers or environment variables), and `AddPermission20150331v2` (cross-account or public invoke).
  - `CreateFunctionUrlConfig` with `AuthType NONE`.
  - EventBridge `PutRule` / `PutTargets` for scheduled persistence.
- Lambda credentials live in environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SESSION_TOKEN`). Code injection or SSRF in a function leaks them. Session names equal the function name.

### 9.4 Amazon EKS

```bash
C=prod; R=eu-central-1
aws eks describe-cluster --region $R --name $C > ${C}_cluster.json        # endpoint access, logging, OIDC issuer
aws eks list-access-entries --region $R --cluster-name $C > ${C}_access_entries.json
aws eks list-pod-identity-associations --region $R --cluster-name $C > ${C}_pod_identity.json
kubectl -n kube-system get configmap aws-auth -o yaml > ${C}_aws-auth.yaml 2>&1   # legacy mapping, if still used
```

- **CloudTrail:** `CreateAccessEntry`, `AssociateAccessPolicy`, `UpdateClusterConfig` (logging or endpoint changes), `CreatePodIdentityAssociation`, `AssumeRoleForPodIdentity` (`eks-auth.amazonaws.com`), and `AssumeRoleWithWebIdentity` from the cluster OIDC provider (IRSA).
- **Kubernetes audit (CloudWatch):** create, patch, or update on `clusterrolebindings`, `rolebindings`, and `configmaps/aws-auth`; `pods/exec`; secret reads; privileged or hostPath pods; and anonymous requests.

```text
fields @timestamp, user.username, verb, objectRef.resource, objectRef.subresource, objectRef.namespace, objectRef.name, sourceIPs.0
| filter @logStream like /kube-apiserver-audit/
| filter verb in ["create","patch","update","delete"] or objectRef.subresource = "exec"
| sort @timestamp asc
```

For node, pod, and container acquisition, see [Kubernetes DFIR](./GUIDE_Kubernetes_DFIR.md) and [Container DFIR](./GUIDE_Container_DFIR.md).

### 9.5 Amazon ECS and AWS Fargate

- Use `describe-task-definition` to review every revision for image, command, environment, secrets, and task role. `RegisterTaskDefinition` with a new image or environment is a persistence and backdoor pattern.
- `ExecuteCommand` in CloudTrail records ECS Exec use. Session content is logged only if ECS Exec logging to S3 or CloudWatch was configured.
- Task-role credentials are served from `169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`. Theft looks like the task role being used from outside the task's network.
- On Fargate there is no host or disk to snapshot. Rely on GuardDuty Runtime Monitoring, application logs, VPC Flow Logs (`ecs-*` fields), and ECS Exec collection before the task stops.

### 9.6 RDS, DynamoDB, and snapshot sharing

| Activity | Events |
|---|---|
| Snapshot exfiltration (EBS, AMI, RDS) | `ModifySnapshotAttribute` (`createVolumePermission`), `ModifyImageAttribute` (`launchPermission`), `ModifyDBSnapshotAttribute`, `ModifyDBClusterSnapshotAttribute` (`restore`), `CopySnapshot`, `CopyDBSnapshot` |
| Database takeover | `ModifyDBInstance` or `ModifyDBCluster` with `masterUserPassword` (value redacted), `PubliclyAccessible=true`, or security-group changes |
| Destruction | `DeleteDBInstance` (check `skipFinalSnapshot`), `DeleteDBSnapshot`, `DeleteDBCluster` |
| DynamoDB export | `ExportTableToPointInTime` (check `s3BucketOwner` for external accounts), plus data events for item access if enabled |

```bash
aws ec2 describe-snapshot-attribute --snapshot-id snap-... --attribute createVolumePermission
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <snapshot-id>
```

### 9.7 Amazon Bedrock (LLMjacking)

Stolen credentials are commonly used to run expensive foundation-model inference.

| Stage | Events |
|---|---|
| Reconnaissance | `ListFoundationModels`, `GetFoundationModelAvailability`, `GetModelInvocationLoggingConfiguration`, `ListFoundationModelAgreementOffers` |
| Enablement | `PutUseCaseForModelAccess`, `CreateFoundationModelAgreement`, `PutFoundationModelEntitlement`, AWS Marketplace subscriptions |
| Abuse | `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream`. These are management events, so they are logged by default without prompt content. |
| Evasion | `DeleteModelInvocationLoggingConfiguration` |
| Persistence | `CreateServiceSpecificCredential` for Bedrock API keys |

Prompt and response content exists only if model invocation logging was enabled. Use Cost Explorer and CloudWatch Bedrock metrics (`Invocations`, `InputTokenCount`, `OutputTokenCount`) to quantify the abuse.

### 9.8 Amazon SES and email abuse

- **Reconnaissance and enablement:** `GetSendQuota`, `ListIdentities`, `GetAccountSendingEnabled`, `UpdateAccountSendingEnabled`, `VerifyEmailIdentity` / `CreateEmailIdentity`, and `PutAccountDetails` (production-access request).
- **SMTP credentials:** SES SMTP credentials are derived from IAM user access keys. Look for `CreateUser` and `CreateAccessKey` with `ses:SendRawEmail` permissions.
- **Sending volume:** Use SES event publishing and CloudWatch SES metrics. Since 2025, SES sending API calls can also be captured as CloudTrail data events if you enabled them.

### 9.9 Organizations, account, and billing

- **Organization changes:** `LeaveOrganization`, `CreateAccount`, `InviteAccountToOrganization`, and `DetachPolicy` / `UpdatePolicy` / `DeletePolicy` / `DisablePolicyType` (weakening SCPs or RCPs).
- **Account contacts and regions:** `PutAlternateContact`, `DeleteAlternateContact`, and `PutContactInformation` (hijacking security notifications), plus `EnableRegion` (opening unmonitored regions).
- **Cost signals:** Cost Anomaly Detection alerts, AWS Budgets, and Cost Explorer grouped by region, service, and usage type. GPU instance types in unused regions are the classic cryptomining signature.
- **AWS notifications:** Abuse reports from AWS Trust & Safety and AWS Health events in the account are evidence. Preserve them and reply within the deadlines AWS gives.

---

## 10. Timeline building

| Source | Time field | Format and caveat |
|---|---|---|
| CloudTrail | `eventTime` | ISO 8601 UTC. Request receipt time. Delivery lags by minutes. |
| GuardDuty | `service.eventFirstSeen`, `service.eventLastSeen`, `createdAt`, `updatedAt` | ISO 8601 UTC. Aggregated findings span ranges. |
| VPC Flow Logs | `start`, `end` | Unix epoch seconds, as aggregation-window boundaries |
| Route 53 Resolver | `query_timestamp` | ISO 8601 UTC |
| ELB access logs | Request timestamp | ISO 8601 UTC |
| S3 server access logs | `[dd/MMM/yyyy:HH:mm:ss +0000]` | Best-effort delivery |
| EKS audit | `requestReceivedTimestamp`, `stageTimestamp` | RFC 3339 UTC |
| AWS Config | `configurationItemCaptureTime` | When Config observed the change, not exactly when it happened |
| Host artefacts | Varies | Check host time zone and clock drift. Amazon Time Sync is usually accurate. |

Recommended approach:

1. Normalize all sources to UTC ISO 8601 and load them into a single store such as Timesketch, Elastic or SOF-ELK, Splunk, or DuckDB.
2. Build an **identity spine** first: the chain of credentials (`AKIA` to `ASIA` to cross-account `ASIA`) with first-seen and last-seen times and source IPs.
3. Hang network, DNS, host, and data-access events off that spine using resource IDs, IPs, and session names.
4. Mark IR actions explicitly using your IR principal and session names so they can be filtered out.
5. Record each conclusion with its supporting event IDs (`eventID`, finding ID, or log line).

---

## 11. Common attacker TTPs and evidence

| Tactic | Technique (examples) | CloudTrail and other evidence |
|---|---|---|
| Initial access | Leaked access keys (Git, CI logs, images); phished SSO or IdP session; SSRF to IMDSv1; vulnerable public app; CI/CD OIDC trust misconfiguration; compromised third-party SaaS with cross-account role | First use of the key from a new IP or user agent; `AWSCompromisedKeyQuarantine*` attachment; `ec2RoleDelivery: 1.0`; `AssumeRoleWithWebIdentity` from unexpected repositories or `sub` claims; WAF and ALB logs |
| Discovery | Identity and resource enumeration | `GetCallerIdentity`, `ListUsers`, `ListRoles`, `GetAccountAuthorizationDetails`, `ListBuckets`, `DescribeInstances`, `DescribeRegions`, `ListSecrets`, `GetServiceQuota` (GPU limits); `AccessDenied` bursts (Q4) |
| Privilege escalation | Policy manipulation and `iam:PassRole` abuse | `CreatePolicyVersion` with `setAsDefault`, `Attach*Policy`, `Put*Policy`, `UpdateAssumeRolePolicy`, `UpdateLoginProfile` or `CreateAccessKey` on another user, `PassRole` with `RunInstances`, `CreateFunction`, or `UpdateFunctionConfiguration` |
| Persistence | New identities, backdoored trust, scheduled compute | Section 5.5; `CreateFunction*` with EventBridge `PutRule`; `ModifyInstanceAttribute` (`userData`); SSM `CreateAssociation` or `CreateActivation`; `CreateLaunchTemplateVersion` |
| Defense evasion | Disable or blind telemetry; suppress findings; use unmonitored regions | Q5 events; GuardDuty `CreateFilter` (auto-archive) or `CreateIPSet` (trusted IPs); Security Hub `CreateAutomationRule` or `BatchUpdateFindings`; `EnableRegion`; `PutEventSelectors` excluding data events |
| Credential access | Secrets, parameters, instance and task credentials, CloudFormation and user-data secrets | `GetSecretValue`, `GetParameter*` with `withDecryption`, `GetPasswordData`, `DescribeInstanceAttribute` (`userData`), `GetTemplate`, `DescribeStacks`, `BatchGetProjects` (CodeBuild environment variables), `GetFunctionConfiguration` |
| Lateral movement | Cross-account roles, SSM, Instance Connect, serial console, console federation | `AssumeRole` with `sharedEventID`; `SendCommand`, `StartSession`; `SendSSHPublicKey`, `SendSerialConsoleSSHPublicKey`; `GetSigninToken` |
| Collection and exfiltration | S3 download or replication, snapshot sharing, data exports | Q8; `PutBucketReplication`; `ModifySnapshotAttribute`, `ModifyImageAttribute`, `ModifyDB*SnapshotAttribute`; `ExportTableToPointInTime`; CloudWatch Logs `CreateExportTask`; high egress in Flow Logs |
| Impact: resource hijacking | Cryptomining, LLMjacking, spam | `RunInstances` with GPU types across regions, `ModifyInstanceAttribute` `disableApiTermination` (anti-cleanup); ECS, Fargate, Batch, SageMaker, or App Runner resources; Bedrock `InvokeModel` spikes; SES enablement |
| Impact: data destruction and ransom | S3 SSE-C re-encryption, lifecycle wipe, deletion, KMS key deletion | `CopyObject` or `PutObject` with SSE-C, `PutBucketLifecycleConfiguration`, `DeleteObjects`, `PutBucketVersioning`, `ScheduleKeyDeletion`, `DeleteDBSnapshot`; ransom notes |
| Impact: lockout | Deny-all resource policies, root takeover, contact hijack | `PutBucketPolicy` or `PutKeyPolicy` denying owners, `UpdateLoginProfile`, `EnableMFADevice` on root, `PutAlternateContact`, `LeaveOrganization` |

Test detections and this playbook with adversary emulation tools such as **Stratus Red Team** in a sandbox account.

---

## 12. Eradication and recovery

1. **Remove every persistence item** found in Sections 5.5, 9, and 11. Diff IAM, resource policies, and compute against IaC and AWS Config history. Do not rely on memory or on the attacker's visible actions alone.
2. **Rotate everything the attacker could reach,** not just what you saw them use:
   - IAM keys and passwords.
   - Secrets Manager and Parameter Store values.
   - Database credentials.
   - Third-party API tokens in environment variables or code.
   - CI/CD and Git tokens.
   - SSH keys and SES SMTP credentials.
3. **Rebuild compromised compute** from known-good AMIs, images, and IaC. Do not clean infected instances or containers in place. Rebuild Lambda functions from source control.
4. **Restore data** from versions, replicas, or AWS Backup. Scan recovery points with GuardDuty Malware Protection for AWS Backup before restoring.
5. **Sweep all regions and accounts** in scope for attacker-created resources (instances, functions, users, roles, keys, snapshots, AMIs, and endpoints). Then decide whether to delete or retain them as evidence.
6. **Close the initial-access vector.** For example, remove leaked keys from Git history, fix SSRF, enforce IMDSv2, tighten OIDC `sub` conditions, enforce phishing-resistant MFA at the IdP, or patch the exploited application.
7. **Lift containment gradually** (quarantine SCP, isolation SGs, session revocations) while monitoring for re-entry.
8. **Engage AWS** through Support or AWS Security Incident Response for help, abuse-report closure, and billing concessions for fraudulent usage, where applicable.

**Hardening that most often prevents a repeat incident:**

- Remove IAM users and long-term keys in favour of Identity Center and roles.
- Enforce IMDSv2 organization-wide.
- Use centralized root access management.
- Apply telemetry-protection SCPs and data-perimeter RCPs and SCPs.
- Enable GuardDuty with all relevant protection plans, and S3 data events for crown-jewel buckets.
- Turn on block public access for S3, snapshots, and AMIs.
- Use Object Lock or air-gapped backups.
- Alert on Q5-class events.

---

## 13. Recommended tooling summary

| Tool | Purpose | Link |
|---|---|---|
| AWS CLI v2 / `jq` | Collection, scripting, and parsing | https://docs.aws.amazon.com/cli/ |
| Amazon Athena | SQL over CloudTrail, Flow Logs, and Security Lake in S3 | https://docs.aws.amazon.com/athena/ |
| Amazon Detective | Behavior-graph investigation and pivoting | https://docs.aws.amazon.com/detective/ |
| DuckDB | Fast local SQL over exported JSON or Parquet logs | https://duckdb.org/ |
| Automated Forensic Orchestrator for Amazon EC2 | AWS solution for automated isolation, snapshot, and memory capture | https://aws.amazon.com/solutions/implementations/automated-forensic-orchestrator-for-amazon-ec2/ |
| cloud-forensics-utils | Python library for snapshot, copy, and attach workflows across clouds | https://github.com/google/cloud-forensics-utils |
| coldsnap | Download or upload EBS snapshots through the EBS direct APIs | https://github.com/awslabs/coldsnap |
| AVML | Static Linux memory acquisition | https://github.com/microsoft/avml |
| LiME | Linux memory acquisition kernel module | https://github.com/504ensicsLabs/LiME |
| WinPmem | Windows memory acquisition | https://github.com/Velocidex/WinPmem |
| Volatility 3 | Memory analysis | https://github.com/volatilityfoundation/volatility3 |
| UAC | Unix-like triage collection | https://github.com/tclahr/uac |
| Velociraptor | Endpoint collection and hunting (Windows, Linux, macOS) | https://docs.velociraptor.app/ |
| Plaso / Timesketch | Super-timelines and collaborative timeline analysis | https://github.com/log2timeline/plaso, https://timesketch.org/ |
| SOF-ELK | Pre-built ELK with AWS log parsers (FOR509) | https://github.com/philhagen/sof-elk |
| Invictus-AWS | AWS log and configuration acquisition for IR | https://github.com/invictus-ir/Invictus-AWS |
| aws-imds-packet-analyzer | Attribute IMDS calls to processes | https://github.com/aws/aws-imds-packet-analyzer |
| PMapper | IAM privilege-escalation path analysis | https://github.com/nccgroup/PMapper |
| Prowler | Posture assessment and post-incident hardening checks | https://github.com/prowler-cloud/prowler |
| Stratus Red Team | Cloud adversary emulation for detection testing | https://github.com/DataDog/stratus-red-team |
| TrailDiscover | Catalogue of security-relevant CloudTrail events with context | https://traildiscover.cloud/ |

---

## 14. Repeatable AWS IR checklist

1. **Open the case.** Assign a case ID, IR principal, session naming, case log, and evidence bucket. Confirm authorization and the accounts in scope.
2. **Orient.** Run `get-caller-identity`, check organization structure and enabled regions, trail status and selectors, GuardDuty status, filters, and IP sets.
3. **Freeze retention.** Extend CloudWatch log retention, suspend log-bucket lifecycle expiry, export GuardDuty findings, and validate and copy CloudTrail logs.
4. **Scope the identity.** Identify the key or principal, its owner account, its sessions (Q1-Q3), attacker IPs and user agents, and all accounts and regions touched.
5. **Inventory persistence.** Work through the Section 5.5 checklist, then resource policies, compute, Lambda, SSM, and Identity Center.
6. **Preserve resources.** For each instance, tag it, enable termination protection, capture metadata, snapshot and lock volumes, capture memory, run triage, and image instance store. Preserve Lambda code, container images, and EKS audit logs.
7. **Contain in one coordinated window.** Apply user denies, key deactivation, role session revocation, Identity Center and IdP actions, isolation SGs (plus NACLs for live sessions), bucket lockdown, and the quarantine SCP if needed.
8. **Verify containment.** Watch for `AccessDenied` from attacker IPs, no new principals, no new resources, and no outbound flows to C2.
9. **Analyze.** Build the timeline around the identity spine. Run host forensics on copies in the Forensics account. Determine data access and exfiltration volumes.
10. **Eradicate and recover.** Remove persistence, rotate credentials, rebuild, restore, and close the initial-access vector.
11. **Report.** Cover the root cause, timeline, data impact, regulatory assessment, lessons learned, and detection and guardrail improvements.

### Minimum evidence package per incident

- CloudTrail logs and digests for all in-scope accounts and regions for the window, plus `validate-logs` output.
- GuardDuty findings JSON, Security Hub findings, and Detective notes.
- IAM authorization details, credential reports, Identity Center assignments, and SCPs and RCPs.
- VPC Flow Logs and Resolver query logs for affected VPCs.
- For each affected instance: metadata JSON, console output and screenshot, user data, SSM history, locked EBS snapshots, memory image, and triage collection, all with hashes.
- Service-specific exports: Lambda code and configuration, ECS task definitions, EKS audit logs, S3 bucket configurations, and KMS key policies.
- A case log of every IR action with its UTC time and IR principal.

---

## 15. Common analytical mistakes

- **Searching only one region, or only Event history.** Attackers favour regions you do not use. Event history holds only 90 days of management events.
- **Treating missing data events as no access.** If S3 or DynamoDB data events were off, you cannot prove a negative. Say so in the report.
- **Deleting instead of disabling.** Deleting keys, users, roles, or instances destroys evidence and IDs. Deactivate, deny, and tag instead.
- **Deactivating the `AKIA` key and stopping there.** Sessions minted from it, other attacker-created credentials, and backdoored trust relationships remain active.
- **Assuming a security-group swap kills live sessions.** Tracked connections persist. Use NACLs or OS-level action.
- **Stopping or terminating instances too early.** Memory and instance-store data are lost, and `DeleteOnTermination` volumes disappear.
- **Collecting through the compromised role.** Uploading evidence or running SSM output delivery with the suspect instance role uses attacker-controlled credentials and pollutes the logs.
- **Confusing IR actions with attacker actions.** Snapshot sharing, policy attachments, and SG changes look the same in CloudTrail. Use named IR sessions and keep a case log.
- **Trusting `userAgent` or session names.** Both are caller-controlled. Prefer access key IDs, `principalId`, source IPs, and `sharedEventID`.
- **Ignoring failed calls.** `AccessDenied` patterns reveal attacker intent and tooling even when nothing succeeded.
- **Treating GuardDuty silence as clean.** Check coverage gaps, disabled protection plans, suppression filters, trusted IP lists, and regions without detectors.
- **Forgetting time semantics.** CloudTrail delivery lag, Flow Log aggregation windows, and Config capture times are not exact event times.
- **Missing the identity provider.** For Identity Center and federated access, the root cause is often in Entra ID, Okta, or Google Workspace logs, not in AWS.

---

## 16. Further learning

- **AWS Security Incident Response Guide (whitepaper):** https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html
- **AWS incident response playbooks (samples):** https://github.com/aws-samples/aws-incident-response-playbooks
- **SANS FOR509, Enterprise Cloud Forensics and Incident Response:** https://www.sans.org/cyber-security-courses/enterprise-cloud-forensics-incident-response/
- **flaws2.cloud.** Includes a defender track that walks through CloudTrail analysis with Athena: http://flaws2.cloud/
- **CloudGoat.** Vulnerable-by-design AWS scenarios that generate realistic evidence: https://github.com/RhinoSecurityLabs/cloudgoat
- **Hacking the Cloud.** Attacker techniques mapped to AWS services: https://hackingthe.cloud/
- **MITRE ATT&CK IaaS matrix:** https://attack.mitre.org/matrices/enterprise/cloud/iaas/
- **Vendor threat research** for current AWS campaigns, including cryptomining, LLMjacking, S3 ransomware, and SES abuse: Datadog Security Labs, Wiz Research, Permiso, Sysdig TRT, Invictus IR, and the AWS Security Blog.

