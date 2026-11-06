# Container & Kubernetes Security Guide

A practical, resource-linked guide to securing containerized environments — built to deepen a growth area (self-assessment: Securing Containerized Environments = 2) and to support interview answers that show you understand the concepts and how they map to detection and response.

> **Scope:** Docker/OCI containers, Kubernetes orchestration, and cloud/container registries. Focus is on controls a **blue-team / threat-response** engineer should understand and operationalize — not on being a full-time platform engineer.

---

## 0. Authoritative starting points

| Resource | Why it matters | Link |
|---|---|---|
| Kubernetes Security (official docs) | Pod security, RBAC, network policy, secrets, admission control | https://kubernetes.io/docs/concepts/security/ |
| CIS Benchmarks (Docker, Kubernetes) | Industry hardening baselines with audit checks | https://www.cisecurity.org/cis-benchmarks |
| NSA/CISA Kubernetes Hardening Guide | Practical hardening guidance for K8s clusters | https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF |
| OWASP Kubernetes Top 10 | Top risks mapped to containers/orchestration | https://owasp.org/www-project-kubernetes-top-ten/ |
| MITRE ATT&CK Containers matrix | Adversary techniques specific to containers | https://attack.mitre.org/matrices/enterprise/containers/ |
| NIST SP 800-190 | Application Container Security Guide | https://csrc.nist.gov/pubs/sp/800/190/final |

---

## 0.5 Basic containerization concepts

Before the security model, get the fundamentals straight — interviewers often probe these to gauge real understanding versus buzzword familiarity.

### What a container actually is
A container is **not a lightweight VM**. It's a **regular process** (or group of processes) on the host that is isolated using Linux kernel features. There is no separate guest OS or hypervisor. This single fact drives almost all of container security: containers share the host kernel, so a kernel exploit or misconfiguration breaks isolation for everything on that node.

```
Virtual Machines                    Containers
┌─────────┐ ┌─────────┐            ┌─────┐ ┌─────┐ ┌─────┐
│ App     │ │ App     │            │ App │ │ App │ │ App │
│ Guest OS│ │ Guest OS│            └─────┘ └─────┘ └─────┘
├─────────┴─┴─────────┤            │ Container runtime   │
│     Hypervisor      │            │ (containerd/CRI-O)  │
├─────────────────────┤            ├─────────────────────┤
│      Host OS        │            │      Host OS        │
└─────────────────────┘            └─────────────────────┘
 Each VM has its own kernel        All share ONE host kernel
```

### The three kernel primitives that make containers
| Primitive | What it does | Security relevance |
|---|---|---|
| **Namespaces** | Isolate what a process *sees*: PID tree, network, mounts, users, hostname, IPC | A container's `pid 1` is not the host's; it sees only its own processes/network |
| **cgroups** | Limit and account *resources*: CPU, memory, I/O, PIDs | Resource limits; also a DoS/containment boundary |
| **Capabilities** | Split root's power into ~40 fine-grained units (`CAP_NET_BIND_SERVICE`, `CAP_SYS_ADMIN`, ...) | Dropping capabilities is the core of least-privilege containers |

Layered on top: **seccomp** (filter syscalls), **AppArmor/SELinux** (mandatory access control), and **union/overlay filesystems** (layered images).

### Images, layers, and containers
- An **image** is a read-only, layered filesystem + metadata (entrypoint, env, user). Built from a **Dockerfile**.
- Each Dockerfile instruction creates a **layer**; layers are stacked via a union filesystem and are **immutable and cached**.
- A **container** is a running instance of an image — the image layers plus a thin **writable layer** on top.

```dockerfile
# Each instruction = one layer
FROM node:18-alpine        # layer: base image
WORKDIR /app               # layer: metadata
COPY package*.json ./      # layer: files
RUN npm ci --omit=dev      # layer: dependencies
COPY . .                   # layer: app code
USER node                  # layer: metadata (run as non-root)
CMD ["node", "server.js"]  # layer: metadata (entrypoint)
```

**Security consequence of layers:** data written and "deleted" in a later layer still exists in an earlier one — which is why secrets baked into an image are recoverable from its history (§2.3).

### The container lifecycle & key terms
| Term | Meaning |
|---|---|
| **Dockerfile** | Text recipe that builds an image |
| **Image** | Immutable, layered artifact; the "template" |
| **Tag** | Human label for an image (`myapp:1.2`); mutable — `latest` can change |
| **Digest** | Immutable content hash (`@sha256:...`); the trustworthy reference |
| **Registry** | Stores/distributes images (Docker Hub, ECR, GCR, Harbor) |
| **Container** | Running instance of an image |
| **Container runtime** | Low-level engine that runs containers (containerd, CRI-O) — Docker uses containerd under the hood |
| **OCI** | Open Container Initiative — the open standards for image/runtime specs |

### Common CLI (mental map)
```bash
docker build -t myapp:1.0 .        # build an image from a Dockerfile
docker images                       # list local images
docker run -d --name web myapp:1.0  # create + start a container
docker ps                           # running containers  (docker ps -a = all)
docker logs web                     # container stdout/stderr
docker exec -it web sh              # shell into a running container (IR alert!)
docker inspect web                  # full config/metadata JSON
docker stop web && docker rm web    # stop + remove
docker history myapp:1.0            # image layers (find baked secrets)
docker diff web                     # filesystem changes vs. the image
```

### From containers to orchestration (Kubernetes)
A single host runs containers fine, but production needs scheduling, scaling, self-healing, and networking across many nodes — that's **Kubernetes**. Core objects:

| K8s object | Meaning |
|---|---|
| **Pod** | Smallest deployable unit; one or more containers sharing network/storage |
| **Node** | A worker machine (VM/physical) running pods via the kubelet |
| **Deployment** | Declarative desired-state for N pod replicas (rolling updates, rollbacks) |
| **Service** | Stable network endpoint/load-balancer in front of pods |
| **Namespace** | Logical isolation boundary within a cluster |
| **ServiceAccount** | Identity a pod uses to call the K8s API (RBAC applies here) |
| **Control plane** | API server, etcd, scheduler, controllers — the cluster's brain |

**The security thread that ties it together:** because containers share the host kernel and pods carry identities (ServiceAccounts) that call the API, the blast radius of a compromised container is defined by (a) its privileges/capabilities and (b) its RBAC permissions — which is exactly what the rest of this guide hardens and detects.

---

## 1. Mental model: the container threat surface

Containers are **not a security boundary** — they're a packaging/isolation convenience. The real boundary is the host kernel and the orchestrator's control plane. A container is a process with namespacing, cgroups, and (optionally) seccomp/AppArmor/SELinux.

Think in layers:

```
Supply chain (base images, dependencies, CI/CD)
  → Image (what's inside, how it's built)
  → Registry (where it's stored, who can push/pull)
  → Runtime (how the container executes)
  → Orchestrator (Kubernetes control plane & data plane)
  → Host (the kernel, container runtime, node OS)
  → Network (pod-to-pod, ingress/egress, service mesh)
  → Secrets & identity (API tokens, cloud creds, workload identity)
```

Attackers target the **weakest link**: an exposed Docker socket, an over-privileged container, a leaked cloud credential, a poisoned base image, or a misconfigured RBAC role.

---

## 2. Supply chain & image security

The most common real-world container compromises start before runtime — in the image.

### 2.1 Base images & provenance
- **Use minimal, trusted base images.** `distroless`, `alpine`, or `scratch` reduce attack surface. Avoid `latest` tags — pin by digest (`image@sha256:...`).
- **Verify provenance.** Use signed images and verify signatures at admission (Sigstore/Cosign, Notary v2).
- **Scan dependencies.** A base image with 1000 CVEs is not a foundation; it's a liability.

### 2.2 Image scanning
Scan for CVEs in OS packages and application dependencies, but understand limits: scanners miss zero-days, misconfigurations, and runtime behavior.

| Tool | What it does |
|---|---|
| **Trivy** | Scans images, filesystems, repos, K8s — CVEs, misconfig, secrets, licenses |
| **Grype** | Vulnerability scanning (Anchore) |
| **Clair** | Static analysis of container images |
| **Docker Scout / Snyk** | Integrated scanning in registries/CI |

```bash
trivy image myapp:latest
trivy image --severity HIGH,CRITICAL myapp:latest
```

**Interview point:** "Scanning finds known CVEs, but it won't catch a poisoned dependency, a malicious maintainer, or a misconfigured admission policy. That's why I pair scanning with provenance verification and runtime detection."

### 2.3 Secrets in images — the classic mistake
Never bake secrets into images. They persist in image layers even if deleted later.

```bash
# BAD — secret survives in the image layer history
FROM node:18
RUN echo "API_KEY=secret123" > /app/config && rm /app/config   # STILL in layer history
```

```bash
# Inspect image layers for baked secrets
docker history --no-trunc myapp:latest
# or
dive myapp:latest    # interactive layer explorer
```

**Control:** Build-time secrets (BuildKit `--secret`), runtime injection (env vars, mounted volumes, external secrets managers), and scanning for committed secrets (gitleaks, trufflehog).

---

## 3. Runtime security — how the container executes

### 3.1 The privilege problem
The default container runs as **root** inside the container. If it escapes, it's root on the host. This is the single most important hardening decision.

| Anti-pattern | Why it's dangerous |
|---|---|
| `--privileged` | Full host access — all devices, all capabilities, no seccomp |
| Running as root (no `USER` in Dockerfile) | Container escape = host root |
| `--cap-add SYS_ADMIN` | Effectively root-equivalent |
| Mounting `/var/run/docker.sock` | Full control of the Docker daemon = host root |
| `--network host` | Shares host network namespace — no isolation |
| `--pid host` | Can see and signal host processes |

```bash
# GOOD — non-root, minimal capabilities, read-only root FS
FROM node:18-alpine
RUN addgroup -S app && adduser -S app -G app
USER app
COPY --chown=app:app . /app
```

```yaml
# Kubernetes PodSecurityContext — the K8s equivalent
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

### 3.2 The Docker socket — the most dangerous mount
Mounting `/var/run/docker.sock` into a container gives it **full control of the Docker daemon**, which runs as root on the host. This is a trivial container escape.

```bash
# This is a host-root escape waiting to happen
docker run -v /var/run/docker.sock:/var/run/docker.sock myapp
```

**Interview point:** "If I saw a container with the Docker socket mounted in an investigation, that's my first indicator of either a compromised workload or a design flaw that needs immediate remediation. It's equivalent to handing over host root."

### 3.3 Seccomp, AppArmor, SELinux
- **Seccomp** filters syscalls the container can make. Default profile blocks ~44 dangerous syscalls; a custom profile can tighten further.
- **AppArmor/SELinux** enforce mandatory access control on file/network access.
- These are the kernel-level defenses that turn a container from "a process with some isolation" into "a process with enforced boundaries."

---

## 4. Kubernetes security

Kubernetes adds orchestration complexity. The attack surface splits into **control plane** and **data plane**.

### 4.1 Control plane security
The API server, etcd, and scheduler are the crown jewels. Compromise here = full cluster control.

- **API server:** enforce RBAC, disable anonymous auth, use audit logging, restrict network access.
- **etcd:** encrypt at rest, restrict access (it holds all cluster state including secrets).
- **Audit logs:** the control plane's "flight recorder" — log all API requests, especially writes.

```bash
# Check API server audit logging
ps aux | grep kube-apiserver | grep audit
# Look for: --audit-log-path, --audit-policy-file
```

### 4.2 RBAC — the most common misconfiguration
Overly permissive RBAC is the #1 K8s misconfiguration. A service account with `cluster-admin` or broad `get/list/create` on secrets is a privilege-escalation path.

```bash
# Find overly permissive bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin")'

# Check what a service account can do
kubectl auth can-i --list --as=system:serviceaccount:default:mysa

# Audit: who can read secrets?
kubectl get roles,clusterroles -A -o json | \
  jq '.items[] | select(.rules[]? | .resources[]? | contains("secrets"))'
```

**Interview point:** "RBAC misconfiguration is the cloud/container equivalent of an over-privileged IAM role — the blast radius of a compromised pod depends entirely on what its service account can do. I look for `cluster-admin` bindings, wildcard permissions, and service accounts that can read secrets."

### 4.3 Network policies
By default, **all pods can talk to all pods** — no network segmentation. Network Policies are the firewall.

```yaml
# Deny all ingress/egress by default, then allow explicitly
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

**Detection relevance:** unexpected pod-to-pod traffic (east-west) or egress to unusual destinations is a lateral-movement/C2 signal.

### 4.4 Pod Security Standards
Kubernetes replaced PodSecurityPolicy with **Pod Security Standards** (built-in admission):

| Level | What it enforces |
|---|---|
| `privileged` | No restrictions (avoid) |
| `baseline` | Prevents known privilege escalations |
| `restricted` | Heavily restricted, current pod hardening best practices |

```bash
# Enforce restricted on a namespace
kubectl label namespace myapp pod-security.kubernetes.io/enforce=restricted
```

### 4.5 Secrets management
Kubernetes Secrets are **base64-encoded, not encrypted** by default. Anyone with API access can read them.

- Enable **encryption at rest** for etcd.
- Use **external secrets managers** (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) via operators or CSI drivers.
- Use **workload identity** (e.g., AWS IRSA, GCP Workload Identity) instead of static cloud credentials in pods.

---

## 5. Container detection & response (the blue-team angle)

This is where your detection-engineering strength meets containers. The telemetry sources differ from traditional endpoints.

### 5.1 What to monitor

| Telemetry | Source | Detection value |
|---|---|---|
| **Container process execution** | Falco, eBPF, EDR with container awareness | Unexpected binaries, shells, crypto miners |
| **Syscall activity** | Falco (eBPF) | Privilege escalation, container escape attempts |
| **K8s API audit logs** | API server | RBAC changes, pod creation, secret access, exec into pods |
| **Network flows** | CNI, service mesh, network policy logs | Lateral movement, C2 egress, scanning |
| **Image registry events** | Registry logs / webhooks | Unauthorized pushes, new images, tag overwrites |
| **Container runtime events** | containerd/CRI-O logs | Container creation, image pulls, exec |

### 5.2 Falco — the container-native IDS
Falco is the CNCF-graduated runtime security tool. It uses eBPF to detect anomalous syscall behavior.

```yaml
# Example Falco rule — shell in a container
- rule: Terminal shell in container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh, zsh, dash)
  output: "Shell spawned in container (user=%user.name command=%proc.cmdline container=%container.name)"
  priority: WARNING
```

```bash
# Run Falco
falco --modern-bpf
```

**Interview point:** "For container detection, I'd start with Falco for runtime syscall anomalies — shells spawning in containers, sensitive file reads, outbound connections from unexpected processes — and pair it with K8s audit logs for control-plane activity like RBAC changes and `kubectl exec`. The detection model is the same as EDR: identify the invariant behavior, then alert on deviations."

### 5.3 High-value container detections

| Behavior | Why it's suspicious |
|---|---|
| Shell spawned in a container | Rarely legitimate in production; usually attacker or debug |
| `kubectl exec` into a pod | Interactive access — check who and why |
| New service account with broad permissions | Privilege escalation |
| Pod with `--privileged` or host mounts | Escape risk |
| Container reading `/etc/shadow`, `/proc/*/environ`, cloud metadata | Credential theft |
| Outbound connection to unusual destination from a container | C2 |
| Image pulled from unknown registry | Supply chain / rogue image |
| New cluster-admin binding | Full cluster compromise |
| Crypto miner process (`xmrig`, high CPU) | Resource hijacking |
| Modification of `/var/run/docker.sock` or container runtime files | Escape attempt |

### 5.4 Container escape & breakout techniques to detect

| Technique | Detection signal |
|---|---|
| Docker socket abuse | Mount of `docker.sock`, API calls to Docker daemon |
| Privileged container escape | `--privileged` pod, capability additions |
| Kernel exploit | Unexpected syscall patterns (Falco), kernel module loads |
| Overly permissive capabilities | `SYS_PTRACE`, `SYS_ADMIN`, `DAC_READ_SEARCH` |
| Host path mounts | `/`, `/etc`, `/root`, `/proc`, `/sys` mounted into container |
| Cloud metadata service abuse | Requests to `169.254.169.254` from containers |

---

## 6. Incident response in containerized environments

Containers are **ephemeral** — evidence disappears when a pod is destroyed. This changes IR.

### 6.1 Evidence preservation
```bash
# Capture the running container's state BEFORE it terminates
docker inspect <container-id> > container_inspect.json
docker logs <container-id> > container_logs.txt
docker diff <container-id> > container_diff.txt        # filesystem changes
docker export <container-id> > container_fs.tar        # full filesystem

# K8s: capture pod state
kubectl get pod <pod> -o yaml > pod_spec.yaml
kubectl logs <pod> --previous > pod_previous_logs.txt  # if restarted
kubectl describe pod <pod> > pod_describe.txt
```

**Key insight:** `kubectl logs --previous` captures logs from a crashed/restarted container — critical for crash-looping or killed containers.

### 6.2 IR workflow for containers
1. **Identify the workload** — which pod, container, image, namespace, node.
2. **Preserve evidence** — logs, inspect output, filesystem diff, before termination.
3. **Check the control plane** — K8s audit logs for who created/modified the pod, RBAC changes.
4. **Scope the blast radius** — what could this pod's service account access? What other pods on the same node? What network policies allowed?
5. **Contain** — cordon the node, delete the pod (after preservation), rotate the service account token, block the C2 at egress.
6. **Trace to the source** — was it a poisoned image, a misconfigured RBAC, a leaked credential, or a vulnerable application?
7. **Hunt** — same image hash, same service account, same C2 destination across the cluster.

### 6.3 Container-specific IR considerations
- **Ephemeral evidence:** containers die and are replaced. Capture state immediately or lose it.
- **Shared kernel:** a container escape affects the host. Check the node, not just the container.
- **Control plane ≠ data plane:** an attacker with API access can create pods; an attacker in a pod can escape to the node. Both are different incident types.
- **Immutable infrastructure:** the fix is often "rebuild and redeploy from a clean image" rather than "clean the container."

---

## 7. Hardening checklist

### Image & build
- [ ] Use minimal base images (distroless/alpine)
- [ ] Pin images by digest, not `latest`
- [ ] Scan images for CVEs and secrets (Trivy/Grype)
- [ ] Sign and verify images (Cosign)
- [ ] No secrets in image layers
- [ ] Multi-stage builds to reduce final image size

### Runtime
- [ ] Run as non-root (`USER` in Dockerfile, `runAsNonRoot` in K8s)
- [ ] Drop all capabilities, add only what's needed
- [ ] Read-only root filesystem
- [ ] No `--privileged` containers
- [ ] No Docker socket mounts
- [ ] Enable seccomp/AppArmor/SELinux
- [ ] Resource limits (CPU/memory) to prevent DoS

### Kubernetes
- [ ] RBAC: least privilege, no wildcard permissions
- [ ] Pod Security Standards: `restricted` on production namespaces
- [ ] Network Policies: default-deny, explicit allow
- [ ] etcd encryption at rest
- [ ] API server audit logging enabled
- [ ] External secrets manager (not K8s Secrets for sensitive data)
- [ ] Workload identity instead of static cloud credentials

### Detection & response
- [ ] Falco or equivalent runtime detection
- [ ] K8s audit logs centralized and monitored
- [ ] Container-aware EDR/agent
- [ ] Network flow logging
- [ ] Image registry audit logging
- [ ] IR runbooks for container incidents (evidence preservation before pod deletion)

---

## 8. Interview talking points (bridging your 2 to the role)

When Nicholas asks about containers, here's the honest-but-strong framing:

> "I understand the container security model conceptually — the layered threat surface from supply chain through runtime to orchestration. I know the high-impact misconfigurations: privileged containers, Docker socket mounts, over-permissive RBAC, and secrets baked into images. I can investigate container incidents using the same methodology I apply to endpoints: identify the workload, preserve ephemeral evidence, check control-plane audit logs, scope the blast radius, and hunt across the cluster. Where I'm still building is deep hands-on production hardening of Kubernetes at scale. For a SaaS company like Asana, I'd want to ramp on your specific container platform and detection coverage, and I'd bring my detection-engineering methodology to building container-native detections with tools like Falco and K8s audit logs."

**Key phrases that signal understanding:**
- "Container escape via Docker socket mount"
- "RBAC misconfiguration as privilege escalation"
- "Ephemeral evidence — preserve before the pod dies"
- "Falco for runtime syscall detection"
- "K8s audit logs as the control-plane flight recorder"
- "Workload identity instead of static credentials"
- "Image provenance and supply chain verification"

---

## 9. Quick reference: dangerous configurations

| Configuration | Risk | Detection |
|---|---|---|
| `--privileged` | Full host access | Pod spec review, admission control |
| `-v /var/run/docker.sock` | Host root escape | Mount audit, Falco |
| `runAsUser: 0` or no USER | Container root = host root on escape | Pod spec review |
| `SYS_ADMIN` capability | Effectively root | Capability audit, Falco |
| `--network host` | No network isolation | Pod spec review |
| `--pid host` | Can see/signal host processes | Pod spec review |
| Host path mounts (`/`, `/etc`, `/root`) | Direct host filesystem access | Mount audit, Falco |
| `cluster-admin` binding | Full cluster control | RBAC audit, K8s audit logs |
| Secrets in image layers | Credential exposure | Image scanning, `docker history` |
| `latest` tag | Unpinned, mutable image | Image policy, admission control |
| No network policies | Unrestricted lateral movement | Network policy audit |
| No Pod Security Standards | No admission-time enforcement | Namespace label audit |
| Static cloud credentials in pods | Credential theft via metadata | Metadata access monitoring |
| etcd unencrypted | All cluster secrets readable | Control plane audit |

---

## 10. Further learning

- **Kubernetes Security documentation** — https://kubernetes.io/docs/concepts/security/
- **NSA/CISA Kubernetes Hardening Guide** — https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- **OWASP Kubernetes Top 10** — https://owasp.org/www-project-kubernetes-top-ten/
- **MITRE ATT&CK Containers** — https://attack.mitre.org/matrices/enterprise/containers/
- **Falco documentation** — https://falco.org/docs/
- **Trivy documentation** — https://aquasecurity.github.io/trivy/
- **Sigstore/Cosign** — https://docs.sigstore.dev/
- **CIS Benchmarks** — https://www.cisecurity.org/cis-benchmarks
- **NIST SP 800-190** — https://csrc.nist.gov/pubs/sp/800/190/final
- **Kubernetes Goat (vulnerable lab)** — https://github.com/madhuakula/kubernetes-goat
- **Bad Pods (privilege escalation reference)** — https://github.com/BishopFox/badPods
