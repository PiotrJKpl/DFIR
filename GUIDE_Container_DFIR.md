# Container DFIR field guide

This guide covers evidence collection and incident reasoning for Linux containers, with Podman examples. For a safe exercise using synthetic evidence, follow the [container DFIR lab](container-dfir-lab/README.md). This is an investigation guide, not a substitute for a production incident-response runbook.

## 1. Define the boundary

A container is a set of host processes with isolated views of resources. It is not a virtual machine. On macOS, Podman runs Linux containers inside a Podman machine; a macOS process listing will not show the container's Linux processes directly. Record which host, VM, runtime, image, container ID, pod, and workload you are investigating.

| Layer | Questions | Typical evidence |
| --- | --- | --- |
| Image and registry | Which immutable image digest was deployed? Was it expected? | Image inspect/history, registry metadata, build provenance |
| Container | What ran, changed, and logged? | Runtime inspect, stdout/stderr logs, process list, writable-layer diff, copied files |
| Host / Podman machine | Did activity reach the node or affect other workloads? | Host process, audit, network and runtime events; VM evidence on macOS |
| Orchestrator | Who changed the workload and what was replaced? | Kubernetes API audit logs, pod events, deployment revisions, RBAC |
| External services | Did data move or identities get used? | Proxy, DNS, egress flow, identity and cloud audit logs |

An indicator inside a container does **not** by itself prove container escape, host compromise, or exfiltration. Corroborate each claim with evidence from the layer where that action would occur.

## 2. Preserve before containment destroys evidence

1. Record the alert source, investigator, UTC time, host, container ID, image ID/digest, and reason for action. Coordinate isolation with the service owner.
2. Capture short-lived state first: processes, network context, runtime metadata, current logs and writable-layer changes. Use the runtime's `inspect`, `top`, `logs`, and `diff` while the container still exists. Avoid an interactive shell or installing tools inside the suspect container unless necessary: they change the evidence.
3. Copy relevant files out, preserve image references and centralized logs, and hash the collected files on the investigation host. Preserve original output and analyze copies.
4. Contain using the least destructive available control (for example, restrict ingress/egress or drain the workload); document exactly when and how. Depending on the incident, stopping a live workload may be urgent even if it reduces evidence. Do not delay emergency containment solely to complete a checklist.
5. Scope sibling containers, the host/VM, service accounts, registry permissions, and similar workloads. Rotate exposed credentials and rebuild from a trusted image if compromise is confirmed.

`podman stop` ends running processes but normally leaves the container filesystem for collection. `podman rm` removes the container and its writable layer. An orchestrator may replace a pod before you can collect either. Volumes, bind mounts, and centralized logs have separate retention and ownership; `podman diff` only compares the container's writable layer to its image, not mounted volume contents.

## 3. Minimal Podman triage

Substitute a real container name or ID; use a protected directory with appropriate access controls for case evidence.

```sh
CONTAINER=container-dfir-lab
CASE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/container-dfir.XXXXXX")
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$CASE_DIR/collection-start-utc.txt"
podman inspect "$CONTAINER" > "$CASE_DIR/inspect.json"
podman top "$CONTAINER" > "$CASE_DIR/processes.txt"
podman logs --timestamps "$CONTAINER" > "$CASE_DIR/logs.txt" 2>&1
podman diff "$CONTAINER" > "$CASE_DIR/diff.txt"
```

Use `podman cp "$CONTAINER:/path/to/file" "$CASE_DIR/file"` for a known artifact; copy mounted-volume evidence separately. Inspect metadata for image ID, creation/start times, user, mounts, capabilities, published ports, and network settings. Container-local and runtime log clocks can differ in presentation; normalize timestamps to UTC before building a timeline. Missing application logs do not prove an event did not occur: logging might be disabled, rotated, or sent elsewhere.

Record collection errors and gaps rather than silently treating incomplete output as clean evidence. A local hash demonstrates that a captured file has not changed since hashing; it does not establish the trustworthiness of the original container, its timestamps, or the investigator's access path. Restrict case-folder access and maintain an evidence register (source, collector, UTC collection time, hash, storage location, transfers).

## 4. Interpret findings carefully

- **Runtime metadata:** distinguish image configuration from run-time overrides. A non-root `USER` reduces privilege but is not proof against compromise. Check mounts, especially any container-engine socket; check privileged mode, capability additions, and host namespaces.
- **Logs:** correlate a request, an application event, and any runtime/audit event by UTC time and container ID. An application can log a *claimed* action that never reached the network.
- **Filesystem:** `podman diff` reports added (`A`), changed (`C`), or deleted (`D`) paths relative to the image. It does not show file content, the actor who wrote it, or changes within mounts. Collect candidate files with `podman cp`, then examine safely on the host.
- **Processes and network:** `podman top` is a snapshot; short-lived processes can be missed. For an egress or host-escape conclusion, seek network telemetry, host/VM evidence, and runtime or orchestrator audit logs.
- **Image versus runtime:** a suspicious file may be baked into an image rather than created during execution. Compare the captured artifact, image layers, image ID, and deployed digest before attributing a change.

## 5. Report and recover

State observations separately from hypotheses. For each significant claim, cite the evidence filename, container ID, UTC timestamp, and confidence or limitation. Report scope, timeline, impact, containment actions, gaps, and follow-up detection or hardening. In Kubernetes, collect pod and node identifiers, container IDs, pod events, workload manifests, API audit records, and volume evidence before a rollout deletes the pod; the Podman commands above are not a Kubernetes collection procedure.

Further reading: [Podman inspect](https://docs.podman.io/en/latest/markdown/podman-inspect.1.html), [Podman logs](https://docs.podman.io/en/latest/markdown/podman-logs.1.html), [Podman diff](https://docs.podman.io/en/latest/markdown/podman-diff.1.html), [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final), [Kubernetes logging](https://kubernetes.io/docs/concepts/cluster-administration/logging/).