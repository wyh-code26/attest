# attest

Enforce SLSA provenance at Kubernetes admission. Fail closed by default.

> **Status: Phase 1 (WIP)** — admission skeleton only. Provenance fetching, verification, and policy evaluation land in phases 2–3. See [Roadmap](#roadmap).

## Why

The supply-chain toolchain has solved *generating* provenance: Sigstore signs, in-toto defines the format, SLSA defines the levels. What's missing is *enforcing* it at deploy time.

Most admission policy engines excel at signature checks and static field matching, but lack a native, extensible way to verify **semantic assertions**: does this image meet SLSA Level 3? Is the builder on the trusted list? Does the source repo match?

And `failurePolicy` defaults to `Ignore` — when the webhook is down, requests pass. Any policy relying on that default vanishes the moment something breaks.

`attest` fills this gap: a focused, auditable, fail-closed semantic provenance verifier for Kubernetes admission.

## Non-negotiable

These five rules define the project. No implementation change may violate them.

1. Verification happens at **Kubernetes admission**, not post-hoc audit, not a CI soft check.
2. Missing proof, fetch failure, invalid signature, malformed format, unsatisfied policy — **all return deny**. No degradation to warning or pass.
3. What is verified are **semantic assertions** (SLSA level, builder identity, source repo), not merely "is there a signature".
4. Policy is expressed in **declarative config**. Changing policy does not require changing code.
5. `ValidatingWebhookConfiguration.failurePolicy` MUST be **`Fail`**.

**The trade-off of rule 5**: when the webhook is unavailable, new Pods cannot be deployed. This is intentional — a security policy that fails open is no policy at all. The cost is that the webhook must be highly available: minimum 3 replicas + HPA, PodDisruptionBudget, liveness/readiness probes. Full operational requirements live in the runbook (phase 5).

## Architecture

```mermaid
flowchart TB
    subgraph Dev["CI"]
        CI["CI Pipeline<br/>build + sign + attest"]
        USER["kubectl"]
    end
    subgraph Registry["OCI Registry (v1.1 referrers)"]
        IMG["Image"]
        ATT["Attestation<br/>in-toto / SLSA"]
    end
    subgraph K8s["Kubernetes"]
        API["kube-apiserver"]
        WHC["ValidatingWebhookConfiguration<br/>failurePolicy: Fail"]
    end
    subgraph Svc["attest-admission"]
        HTTP["HTTP :8443 (TLS)"]
        ADM["Admission Handler"]
        CACHE["Cache<br/>verified only"]
        FETCH["Fetcher"]
        VER["Signature Verifier"]
        POL["Policy Engine"]
    end
    CI -->|push| IMG
    CI -->|sign + attach| ATT
    USER -->|apply Pod| API
    API --> WHC -->|AdmissionReview| HTTP --> ADM
    ADM --> CACHE
    CACHE -->|miss| FETCH -->|referrers| ATT
    FETCH --> VER --> POL
    ADM -->|allow / deny| API
    API -->|deny| USER
