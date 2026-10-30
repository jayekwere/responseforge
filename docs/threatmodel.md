# ResponseForge threat model

## Overview

ResponseForge has two distinct execution paths: a transactional SQLite simulation and separately configured AWS, Azure and GCP identity response actions. The FastAPI service authenticates operation callers using a trusted bearer identity map. The browser demonstrates the synthetic workflow; the cloud API is a separate interface. Local state records tenant-scoped plans, approval subjects, dispatch reservations, target locks and evidence. This architecture model incorporates one independent fresh-context, read-only source review. It is not an audit or a provider acceptance result.

Native AWS acceptance evidence is separate from this architecture review. It used an existing authorized administrator role and three synthetic approval subjects controlled by one verification operator. It verifies provider acknowledgement, native readback, local evidence-chain integrity and cleanup for the dedicated target, without proving independent human approval or account-wide response safety (`docs/aws-live-verification.json:2`).

| Component | Source and role |
| --- | --- |
| Startup | `app/cli.py:38`, demo or configured identities |
| HTTP boundary | `app/api.py:74`, authentication, body and origin controls |
| Local simulation | `app/playbooks.py:43`, fixed synthetic mutations |
| Live dispatch | `app/cloud.py:38`, approvals, durable intent and reconciliation |
| Native adapters | `app/connectors.py:108`, fixed provider operations |
| Tenant state and evidence | `app/common.py:56`, SQLite and local hash chain |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Configured host service | Bearer identity map | IDENTITY_FILE, strict Identity records | Operator-selected private token-map file | Service and trusted operator | Owner-only mode, token length at least 32, constant-time lookup | `app/cli.py:49`, `app/common.py:176`; direct create_app callers own equivalent provisioning |
| Offline CLI demo | Ephemeral state | TemporaryDirectory then demo.db | OS temporary directory and SQLite companions | Synthetic actors and stdout consumer | Temporary lifecycle, fixed demo clock, Sandbox only | `app/cli.py:18` |
| Host service | Persistent state | STATE_PATH or artifacts/state.db | Selected file or cwd/artifacts/state.db and WAL companions | Service and tenant-authorized callers | 0600 database, tenant composite keys, immediate transactions | `app/cli.py:61`, `app/common.py:56`; parent-directory privacy is host-owned |
| Compose demo | Persistent state | WORKDIR /app and state volume | /app/artifacts/state.db in engine-managed state volume | UID 10001 process and container host | Read-only root, dropped capabilities, no-new-privileges, resource limits | `Dockerfile:9`, `compose.yaml:5`; host backing path is engine-selected |
| Configured cloud service | Target registry | CLOUD_TARGET_FILE then Registry.load | Private file of identifiers and credential references | Service, connector factory, operator | Strict union, 1 MiB acceptance bound, owner-only mode, duplicate physical-target rejection | `app/cli.py:56`, `app/connectors.py:62`, `app/connectors.py:78` |
| Configured cloud service | Dispatch reservations and locks | Store database, cloud_dispatch and cloud_locks | Tenant/plan and tenant/key dispatch rows; physical-target digest lock | CloudOrchestrator and authorized operators | SQLite uniqueness; intent before network; write_started before mutation | `app/cloud.py:41`, `app/cloud.py:145`, `app/cloud.py:218` |
| AWS target | Access-key status | Registry profile, account, user ID and key ID | Fixed STS us-east-1 and global IAM HTTPS endpoints; explicit user and access key | Trusted AWS CLI credential mechanism and AWS | Operation allowlist, native identity/tags, root/self exclusion, one configured attempt | `app/connectors.py:90`, `app/connectors.py:112`, `app/connectors.py:143`, `app/connectors.py:181`; dedicated AWS acceptance recorded in `docs/aws-live-verification.json:2` |
| Azure target | Service-principal enabled state | Registry subscription/directory, az context, in-memory Graph token | graph.microsoft.com/v1.0/servicePrincipals/configured-object-ID | Trusted Azure CLI and Microsoft Graph | Context and pinned object/app identity, Application type, ownership tags, HTTPS authority, no redirects | `app/connectors.py:241`, `app/connectors.py:269`, `app/connectors.py:272`; account acceptance unverified |
| GCP target | Service-account enabled state | Explicit project/operator account, gcloud token, stable unique ID | iam.googleapis.com/v1/projects/configured-project/serviceAccounts/configured-unique-ID | Trusted gcloud and GCP IAM | Native project/email/UID/ownership, self and implicit impersonation/override rejection, fixed HTTPS authority | `app/connectors.py:303`, `app/connectors.py:312`; account acceptance unverified |
| Host HTTP | Operation listener | HOST or 127.0.0.1; --port or 8080 | Default 127.0.0.1:8080 | Reachable clients | Bearer operation auth, Host/Origin controls, 1 MiB request bound; access logging disabled | `app/cli.py:66`, `app/api.py:44`, `app/api.py:102` |
| Compose HTTP | Demo listener | Container HOST=0.0.0.0 and loopback port publication | Container 0.0.0.0:8080; host 127.0.0.1:8080 | Container peers and host loopback clients | Compose publication and application controls | `compose.yaml:4`; direct Docker publication is separately configured |
| Verification CI | Evidence export | Synthetic tests/demo and upload-artifact | verification-evidence, 14-day retention | GitHub artifact readers | contents:read, checkout credentials disabled, synthetic inputs | `.github/workflows/verify.yml:7`, `.github/workflows/verify.yml:17`; real cloud evidence must stay outside exported paths |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets are provider authority, target-registry integrity, independent role assignments, tenant data, approved plan identity, native target state and dispatch/evidence integrity. An unauthenticated reachable caller can send requests. A compromised analyst can submit supported events and request plans within its tenant; it does not initially control the server, registry, provider credentials, policy or another subject's credentials. A role list does not create another subject. Host administrators and trusted maintainers already control code and local state and are outside the isolation boundary (`SECURITY.md:6`).

Tenant and roles come from the identity map, not submitted operation data. Strict contracts reject extra fields. HTTP body, Host, Origin, CSP and no-store controls protect the exposed service boundary (`app/common.py:16`, `app/common.py:51`, `app/api.py:44`, `app/api.py:102`). The synthetic path accepts only sim: resources and fixed playbooks; mutation, verification, audit and idempotency share one transaction (`app/playbooks.py:11`, `app/playbooks.py:43`, `app/playbooks.py:154`).

Cloud callers select a configured tenant alias and disable or restore action. They cannot choose native IDs, profiles or URLs. Demo startup rejects a cloud registry. A plan binds event evidence, native before-state digest, registry fingerprint, policy, requester and a 15-minute expiry. Approval and operation require different subjects from the requester and each other. Restore requires an eligible verified disable whose original state was active; a pre-dispatch failed restore may be replanned, while an uncertain restore remains reserved (`app/api.py:84`, `app/api.py:166`, `app/cloud.py:56`, `app/cloud.py:112`, `app/cloud.py:122`, `app/cloud.py:145`).

External calls are not SQLite-atomic. Reservations and physical-target locks precede network access. Native preconditions and expiry are rechecked before dispatch. An existing plan/key reservation returns stored status instead of another application write. Ambiguous dispatch retains its lock; reconciliation only reads after a five-minute cooldown. Expired reservations that never reached write_started are recovered atomically (`app/cloud.py:145`, `app/cloud.py:218`, `app/cloud.py:267`). These controls do not establish distributed exactly-once execution or exclude changes by another cloud administrator.

Provider tools, PATH, local credential stores, proxy configuration and host file access remain trusted. Credential-cache locations are host-owned. Default containers provide the synthetic demo and do not supply live provider tools or credential mounts. Ownership tags supplement exact provider IAM restrictions; they do not replace them. AWS live acceptance verified disable/readback/restore/readback on a dedicated temporary IAM key, followed by key/user cleanup. Azure/GCP live acceptance remains unverified. Event hashes are analyst assertions. Native disabled status proves only observed provider state, not revocation of issued sessions or downstream tokens. The local hash chain is not independent tamper-proof retention (`app/common.py:123`, `docs/live-connectors.md:3`).

Private paths, snapshots, key files and environment files are excluded from the build context; arbitrary sensitive operator-selected filenames still require private placement (`.dockerignore:11`). Independent people require independently controlled credentials; the public demo and integration test subjects do not prove human separation. This reference implementation makes no production HA, rate-limit, SSO or certification claim.

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses guiding review, not validated findings.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High | Low-privilege caller targets another tenant's cloud identity | Configured live service and valid limited credential | Unauthorized target mutation | Identity-derived tenant, alias registry, role and independent-subject checks, pinned native identities | Maintain target-limited provider grants and negative tenant tests | `app/api.py:166`, `app/connectors.py:83`, `app/cloud.py:145` |
| High | Replayed or changed approval causes another external write | Prior approved plan and reachable execution API | Repeated or unintended response | Plan/key uniqueness, request hash, native preconditions, expiry and physical lock | Preserve state during restart and drain old workers during configuration changes | `app/cloud.py:134`, `app/cloud.py:145`, `app/cloud.py:218` |
| High | Timeout is mistaken for failure and blindly retried | Provider mutation dispatched without definite acknowledgement | Conflicting response and restore | write_started evidence, uncertain state, retained lock, read-only reconciliation | Investigate native state; never assume rollback or retry safety | `app/cloud.py:218`, `app/cloud.py:267` |
| Medium | Forged event evidence or premature closure overstates response | Authorized analyst asserts an arbitrary hash | Misleading incident record | Freshness and exact plan binding; native outcome readback remains independent | Authenticate event sources in a separately verified integration | `app/cloud.py:24`, `app/cloud.py:56` |
| Medium | Credential or native inventory is exported in a demo/image | Operator places real material in public paths | Confidentiality loss | Private registry/state checks, build exclusions, synthetic CI inputs | Keep private directories, provider credentials and evidence outside image and artifact inputs | `app/connectors.py:78`, `.dockerignore:11` |
| Low | Local audit consistency is presented as independent retention | Host operator controls the database | Overstated assurance | Explicit local-chain semantics | Export checkpoints to independently controlled storage before relying on stronger retention | `app/common.py:123`, `docs/live-connectors.md:41` |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require evidence of broad unauthorized cloud authority across configured boundaries, not merely possession of a trusted host administrator account. High applies to a reachable caller bypassing tenant, independent approval or dispatch controls to mutate a configured external identity. Medium applies to constrained evidence deception or confidential data exposure with a concrete recipient and prerequisite. Low covers bounded local defects and misleading documentation without a demonstrated authority gain. Demo-only synthetic mutations do not inherit live cloud severity. Missing provider access lowers verification confidence; it does not establish either safety or a vulnerability.

Repository: https://github.com/jayekwere/responseforge
Version: 224779b1da1f940375ed5ebaff137d70c5a1cba6
