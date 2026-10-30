# ResponseForge threat model

## Overview

Intended use: the runnable repository implementation and its documented local demo. The user requested an open-source implementation with honest security scope. This model describes inspected source, not a security certification or a claim of complete audit coverage.

Data flow: Bearer identity --> event --> fixed policy plan --> independent approval --> independent operator --> transactional local sandbox mutation --> readback --> audit and idempotency result.

| Component/source | Responsibility |
| --- | --- |
| `app/api.py:65` | Authenticated operation API and bounded HTTP middleware |
| `app/common.py:176` | Trusted bearer identity, tenant and role lookup |
| `app/playbooks.py:56` | Expiring plans, independent subjects and execution checks |
| `app/playbooks.py:43` | SQLite-only response connector |
| `app/common.py:102` | Transactional evidence hash chain |

| Deployment or workflow | Resource/configuration and effective location | Readers, writers or recipients | Enforcing control or unknown |
| --- | --- | --- | --- |
| Configured credentials | IDENTITY_FILE private token map | Server memory and trusted operator | CLI checks credential length/privacy; direct factory users own equivalent checks |
| Configured state | STATE_PATH or artifacts/state.db | Tenant-scoped API actors and server | SQLite WAL, composite tenant keys, immediate transactions, database mode 0600; private directory required |
| Execution target | objects[(identity.tenant, plan.resource, resource)] with sim: resource IDs | Local SQLite sandbox only | Two fixed policies/outcomes; no shell, arbitrary destinations or external cloud writes |
| Offline demo | Temporary demo.db, fixed clock and public demo identities | Synthetic actors | Temporary local state only; duplicate execution verifies identical committed outcome |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets: Tenant event/plan integrity, synthetic resource state/version, approval identity, operation keys, durable outcomes, bearer credentials and evidence history.

Authenticated identity supplies tenant and role. An analyst can submit supported events and create only synthetic sandbox resources. A plan binds event/resource/policy digests, expected resource version and expiry. Approval rejects requester self-approval. Execution requires an operator distinct from requester and approver and rechecks all approved preconditions. Mutation, provider readback, success audit and idempotency response are in one immediate SQLite transaction. This atomicity applies only to this local connector.

Host administrators, private configuration owners and trusted repository maintainers can alter code, files and private state. They are trusted. An ordinary input author does not gain those capabilities by supplying JSON. Public demo credentials represent synthetic roles in one trusted local demonstration. The local stateless TypeScript evaluators do not establish authenticated service tenancy; the Python services derive tenancy from trusted identities. External assertions retain their stated trust prerequisites.

No external EDR, cloud, IAM or ticketing response is implemented. Event evidence hashes are analyst assertions. Public demo identities provide no real human separation. Local chain integrity does not prevent an administrator rewriting or truncating all state; no production HA or throughput claim.

## Attack Surface, Mitigations, and Attacker Stories

These are threat scenarios and review obligations, not reported vulnerabilities. Priority describes plausible impact if the named control fails in its stated deployment. The source table above identifies the actual consumers and controls.

| Priority | Scenario and potential capability gain | Existing source-established controls | Additional mitigation or prerequisite |
| --- | --- | --- | --- |
| High | An analyst turns an untrusted event into an arbitrary response command or target. | Strict event/playbook contracts, sim: targets, fixed policy actions and no arbitrary execution surface. | Keep new connectors explicit and separately authorized. |
| High | Combined roles bypass independent request/approval/execution. | Distinct subject checks survive combined roles and cross-tenant attempts. | Assign subjects to separate people and protect private credentials. |
| High | Retries, a stale plan or changed target repeats a harmful action. | Durable operation-key binding, transactional serialization, expiry, policy/resource version and event freshness checks. | External connectors need their own ambiguous-outcome and idempotency design. |
| Medium | A connector reports success without the intended state. | Server reads back expected state/version before recording success; mismatch rolls back. | Do not generalize local transactional verification to external providers; retain external evidence/checkpoints when required. |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require a credible unauthenticated path to broad privileged external execution or equivalent cross-tenant compromise. This model does not establish such a path. A fictional sandbox state change is not critical cloud compromise.

High includes a reachable authorization, approval or gate bypass that grants a materially new capability over another tenant or a deployment decision, with the required privileged consuming workflow present. An input author changing their own local file is a counterexample.

Medium includes bounded local denial of service, decision-fidelity loss or evidence misbinding under realistic deployment prerequisites. Merely changing trusted policy as its administrator is a counterexample.

Low includes limited presentation/integrity confusion without a new privileged operation. A string that is safely rendered as text is controlled behavior, not an injection finding. Confidence depends on source and executable evidence, independently of impact.

One fresh-context independent read-only architecture review informed this model. Source changed during construction; the parent rechecked the controls and source anchors after the reported discrepancies were fixed. Verified negatives are recorded in tests and verification artifacts. External account behavior remains unverified wherever stated.

Repository: https://github.com/jayekwere/responseforge
Version: 6dee7ea23ee7eb2f29478b47a9ee50df5e7612ba
