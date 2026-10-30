# Authorized cloud response

The offline demo remains a SQLite simulation. The separate `/api/cloud/operate` API implements real AWS IAM access-key status updates, Microsoft Graph service-principal `accountEnabled` updates and GCP service-account disable/enable calls. These connectors are implemented and tested against synthetic native API contracts. Live account verification is pending. Do not interpret contract tests as provider acceptance.

Use configured identities and a private target registry. `--demo` rejects `CLOUD_TARGET_FILE`. Nothing in an incoming event can select an account, credential profile, native target ID or URL. Registry aliases are tenant scoped, and duplicate physical targets across aliases or tenants are rejected.

```sh
chmod 600 /absolute/private/identities.json /absolute/private/targets.json
IDENTITY_FILE=/absolute/private/identities.json \
CLOUD_TARGET_FILE=/absolute/private/targets.json \
STATE_PATH=/absolute/private/responseforge.db \
.venv/bin/python -m app.cli serve
```

Start from `samples/cloud-targets.example.json`, which contains fictional identifiers. The registry is validated by the strict `AwsTarget`, `AzureTarget` and `GcpTarget` schemas. It must be readable only by its owner. Keep native evidence, account IDs and real target registries outside the repository.

| Connector | Read preconditions | Write and verification | Account status |
| --- | --- | --- | --- |
| AWS | Explicit CLI profile and expected account, stable IAM UserId, pinned access-key ID, `responseforge-` username, tags `responseforge-managed=true` and `responseforge-tenant=<tenant>` | `UpdateAccessKey` with explicit UserName and AccessKeyId, then `GetUser` and `ListAccessKeys` readback | Unverified against a live account |
| Azure | CLI subscription and directory context, stable service-principal object ID and app ID, Application type, `responseforge-` display name, tags `responseforge-managed` and `responseforge-tenant:<tenant>` | Graph PATCH accountEnabled, then native GET of the pinned object | Unverified against a live account |
| GCP | Explicit project and operator account, stable service-account uniqueId, matching email, description `responseforge-managed:<tenant>:<alias>`, implicit impersonation rejected | IAM disable/enable using uniqueId, then native GET | Unverified against a live account |

AWS root callers and the target IAM user itself cannot operate the AWS connector. Azure rejects a matching operator service principal. GCP rejects a matching operator service account. Give the service credential access only to the exact dedicated targets. Ownership markers are additional checks, not a substitute for cloud IAM restrictions. Provider configuration, locally installed credential tools and the service host are trusted.

## Approval and dispatch

Submit `operation: plan` with data containing target alias, `action: disable`, an event evidence SHA-256 and a timezone-aware observed_at within the last hour. The evidence hash is an analyst assertion. The service independently reads native target state before recording the plan. The plan expires after 15 minutes and binds the policy, target configuration, evidence and native precondition state. An approver different from the requester approves its digest; an operator different from both dispatches it with an idempotency key. The fixed roles must map to independently controlled credentials in the identity file.

A restore is a separate plan, approval and execution. It requires `action: restore` and `restore_of` referencing this service's verified disable of the same target, whose original state was active. A pre-existing inactive credential cannot be activated by inventing a restore request.

SQLite commits the reservation and target lock before network access, and records `write_started` before a provider write. No database transaction spans a provider request. Application retries return the stored dispatch status and never issue that plan's write again. AWS CLI automatic retries are set to one attempt; HTTP redirects and transport write retries are disabled.

A timeout, lost acknowledgement or failed readback produces `uncertain` and retains the target lock. After a five-minute cooldown, an independent operator may request `reconcile`, which only reads provider state. Desired native state permits a verified receipt; unchanged state remains uncertain. A crashed reservation that never reached write_started can be expired atomically after five minutes, preventing a resumed worker from dispatching it. Concurrent retry tests cover reservation exclusivity. This is not a distributed exactly-once guarantee. Keep cloud credentials exclusive to this workflow while testing; another administrator can independently change a target.

A successful native status read proves only the reported account/key state at that observation. It does not prove that all issued sessions, cached tokens or downstream access have been revoked. A reconciled receipt explicitly distinguishes native state observed after an ambiguous dispatch from an acknowledged provider operation. There is no automatic rollback or automatic destructive retry.

## Account setup and limits

Install and authenticate the official AWS CLI, Azure CLI or gcloud CLI before enabling a connector. Credentials stay in the provider's local credential mechanism and never enter a target registry or HTTP request body. Backend tokens are not supplied by API callers. Fixed official HTTPS authorities are used. The platform has no arbitrary command playbook, messaging integration, EDR isolation connector or cross-account target discovery.

Test only dedicated disposable identities with no grants. Capture their stable native IDs and ownership markers, and independently verify disable and approved restore before cleanup. Never use a production administrator, shared service identity or the backend's own credential as a target. Cloud API propagation, external administrative races and API availability remain provider limitations. SQLite evidence is a local hash chain, not independent tamper-proof storage.

Native API contracts: [AWS UpdateAccessKey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html), [Microsoft Graph service principal update](https://learn.microsoft.com/graph/api/serviceprincipal-update), [GCP service account disable and enable](https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable).
