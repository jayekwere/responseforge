# Distinct project scope

The existing public repositories were inspected before this project was created.

| Existing work | Boundary kept distinct here |
| --- | --- |
| ci-cd-security-pipeline | Demonstrates scan gates in one application; ReviewShield implements reusable finding and GitHub App review contracts. |
| iam-least-privilege-auditor | Collects AWS hygiene observations; PrivilegePath traverses explicit multi-cloud relationship graphs without claiming effective access. |
| cloud-posture-dashboard | Summarizes posture snapshots; RemediationOS manages approved transitions and exact rescan evidence. |
| secure-aws-platform and terraform-aws-eks-security-baseline | Define infrastructure; StackGuard reviews planned changes before any apply. |
| agent-anomaly-detection and cloudthreat-lab | Explore detection; ResponseForge controls what happens after an event. |

ResponseForge is an independently runnable repository. It does not require those projects or silently duplicate their implementations.
