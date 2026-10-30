# Security policy

ResponseForge 0.1 is a reference implementation. Use synthetic data for public demos.
Report sensitive vulnerabilities privately through GitHub private vulnerability reporting when enabled. If unavailable, open an issue requesting a private channel without exploit details or confidential data.

Review input validation, authorization, evidence integrity, tenant boundaries, and failure behavior. Changes to policy, scanner configuration, workflow permissions, fixtures, and evidence acceptance require careful review. Never run untrusted source with privileged credentials. Host administrators and trusted maintainers can change code and private state; this project does not isolate them.

See the repository threat model and limitations before connecting an external account. Tests establish specific controls on synthetic inputs, not a security certification.
