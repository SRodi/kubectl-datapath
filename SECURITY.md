# Security policy

## Supported versions

Before the first stable release, security fixes are applied to the latest
commit on the default branch. After versioned releases begin, this file will
list the supported release lines.

## Reporting a vulnerability

Use the repository's **Security** tab and select **Report a vulnerability** to
open a private GitHub Security Advisory. Do not report suspected
vulnerabilities in a public issue.

Include:

- the affected version or commit;
- the required Kubernetes and node configuration;
- reproduction steps;
- the expected and observed security boundary;
- any known impact or mitigation.

The project will acknowledge the report, validate the impact, and coordinate a
fix and disclosure through the private advisory.

## Security model

`kubectl-datapath` creates short-lived privileged Pods that have node-level
access. Review [Security and threat model](docs/security.md) before granting
users permission to run traces.
