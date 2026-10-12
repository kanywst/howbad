# Security Policy

## Reporting a vulnerability

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/kanywst/howbad/security/advisories/new). Please do not open a public issue for anything exploitable.

Expect an acknowledgement within 7 days. Confirmed issues are fixed in the next patch release, and the advisory is published once that release is out.

## Supported versions

Only the latest release receives fixes.

## What howbad does with your credentials

- It reads credentials from the places listed in the README and keeps them in memory for the length of one run. howbad itself writes nothing to disk; the AWS SDK may refresh an SSO token in `~/.aws/sso/cache`, and helpers you configured (credential_process, kubeconfig exec plugins) may update their own caches, as they would for any tool.
- Each credential is sent only to the provider that issued it: GitHub tokens to the GitHub API host they belong to, npm tokens to the registry they are configured for, Slack tokens to `slack.com`, AWS credentials to AWS STS and IAM, kubeconfig credentials to that cluster.
- All provider calls are read-only. Kubernetes `SelfSubjectAccessReview` and `SelfSubjectReview` are `create` calls by API shape but persist nothing. An expired AWS SSO access token may be refreshed through SSO OIDC, as the AWS CLI would.
- Secrets never appear in text or JSON output. A credential is identified by the first eight hex characters of its SHA-256.

## Things that run code

Some credentials only work by running a program. `howbad` runs them the same way your tools would:

- `gh auth token`, to read the gh CLI token from the OS keychain
- AWS `credential_process`, through the AWS SDK
- kubeconfig `exec` plugins (for example `aws eks get-token`), through client-go, never interactively

`--no-exec` skips all three. `--offline` skips every network call.
