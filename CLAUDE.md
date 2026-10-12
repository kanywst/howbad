# CLAUDE.md

## Project

`howbad` finds the credentials a coding agent running as the user could pick up and asks each issuing provider, read-only, what they can do. It runs on developer laptops against live credentials.

## Commands

```bash
make build    # go build -o howbad .
make test     # go test -race -cover ./...
make lint     # golangci-lint run ./...
make vuln     # govulncheck
make demo     # re-record assets/demo.gif (fake home + fake providers, needs vhs)
go run ./internal/demo   # print the demo report without recording
```

## Layout

```text
discover  →  []cred.Credential  →  resolve  →  []finding.Finding  →  report (text | json)
```

- `internal/cred`: the `Credential` type and the prefix/name classifier. The secret is an unexported field so it cannot reach JSON or a format string.
- `internal/discover`: one function per source (env, gh, npm, AWS, kube, gcloud, agent MCP configs). Everything reads through `discover.Env` so tests run against a temp home.
- `internal/resolve`: one resolver per provider. Base URLs live in `resolve.Options` so tests point them at `httptest`.
- `internal/report`: severity ordering, dedupe of AWS/kube principals, text and JSON output.

## Rules

- A secret never goes into output, errors or logs. Tests assert this (`assertNoSecrets`, `TestSecretNeverSerialized`); extend them when adding a source.
- A credential is sent only to the provider that issued it, and only to read-only endpoints.
- Anything that runs a program (`gh auth token`, `credential_process`, exec plugins) must be skipped by `--no-exec`.
- When a permission cannot be read back (fine-grained GitHub tokens, granular npm tokens, IAM denied), report the upper bound and mark it `Inferred`. Under-reporting is the dangerous direction.
- `--json` fields and the `--fail-on` exit code (2) are an API.
