# API spec sync scripts

These scripts vendor the latest OpenAPI specs from the upstream service repos
into `internal/apiclients/<service>/<version>/spec.yaml`, after which the
generated client code can be regenerated with `go generate`.

| Script                          | Service             | Upstream repo                  | Vendored to                                          |
|---------------------------------|---------------------|--------------------------------|------------------------------------------------------|
| `pull-down-package-api.sh`      | Package API         | `snyk/package-api-service`     | `internal/apiclients/package/2024-10-15/spec.yaml`   |
| `pull-down-breakability-api.sh` | Breakability API    | `snyk/breakability-service`    | `internal/apiclients/breakability/2025-11-05/spec.yaml` |

## Prerequisites

- SSH access to the relevant Snyk GitHub repos (the scripts clone via
  `git@github.com:snyk/...`).
- A working Go toolchain, only needed for the regeneration step below.

The scripts clone (or pull) the upstream repo into a sibling directory next to
this checkout (e.g. `../package-api-service`, `../breakability-service`). If
the directory already exists it is reused and updated.

## Usage

Run from the repo root:

```bash
# Package API
./scripts/pull-down-package-api.sh

# Breakability API
./scripts/pull-down-breakability-api.sh
```

To pull from a branch other than `main`, set `API_SPEC_BRANCH` first:

```bash
API_SPEC_BRANCH=my-feature-branch ./scripts/pull-down-breakability-api.sh
```

Each script prints the generation date, branch, and upstream commit SHA on
completion so the vendored state is traceable.

## Regenerating the Go client

After the spec has been refreshed, regenerate the typed client:

```bash
# Package API
go generate ./internal/apiclients/package/2024-10-15/...

# Breakability API
go generate ./internal/apiclients/breakability/2025-11-05/...
```

This invokes `oapi-codegen` per the `//go:generate` directive in each
package's `gen.go`, using the local `spec.config.yaml` and producing the
updated `*.go` client.

Commit both the refreshed `spec.yaml` and the regenerated `*.go` together so
the vendored spec and generated code stay in sync.
