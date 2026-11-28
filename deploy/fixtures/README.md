# Fixture estate

A small, reproducible estate with known answers. Later acceptance tests (M2's expected
candidate set, the backport test, Phase 1 verify and rollback) run against it and compare
what Athena reports with `ground_truth.json`.

Everything here is data. Nothing in it is live: the secrets are fake, the malicious
package is a name and a version only, and every service binds to loopback or publishes
nothing.

## Pieces

| Path | What it is |
|---|---|
| `compose.fixtures.yaml` | Two deliberately old images, pinned by tag and digest and labelled `athena.fixture=true`: `nginx:1.18.0` (CVE-2021-23017) on `127.0.0.1:18080`, and `python:3.8.0-slim-buster` (CVE-2020-8492) with no published port. |
| `repo/` | A repository for Athena's repository scan: pinned vulnerable PyPI and npm packages, two Gitleaks-detectable fake secrets, one benign `.pth` path entry and one `.pth` with an `import` line, and `agent-framework==1.26.1`, which OSV lists as `MAL-2026-20101`. |
| `host/profile.json` | One Ubuntu 20.04 host in the node agent's observation format: one entry per capability, with the `data` the agent sends. It includes a vulnerable `sudo`, and an `openssl` that Ubuntu has already patched by backport, so it must not match the upstream range. |
| `ground_truth.json` | The expected findings for each asset: identifier, component, location and expected classification. |

## Running it

```bash
docker compose -f deploy/compose.yaml -f deploy/fixtures/compose.fixtures.yaml \
  --profile fixtures up -d
```

Without `--profile fixtures` the fixture services do not start. Connect `deploy/fixtures/repo`
as a repository to exercise the code-side scans.

The repository's own `.gitleaks.toml` allowlists `deploy/fixtures/repo/`, so the planted
secrets do not fail a scan of Athena itself. The fixture directory deliberately carries no
Gitleaks config of its own, so a scan of the fixture repository still finds them.

## Classifications

| Value | Meaning |
|---|---|
| `affected` | The component is inside the vulnerable range and the finding should be raised. |
| `not_affected_backport` | The upstream range matches, but the distribution fixed it by backport; Athena must not confirm it. |
| `malicious` | An OSV `MAL-` entry; malware is floored at critical. |
| `inert_fake_secret` | A planted credential in a detectable format; it grants nothing. |
| `suspicious` / `benign` | The `.pth` with an executable `import` line, and the one with only a path. |

`core/tests/test_fixture_estate.py` checks that the manifests, the host profile replayed
through node ingest, the compose pins and the ground truth agree. It needs no network.
