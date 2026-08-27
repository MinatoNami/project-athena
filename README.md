# Athena

Autonomous security investigation, human-controlled remediation.

Athena continuously patrols codebases, hosts, containers, and networks; investigates
whether a vulnerability actually applies *here*; and prepares evidence-backed
remediation while keeping a human in control of every change.

## Documentation

| | |
|---|---|
| [Product Requirements](Athena%20—%20Product%20Requirements%20Document.md) | What Athena does, for whom, and why |
| [Technical Design](docs/TECHNICAL_DESIGN.md) | How it is built |
| [Web UI](docs/WEB_UI.md) | The Nuxt dashboard |
| [Milestones](docs/MILESTONES.md) | What gets built when, and how each stage is proven |

## Status

**M0 — Foundations.** The deployable skeleton with its security boundaries in place.
Inventory (M1), correlation (M2), investigation (M3), remediation (M4), and the
approval loop (M5) follow. See [MILESTONES.md](docs/MILESTONES.md).

## Layout

```text
core/       FastAPI app, workers, scheduler, queue, audit chain, crypto
executor/   the privileged executor — separate image, separate DB role, no LLM client
web/        Nuxt 4 dashboard with a Nitro BFF
deploy/     compose stack and the SSH deployment script
evals/      ground-truth corpus and the vulnerable fixture estate
docs/       PRD, technical design, UI spec, milestones
```

## Run it locally

```bash
cd deploy
mkdir -p secrets && bash scripts/gen-secrets.sh
docker compose up -d --build
docker compose exec api athena bootstrap    # prints a single-use admin token
```

Then open <http://127.0.0.1:8080> and create the admin account with that token.
There are no default credentials.

## Ports

Every published port binds to `127.0.0.1` by default. Nothing is reachable off the
box unless you put something in front of it deliberately.

| Default | Service | Purpose | Override |
|---|---|---|---|
| `8080` | `web` | Nuxt dashboard. **The only one a gateway should route.** | `ATHENA_WEB_PORT` / `ATHENA_WEB_BIND` |
| `8000` | `api` | FastAPI core. Published for diagnostics, not for browsers. | `ATHENA_API_PORT` / `ATHENA_API_BIND` |
| `2375` | `docker-proxy` | Read-only Docker socket proxy, for image scanning. | `ATHENA_DOCKER_PROXY_PORT` / `ATHENA_DOCKER_PROXY_BIND` |

Not published at all, and reachable only on the internal compose network: `db`
(Postgres 5432), `worker`, `scheduler`, `executor`.

### Putting a gateway in front

Route the **web** port only. The dashboard is a backend-for-frontend: it proxies
`/api/*` to core over the internal network, and core is never meant to be
browser-reachable. Exposing the API port through a gateway bypasses that boundary
rather than adding to it.

Two things the proxy must get right:

- **Do not buffer `/api/events`.** The dashboard receives live updates over
  Server-Sent Events. A buffering proxy holds them until the buffer fills, so the
  page silently stops updating rather than visibly breaking.
- **Raise the read timeout** above the gap between events. nginx's 60-second
  default drops the connection during a quiet period; a value in the tens of
  minutes is appropriate.

Serving the dashboard under a **path prefix** rather than its own hostname needs
more than a proxy rule: Nuxt writes asset URLs into the client bundle at build
time, so the base path has to be baked in when the image is built. Give it a
subdomain unless you are prepared to rebuild for the path.

## Deploy to a remote host

```bash
./deploy/deploy.sh
```

Set the target once — the host is not committed, since it names a specific machine:

```bash
echo my-ssh-host > deploy/.deploy-host    # untracked
```

Or pass `--host`, or export `ATHENA_DEPLOY_HOST`. There is no default: a deploy
script that guesses which machine to touch eventually touches the wrong one.

The script syncs the source, generates secrets **on the remote** (never overwriting
existing ones), builds images there, starts the stack, waits for health, and runs
`athena doctor`.

```bash
./deploy/deploy.sh --dry-run    # show what would happen
./deploy/deploy.sh status
./deploy/deploy.sh logs api
```

> Back up `deploy/secrets/master_key` on the deployment host out of band. Without it
> every stored secret is unrecoverable — including from a database backup.

## Development

```bash
cd core
pip install -e ".[dev]"
pytest tests/test_boundaries.py tests/test_envelope.py    # no database needed
ATHENA_TEST_DB_URL=postgresql+psycopg://... pytest         # full suite
```
