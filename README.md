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

## Deploy to a remote host

```bash
./deploy/deploy.sh
```

Defaults to the `alena-tailscale` SSH host; override with `--host`. The script syncs
the source, generates secrets **on the remote** (never overwriting existing ones),
builds images there, starts the stack, waits for health, and runs `athena doctor`.

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
