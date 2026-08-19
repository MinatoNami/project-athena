"""Athena command line.

    athena serve       API
    athena worker      queue consumer
    athena scheduler   periodic work (leader-elected)
    athena migrate     apply database migrations
    athena bootstrap   mint a single-use admin bootstrap token
    athena node-token  mint a single-use node enrolment token
    athena doctor      check schema, keys, connectivity, queue health
    athena keygen      generate a master key
"""

from __future__ import annotations

import argparse
import sys

import structlog

from athena import __version__
from athena.config import get_settings
from athena.logging import configure as configure_logging

log = structlog.get_logger(__name__)


def _migrate() -> int:
    from alembic import command
    from alembic.config import Config

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    command.upgrade(cfg, "head")
    log.info("migrate.complete")
    return 0


def _serve() -> int:
    import uvicorn

    s = get_settings()
    uvicorn.run(
        "athena.api.app:app",
        host=s.bind_host,
        port=s.bind_port,
        log_config=None,
        access_log=False,
    )
    return 0


def _bootstrap() -> int:
    """Mint a bootstrap token. Idempotent-safe: refuses once an account exists."""
    from athena.api.auth import (
        any_user_exists,
        live_bootstrap_token_exists,
        mint_bootstrap_token,
    )
    from athena.db.base import session_scope

    with session_scope() as session:
        if any_user_exists(session):
            log.info("bootstrap.skipped", reason="an account already exists")
            return 0
        if live_bootstrap_token_exists(session):
            log.info(
                "bootstrap.skipped",
                reason="an unused token is still valid; check an earlier deploy log",
            )
            return 0
        token = mint_bootstrap_token(session)

    # Printed to stdout exactly once. It is never stored in recoverable form.
    print("\n" + "=" * 68, file=sys.stderr)
    print("  ATHENA FIRST-RUN BOOTSTRAP TOKEN (valid 24h, single use)", file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    print(f"\n  {token}\n", file=sys.stderr)
    print("  Create the admin account with this token, then it is burned.", file=sys.stderr)
    print("=" * 68 + "\n", file=sys.stderr)
    return 0


def _node_token(tier: str = "unknown") -> int:
    """Mint a node enrolment token without a dashboard session.

    Enrolling a host is a shell-level operation on that host, so it should not
    require logging into the UI first.
    """
    import hashlib
    import secrets as _secrets
    from datetime import UTC, datetime, timedelta

    from athena.audit import record
    from athena.db.base import session_scope
    from athena.db.models import NodeEnrolmentToken

    token = _secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(minutes=15)

    with session_scope() as session:
        session.add(
            NodeEnrolmentToken(
                token_hash=hashlib.sha256(token.encode()).digest(),
                tier=tier,
                created_by="system:cli",
                expires_at=expires,
            )
        )
        record(
            session,
            actor="system:cli",
            action="NODE_ENROLMENT_TOKEN_MINTED",
            subject="nodes",
            detail={"tier": tier, "via": "cli"},
        )

    print("\n" + "=" * 68, file=sys.stderr)
    print("  NODE ENROLMENT TOKEN (valid 15 minutes, single use)", file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    print(f"\n  {token}\n", file=sys.stderr)
    print("  On the host to protect:", file=sys.stderr)
    print(f"    athena-node enrol --core <core-url> --token {token}\n", file=sys.stderr)
    print("=" * 68 + "\n", file=sys.stderr)
    return 0


def _doctor() -> int:
    """Verify the things that silently break a deployment."""
    from sqlalchemy import text

    from athena.audit import verify_chain
    from athena.crypto.envelope import MasterKeyUnavailable, seal, unseal
    from athena.db.base import session_scope

    checks: list[tuple[str, bool, str]] = []

    # database + schema
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
            rev = session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            checks.append(("database", True, f"connected, schema at {rev}"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("database", False, str(exc)))
        _report(checks)
        return 1

    # master key round-trip
    try:
        sealed = seal("athena-doctor-probe", aad="doctor")
        ok = unseal(**sealed, aad="doctor") == "athena-doctor-probe"
        checks.append(("master key", ok, "seal/unseal round-trip" if ok else "round-trip failed"))
    except MasterKeyUnavailable as exc:
        checks.append(("master key", False, str(exc)))
    except Exception as exc:  # noqa: BLE001
        checks.append(("master key", False, str(exc)))

    with session_scope() as session:
        # audit chain
        result = verify_chain(session)
        checks.append(
            (
                "audit chain",
                bool(result["intact"]),
                f"{result['checked']} events verified"
                if result["intact"]
                else f"broken at seq {result.get('broken_at')}",
            )
        )

        # append-only enforcement is a security control, so assert it rather than assume it
        enforced = session.execute(
            text(
                "SELECT count(*) FROM pg_trigger "
                "WHERE tgrelid = 'audit_event'::regclass AND NOT tgisinternal"
            )
        ).scalar_one()
        checks.append(
            ("audit immutability", enforced >= 2, f"{enforced} triggers installed (expect 2)")
        )

        # queue health
        stuck = session.execute(
            text(
                "SELECT count(*) FROM job WHERE finished_at IS NULL "
                "AND attempts >= max_attempts"
            )
        ).scalar_one()
        depth = session.execute(
            text("SELECT count(*) FROM job WHERE finished_at IS NULL")
        ).scalar_one()
        checks.append(("queue", stuck == 0, f"depth {depth}, exhausted {stuck}"))

        # a downgraded cookie policy is a security finding about Athena itself
        secure = get_settings().cookie_secure
        checks.append(
            (
                "cookie policy",
                secure,
                "Secure flag set"
                if secure
                else "ATHENA_COOKIE_SECURE=false — sessions are sent over plain HTTP",
            )
        )

        # an account must exist, or the deployment is unusable
        users = session.execute(text("SELECT count(*) FROM app_user")).scalar_one()
        checks.append(
            (
                "accounts",
                users > 0,
                f"{users} account(s)" if users else "none — run `athena bootstrap`",
            )
        )

    return _report(checks)


def _report(checks: list[tuple[str, bool, str]]) -> int:
    width = max(len(name) for name, _, _ in checks)
    failed = 0
    for name, ok, detail in checks:
        mark = "✓" if ok else "✗"
        if not ok:
            failed += 1
        print(f"  {mark}  {name.ljust(width)}   {detail}")
    print()
    if failed:
        print(f"  {failed} check(s) failed")
    else:
        print("  all checks passed")
    return 1 if failed else 0


def _keygen() -> int:
    from athena.crypto.envelope import generate_master_key

    print(generate_master_key())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="athena", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "worker", "scheduler", "migrate", "bootstrap", "doctor", "keygen"):
        sub.add_parser(name)
    node_token = sub.add_parser("node-token")
    node_token.add_argument("--tier", default="unknown")

    args = parser.parse_args(argv)
    configure_logging(get_settings().log_level)

    if args.command == "worker":
        from athena.workers.worker import run

        run()
        return 0
    if args.command == "scheduler":
        from athena.workers.scheduler import run

        run()
        return 0

    if args.command == "node-token":
        return _node_token(args.tier)

    return {
        "serve": _serve,
        "migrate": _migrate,
        "bootstrap": _bootstrap,
        "doctor": _doctor,
        "keygen": _keygen,
    }[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
