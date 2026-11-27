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

    print("\n" + "=" * 68, file=sys.stderr)
    print("  ATHENA FIRST-RUN BOOTSTRAP TOKEN (valid 24h, single use)", file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    print(f"\n  {token}\n", file=sys.stderr)
    print("  Create the admin account with this token, then it is burned.", file=sys.stderr)
    print("=" * 68 + "\n", file=sys.stderr)
    return 0


BREAK_GLASS_ACTOR = "system:break-glass"


def _operator() -> str:
    import getpass
    import os

    try:
        name = getpass.getuser()
    except (KeyError, OSError):
        name = "unknown"
    return f"{name} (uid {os.getuid()})"


def _break_glass(*, email: str, reason: str | None, confirm: bool, create: bool) -> int:
    import secrets as _secrets
    import socket
    from datetime import UTC, datetime

    from sqlalchemy import select, update

    from athena.api.auth import clear_mfa, hash_password
    from athena.audit import record
    from athena.db.base import session_scope
    from athena.db.models import Session_, User

    reason = (reason or "").strip()
    if not confirm or not reason:
        print(
            "break-glass refused: pass --confirm and a non-empty --reason; "
            "both are recorded in the audit chain.",
            file=sys.stderr,
        )
        return 2

    from pydantic import TypeAdapter, ValidationError

    from athena.api.types import AccountEmail

    try:
        email = TypeAdapter(AccountEmail).validate_python(email)
    except ValidationError:
        print(f"break-glass refused: {email!r} is not a valid email address.", file=sys.stderr)
        return 2

    credential = _secrets.token_urlsafe(24)
    now = datetime.now(UTC)

    with session_scope() as session:
        user = session.execute(
            select(User).where(User.email == email).with_for_update()
        ).scalar_one_or_none()
        if user is None and not create:
            print(
                f"break-glass refused: no account for {email}; pass --create to create one.",
                file=sys.stderr,
            )
            return 1

        if user is None:
            user = User(
                email=email,
                password_hash=hash_password(credential),
                role="admin",
                password_change_required=True,
            )
            session.add(user)
            session.flush()
            outcome = {"outcome": "created", "previous_role": None, "was_disabled": False}
            mfa_was_active = False
            revoked = 0
        else:
            outcome = {
                "outcome": "reset",
                "previous_role": user.role,
                "was_disabled": user.disabled_at is not None,
            }
            mfa_was_active = user.mfa_enabled
            user.password_hash = hash_password(credential)
            user.password_change_required = True
            user.role = "admin"
            user.disabled_at = None
            clear_mfa(user)
            revoked = session.execute(
                update(Session_)
                .where(Session_.user_id == user.id, Session_.revoked_at.is_(None))
                .values(revoked_at=now)
            ).rowcount

        if mfa_was_active:
            record(
                session,
                actor=BREAK_GLASS_ACTOR,
                action="MFA_RESET",
                subject=f"user:{user.id}",
                detail={"via": "break-glass", "reason": reason},
            )
        record(
            session,
            actor=BREAK_GLASS_ACTOR,
            action="BREAK_GLASS",
            subject=f"user:{user.id}",
            detail={
                **outcome,
                "email": email,
                "reason": reason,
                "mfa_reset": mfa_was_active,
                "sessions_revoked": revoked,
                "operator": _operator(),
                "host": socket.gethostname(),
            },
        )

    print("\n" + "=" * 68, file=sys.stderr)
    print("  ATHENA BREAK-GLASS CREDENTIAL (single use, shown once)", file=sys.stderr)
    print("=" * 68, file=sys.stderr)
    print(f"\n  account   {email}", file=sys.stderr)
    print(f"  password  {credential}\n", file=sys.stderr)
    print("  MFA is cleared and every session for this account is revoked.", file=sys.stderr)
    print("  The first sign-in must set a new password; then enrol MFA again.", file=sys.stderr)
    print("=" * 68 + "\n", file=sys.stderr)
    return 0


def _node_token(tier: str = "unknown") -> int:
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
    from sqlalchemy import text

    from athena.audit import verify_chain
    from athena.crypto.envelope import MasterKeyUnavailable, seal, unseal
    from athena.db.base import session_scope

    checks: list[tuple[str, bool, str]] = []

    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
            rev = session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            checks.append(("database", True, f"connected, schema at {rev}"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("database", False, str(exc)))
        _report(checks)
        return 1

    try:
        sealed = seal("athena-doctor-probe", aad="doctor")
        ok = unseal(**sealed, aad="doctor") == "athena-doctor-probe"
        checks.append(("master key", ok, "seal/unseal round-trip" if ok else "round-trip failed"))
    except MasterKeyUnavailable as exc:
        checks.append(("master key", False, str(exc)))
    except Exception as exc:  # noqa: BLE001
        checks.append(("master key", False, str(exc)))

    with session_scope() as session:
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

        enforced = session.execute(
            text(
                "SELECT count(*) FROM pg_trigger "
                "WHERE tgrelid = 'audit_event'::regclass AND NOT tgisinternal"
            )
        ).scalar_one()
        checks.append(
            ("audit immutability", enforced >= 2, f"{enforced} triggers installed (expect 2)")
        )

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


def _rescore(*, dry_run: bool) -> int:
    from athena.workers.rescore import rescore_all

    summary = rescore_all(dry_run=dry_run)
    verb = "would move" if dry_run else "moved"
    print(f"examined {summary['examined']} investigated finding(s)")
    print(f"  unchanged : {summary['unchanged']}")
    print(f"  {verb:9} : {summary['changed']}")
    for movement, count in summary["movements"].items():
        print(f"      {movement:32} {count}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="athena",
        description=(
            "Athena command line.\n"
            "\n"
            "    athena serve       API\n"
            "    athena worker      queue consumer\n"
            "    athena scheduler   periodic work (leader-elected)\n"
            "    athena migrate     apply database migrations\n"
            "    athena bootstrap   mint a single-use admin bootstrap token\n"
            "    athena node-token  mint a single-use node enrolment token\n"
            "    athena break-glass restore an admin (needs --confirm and --reason)\n"
            "    athena doctor      check schema, keys, connectivity, queue health\n"
            "    athena keygen      generate a master key\n"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "worker", "scheduler", "migrate", "bootstrap", "doctor", "keygen"):
        sub.add_parser(name)
    node_token = sub.add_parser("node-token")
    node_token.add_argument("--tier", default="unknown")
    break_glass = sub.add_parser(
        "break-glass", help="restore an admin account from the host; audited"
    )
    break_glass.add_argument("--email", required=True)
    break_glass.add_argument("--reason", help="why; recorded in the audit chain")
    break_glass.add_argument(
        "--confirm", action="store_true", help="required: acknowledge this is a recovery action"
    )
    break_glass.add_argument(
        "--create", action="store_true", help="create the admin if no account has this email"
    )
    rescore = sub.add_parser("rescore")
    rescore.add_argument("--dry-run", action="store_true",
                         help="report what would move without writing anything")

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

    if args.command == "break-glass":
        return _break_glass(
            email=args.email, reason=args.reason, confirm=args.confirm, create=args.create
        )

    if args.command == "rescore":
        return _rescore(dry_run=args.dry_run)

    return {
        "serve": _serve,
        "migrate": _migrate,
        "bootstrap": _bootstrap,
        "doctor": _doctor,
        "keygen": _keygen,
    }[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
