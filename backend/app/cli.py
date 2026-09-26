"""Command-line helpers for CI. Exit 1 when a policy check fails."""

from __future__ import annotations

import argparse
import json
import sys

from app.core.config import Settings
from app.core.database import create_db_engine, create_session_factory, init_db
from app.core.exceptions import AppError
from app.services.policy.engine import evaluate_scan
from app.services.scanner.queries import get_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cryptonex")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("policy-check", help="Evaluate stored scan findings against policy")
    check.add_argument("--scan-id", type=int, required=True)
    check.add_argument("--policy-file", dest="policy_file")
    args = parser.parse_args(argv)
    if args.command == "policy-check":
        return _policy_check(args.scan_id, args.policy_file)
    return 2


def _policy_check(scan_id: int, policy_file: str | None) -> int:
    settings = Settings()
    engine = create_db_engine(settings.database_url)
    init_db(engine)
    factory = create_session_factory(engine)
    session = factory()
    try:
        policy_yaml = None
        if policy_file:
            from pathlib import Path

            policy_yaml = Path(policy_file).read_text(encoding="utf-8")
        result = evaluate_scan(session, get_scan(session, scan_id), policy_yaml)
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return int(result["ci_exit_code"])
    except AppError as exc:
        json.dump({"error": {"code": exc.code, "message": exc.message}}, sys.stdout)
        sys.stdout.write("\n")
        return 2
    finally:
        session.close()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
