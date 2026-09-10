from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Optional, Sequence

from metatron.assistant import DEFAULT_MODEL, AssessmentError, assess
from metatron.audit import append_event
from metatron.models import EngagementError
from metatron.observer import ObservationError, observe_http
from metatron.policy import authentication_headers, authorize, load_engagement


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Metatron, assistant de pentest autorisé")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Valider un contrat d'engagement")
    validate.add_argument("engagement")

    for command in ("observe", "assess"):
        sub = subparsers.add_parser(command)
        sub.add_argument("engagement")
        sub.add_argument("--target", required=True)
        sub.add_argument(
            "--acknowledge-authorization",
            action="store_true",
            help="Confirme que l'opérateur dispose d'une autorisation explicite et active",
        )
        sub.add_argument("--audit-log", default=".metatron/audit.jsonl")
    assess_parser = subparsers.choices["assess"]
    assess_parser.add_argument("--objective", required=True)
    assess_parser.add_argument("--model", default=os.environ.get("METATRON_MODEL", DEFAULT_MODEL))
    return parser


def _emit(value: Dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _authorized_observation(args: argparse.Namespace, action: str):
    if not args.acknowledge_authorization:
        raise EngagementError("Ajouter --acknowledge-authorization pour confirmer l'autorisation active.")
    engagement = load_engagement(args.engagement)
    origin, target, scope_entry = authorize(engagement, args.target, action)
    if action == "ai_assess":
        authorize(engagement, args.target, "http_observe")
    headers = authentication_headers(scope_entry.auth)
    observation = observe_http(target, origin, auth_headers=headers)
    return engagement, observation


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    run_id = str(uuid.uuid4())
    started = time.monotonic()
    try:
        if args.command == "validate":
            engagement = load_engagement(args.engagement)
            _emit(
                {
                    "engagement_id": engagement.engagement_id,
                    "network_policy": engagement.network_policy,
                    "scope_count": len(engagement.scope),
                    "status": "valid",
                }
            )
            return 0

        action = "http_observe" if args.command == "observe" else "ai_assess"
        engagement, observation = _authorized_observation(args, action)
        output: Dict[str, Any] = observation.to_dict()
        model = None
        if args.command == "assess":
            model = args.model
            output = {
                "observation": output,
                "assessment": assess(output, args.objective, model=model),
            }
        append_event(
            args.audit_log,
            {
                "run_id": run_id,
                "agent": "metatron",
                "action": args.command,
                "engagement_id": engagement.engagement_id,
                "target_origin": observation.target_origin,
                "model": model,
                "state": "completed",
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
        )
        _emit(output)
        return 0
    except (EngagementError, ObservationError, AssessmentError, OSError, json.JSONDecodeError) as exc:
        audit_path = getattr(args, "audit_log", None)
        if audit_path:
            append_event(
                audit_path,
                {
                    "run_id": run_id,
                    "agent": "metatron",
                    "action": args.command,
                    "state": "failed",
                    "error_type": type(exc).__name__,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                },
            )
        print("Erreur: %s" % exc, file=sys.stderr)
        return 2
