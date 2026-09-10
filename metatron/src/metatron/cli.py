from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from metatron.assistant import assess
from metatron.audit import append_event
from metatron.models import AssessmentError, EngagementError, ExecutionError
from metatron.planning import create_plan, load_plan, save_plan
from metatron.policy import load_engagement
from metatron.runner import execute_plan


# Build explicit subcommands so planning cannot accidentally perform network actions.
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Metatron, assistant de pentest autorisé")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Valider un contrat d'engagement")
    validate.add_argument("engagement")

    plan = subparsers.add_parser("plan", help="Créer un plan signé par son contenu, sans l'exécuter")
    plan.add_argument("engagement")
    plan.add_argument("--target", required=True)
    plan.add_argument("--tool", action="append", required=True, dest="tools")
    plan.add_argument("--ttl-minutes", type=int, default=15)
    plan.add_argument("--output", required=True)

    execute = subparsers.add_parser("execute", help="Exécuter un plan préalablement approuvé")
    execute.add_argument("engagement")
    execute.add_argument("--plan", required=True)
    execute.add_argument("--approve", required=True, help="Identifiant exact du plan approuvé")
    execute.add_argument("--approve-noisy", action="store_true")
    execute.add_argument("--audit-log", default=".metatron/audit.jsonl")

    report = subparsers.add_parser("assess", help="Analyser un fichier de preuves avec Ollama local")
    report.add_argument("--evidence", required=True)
    report.add_argument("--objective", required=True)
    report.add_argument("--model", default=os.environ.get("METATRON_MODEL", ""))
    report.add_argument("--endpoint", default=os.environ.get("METATRON_OLLAMA_URL", "http://127.0.0.1:11434"))
    report.add_argument("--audit-log", default=".metatron/audit.jsonl")
    return parser


# Emit machine-readable output for repeatable CLI workflows.
def _emit(value: Dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


# Read evidence as inert JSON and reject every executable serialization format.
def _load_json(path: str) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise EngagementError("Le fichier de preuves doit contenir un objet JSON.")
    return value


# Route the four lifecycle phases while preserving their side-effect boundaries.
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
        if args.command == "plan":
            engagement = load_engagement(args.engagement)
            plan = create_plan(
                engagement,
                args.target,
                args.tools,
                ttl_minutes=args.ttl_minutes,
            )
            save_plan(plan, args.output)
            _emit(plan.to_dict())
            return 0
        if args.command == "execute":
            engagement = load_engagement(args.engagement)
            plan = load_plan(args.plan)
            results = execute_plan(
                engagement,
                plan,
                args.approve,
                approve_noisy=args.approve_noisy,
                audit_path=args.audit_log,
            )
            _emit({"plan_id": plan.plan_id, "results": [result.to_dict() for result in results]})
            return 0

        evidence = _load_json(args.evidence)
        assessment = assess(evidence, args.objective, args.model, endpoint=args.endpoint)
        append_event(
            args.audit_log,
            {
                "run_id": run_id,
                "agent": "metatron",
                "action": "assess",
                "model": args.model,
                "state": "completed",
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
        )
        _emit(assessment)
        return 0
    except (AssessmentError, EngagementError, ExecutionError, OSError, json.JSONDecodeError) as exc:
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
