from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from metatron.models import Engagement, EngagementError, ExecutionPlan
from metatron.policy import TOOL_RISKS, authorize, canonical_origin, parse_datetime


# Hash a canonical payload so approval is bound to exact target, tools, and expiry.
def _plan_id(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


# Create a short-lived plan after deterministic scope checks, without side effects.
def create_plan(
    engagement: Engagement,
    target: str,
    tools: Iterable[str],
    now: Optional[datetime] = None,
    ttl_minutes: int = 15,
    resolver=None,
) -> ExecutionPlan:
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    requested = list(tools)
    if not requested or len(requested) > engagement.max_tool_runs:
        raise EngagementError("Le nombre d'outils demandé dépasse le budget de l'engagement.")
    if len(requested) != len(set(requested)):
        raise EngagementError("Un plan ne peut pas contenir deux fois le même outil.")
    if not 1 <= ttl_minutes <= 60:
        raise EngagementError("La durée de validité du plan doit être comprise entre 1 et 60 minutes.")
    origin = ""
    for tool in requested:
        if tool not in TOOL_RISKS:
            raise EngagementError("Outil inconnu: %s" % tool)
        kwargs = {"now": instant}
        if resolver is not None:
            kwargs["resolver"] = resolver
        authorized_origin, _ = authorize(engagement, target, tool, **kwargs)
        origin = authorized_origin
    expires_at = min(engagement.expires_at, instant + timedelta(minutes=ttl_minutes))
    if expires_at <= instant:
        raise EngagementError("Le plan n'aurait aucune durée de validité.")
    payload = {
        "schema_version": 1,
        "engagement_id": engagement.engagement_id,
        "target_origin": origin,
        "tools": requested,
        "risks": [TOOL_RISKS[tool] for tool in requested],
        "created_at": instant.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
    }
    return ExecutionPlan(plan_id=_plan_id(payload), **{
        "schema_version": 1,
        "engagement_id": payload["engagement_id"],
        "target_origin": payload["target_origin"],
        "tools": payload["tools"],
        "risks": payload["risks"],
        "created_at": instant,
        "expires_at": expires_at,
    })


# Rebuild a plan from JSON and verify its content-addressed identifier.
def plan_from_dict(data: Dict[str, Any]) -> ExecutionPlan:
    expected = {
        "schema_version",
        "plan_id",
        "engagement_id",
        "target_origin",
        "tools",
        "risks",
        "created_at",
        "expires_at",
    }
    if not isinstance(data, dict) or set(data) != expected or data.get("schema_version") != 1:
        raise EngagementError("Le plan d'exécution est invalide.")
    if (
        not isinstance(data.get("tools"), list)
        or not data["tools"]
        or len(data["tools"]) != len(set(data["tools"]))
        or not all(isinstance(item, str) for item in data["tools"])
    ):
        raise EngagementError("La liste d'outils du plan est invalide.")
    if data.get("risks") != [TOOL_RISKS.get(tool) for tool in data["tools"]]:
        raise EngagementError("Les niveaux de risque du plan sont incohérents.")
    payload = {key: data[key] for key in expected - {"plan_id"}}
    if data.get("plan_id") != _plan_id(payload):
        raise EngagementError("L'identifiant du plan ne correspond pas à son contenu.")
    created_at = parse_datetime(data["created_at"], "created_at")
    expires_at = parse_datetime(data["expires_at"], "expires_at")
    if created_at >= expires_at or expires_at - created_at > timedelta(minutes=60):
        raise EngagementError("La fenêtre temporelle du plan est invalide.")
    if not isinstance(data.get("engagement_id"), str) or not data["engagement_id"].strip():
        raise EngagementError("L'identifiant d'engagement du plan est invalide.")
    if data.get("target_origin") != canonical_origin(data.get("target_origin")):
        raise EngagementError("La cible du plan doit être une origine canonique.")
    return ExecutionPlan(
        schema_version=1,
        plan_id=data["plan_id"],
        engagement_id=data["engagement_id"],
        target_origin=data["target_origin"],
        tools=list(data["tools"]),
        risks=list(data["risks"]),
        created_at=created_at,
        expires_at=expires_at,
    )


# Read and validate a plan before the execution command can inspect it.
def load_plan(path: str) -> ExecutionPlan:
    with Path(path).open("r", encoding="utf-8") as handle:
        return plan_from_dict(json.load(handle))


# Persist a non-secret plan atomically enough for local CLI use.
def save_plan(plan: ExecutionPlan, path: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(destination)
