from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from metatron.audit import append_event, claim_plan
from metatron.models import Engagement, EngagementError, ExecutionError, ExecutionPlan, ToolResult
from metatron.planning import plan_from_dict
from metatron.policy import TOOL_RISKS, authorize
from metatron.tools import execute_tool


# Execute a content-addressed plan only after exact approval and fresh scope checks.
def execute_plan(
    engagement: Engagement,
    plan: ExecutionPlan,
    approval: str,
    approve_noisy: bool = False,
    audit_path: str = ".metatron/audit.jsonl",
    now: Optional[datetime] = None,
    resolver=None,
    tool_executor: Callable[..., ToolResult] = execute_tool,
) -> List[ToolResult]:
    plan_from_dict(plan.to_dict())
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if approval != plan.plan_id:
        raise EngagementError("L'approbation ne correspond pas à l'identifiant du plan.")
    if engagement.engagement_id != plan.engagement_id:
        raise EngagementError("Le plan appartient à un autre engagement.")
    if not plan.created_at <= instant < plan.expires_at:
        raise EngagementError("Le plan n'est pas actif ou a expiré.")
    if len(plan.tools) > engagement.max_tool_runs:
        raise EngagementError("Le plan dépasse le budget courant de l'engagement.")
    if plan.risks != [TOOL_RISKS.get(tool) for tool in plan.tools]:
        raise EngagementError("Les niveaux de risque du plan sont incohérents.")
    if "noisy" in plan.risks and not approve_noisy:
        raise EngagementError("Un plan bruyant exige --approve-noisy.")
    if not claim_plan(audit_path, plan.plan_id):
        raise EngagementError("Ce plan a déjà été tenté; créer et approuver un nouveau plan.")

    run_id = str(uuid.uuid4())
    results = []
    for tool in plan.tools:
        check_instant = instant if now is not None else datetime.now(timezone.utc)
        if check_instant >= plan.expires_at:
            raise EngagementError("Le plan a expiré pendant l'exécution.")
        kwargs: Dict[str, object] = {"now": check_instant}
        if resolver is not None:
            kwargs["resolver"] = resolver
        origin, scope_entry = authorize(engagement, plan.target_origin, tool, **kwargs)
        try:
            result = tool_executor(tool, origin, scope_entry.auth)
        except (ExecutionError, OSError) as exc:
            append_event(
                audit_path,
                {
                    "run_id": run_id,
                    "agent": "metatron",
                    "action": "execute",
                    "plan_id": plan.plan_id,
                    "engagement_id": engagement.engagement_id,
                    "target_origin": origin,
                    "tool": tool,
                    "state": "failed",
                    "error_type": type(exc).__name__,
                },
            )
            raise
        append_event(
            audit_path,
            {
                "run_id": run_id,
                "agent": "metatron",
                "action": "execute",
                "plan_id": plan.plan_id,
                "engagement_id": engagement.engagement_id,
                "target_origin": origin,
                "tool": tool,
                "state": result.state,
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
            },
        )
        results.append(result)
    return results
