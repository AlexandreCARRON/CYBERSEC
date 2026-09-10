from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


# Append one non-secret event so execution remains traceable without a database.
def append_event(path: str, event: Dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    record = dict(event)
    record["recorded_at"] = datetime.now(timezone.utc).isoformat()
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


# Refuse accidental replay once any tool attempt for a plan is journaled.
def claim_plan(path: str, plan_id: str) -> bool:
    audit = Path(path)
    claims = audit.parent / (audit.name + ".claims")
    claims.mkdir(parents=True, exist_ok=True)
    claim = claims / plan_id
    try:
        descriptor = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    os.close(descriptor)
    return True
