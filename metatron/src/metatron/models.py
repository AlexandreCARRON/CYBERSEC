from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet, List, Optional


class EngagementError(ValueError):
    """Raised when an engagement, plan, or requested action is invalid."""


class ExecutionError(RuntimeError):
    """Raised when an approved tool cannot be executed safely."""


class AssessmentError(RuntimeError):
    """Raised when the optional local model returns an invalid assessment."""


@dataclass(frozen=True)
class AuthConfig:
    mode: str
    username_env: Optional[str] = None
    password_env: Optional[str] = None
    token_env: Optional[str] = None


@dataclass(frozen=True)
class ScopeEntry:
    origin: str
    allowed_tools: FrozenSet[str]
    auth: AuthConfig


@dataclass(frozen=True)
class Engagement:
    schema_version: int
    engagement_id: str
    title: str
    authorized_by: str
    starts_at: datetime
    expires_at: datetime
    network_policy: str
    max_tool_runs: int
    scope: List[ScopeEntry]


@dataclass(frozen=True)
class ExecutionPlan:
    schema_version: int
    plan_id: str
    engagement_id: str
    target_origin: str
    tools: List[str]
    risks: List[str]
    created_at: datetime
    expires_at: datetime

    # Serialize timestamps explicitly so plan hashes and files stay portable.
    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["created_at"] = self.created_at.isoformat().replace("+00:00", "Z")
        value["expires_at"] = self.expires_at.isoformat().replace("+00:00", "Z")
        return value


@dataclass(frozen=True)
class ToolResult:
    tool: str
    target_origin: str
    state: str
    duration_ms: int
    exit_code: Optional[int]
    evidence: Dict[str, Any]

    # Keep the execution envelope JSON-compatible for audit and evaluation.
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
