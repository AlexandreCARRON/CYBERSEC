from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet, List, Optional


class EngagementError(ValueError):
    """Raised when an engagement contract is invalid or out of scope."""


@dataclass(frozen=True)
class AuthConfig:
    mode: str
    username_env: Optional[str] = None
    password_env: Optional[str] = None
    token_env: Optional[str] = None


@dataclass(frozen=True)
class ScopeEntry:
    origin: str
    allowed_actions: FrozenSet[str]
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
    scope: List[ScopeEntry]


@dataclass(frozen=True)
class HeaderFinding:
    control: str
    status: str
    evidence: str


@dataclass(frozen=True)
class Observation:
    target_origin: str
    status_code: int
    headers: Dict[str, str]
    findings: List[HeaderFinding]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
