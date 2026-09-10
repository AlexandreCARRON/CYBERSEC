from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple
from urllib.parse import urlsplit

from metatron.models import AuthConfig, Engagement, EngagementError, ScopeEntry


TOOL_RISKS = {
    "dns": "passive",
    "http_headers": "passive",
    "whois": "passive",
    "nmap_service": "active",
    "whatweb": "active",
    "nikto": "noisy",
}
NETWORK_POLICIES = frozenset({"loopback_only", "private_and_loopback", "public_only"})
AUTH_MODES = frozenset({"none", "basic", "bearer"})
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


# Reduce every URL to a stable HTTP(S) origin before comparing it with scope.
def canonical_origin(value: str) -> str:
    if not isinstance(value, str):
        raise EngagementError("La cible doit être une URL HTTP(S) absolue.")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise EngagementError("La cible doit être une URL HTTP(S) absolue.")
    if parsed.username or parsed.password:
        raise EngagementError("Les identifiants dans l'URL sont interdits.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise EngagementError("Le port de la cible est invalide.") from exc
    default_port = 80 if parsed.scheme == "http" else 443
    host = parsed.hostname.rstrip(".").lower()
    display_host = "[%s]" % host if ":" in host else host
    suffix = "" if port in {None, default_port} else ":%d" % port
    return "%s://%s%s" % (parsed.scheme, display_host, suffix)


# Parse authorization dates into UTC and reject ambiguous naive timestamps.
def parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise EngagementError("%s doit être une date ISO 8601." % field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EngagementError("%s doit être une date ISO 8601." % field) from exc
    if parsed.tzinfo is None:
        raise EngagementError("%s doit inclure un fuseau horaire." % field)
    return parsed.astimezone(timezone.utc)


# Require non-empty ownership and authorization metadata in every contract.
def _required_text(data: Dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise EngagementError("%s est obligatoire." % field)
    return value.strip()


# Load credential references without ever resolving or persisting their values.
def _auth_from_dict(value: Any) -> AuthConfig:
    if not isinstance(value, dict):
        raise EngagementError("auth doit être un objet.")
    mode = value.get("mode")
    if mode not in AUTH_MODES:
        raise EngagementError("Le mode d'authentification est invalide.")
    expected = {
        "none": {"mode"},
        "basic": {"mode", "username_env", "password_env"},
        "bearer": {"mode", "token_env"},
    }[mode]
    if set(value) != expected:
        raise EngagementError("Les références d'authentification ne correspondent pas au mode %s." % mode)
    for field in expected - {"mode"}:
        env_name = value.get(field)
        if not isinstance(env_name, str) or not ENV_NAME.fullmatch(env_name):
            raise EngagementError("%s doit référencer une variable d'environnement." % field)
    return AuthConfig(
        mode=mode,
        username_env=value.get("username_env"),
        password_env=value.get("password_env"),
        token_env=value.get("token_env"),
    )


# Convert the versioned JSON contract into the only runtime authorization object.
def engagement_from_dict(data: Dict[str, Any]) -> Engagement:
    if not isinstance(data, dict):
        raise EngagementError("Le contrat d'engagement doit être un objet JSON.")
    expected_fields = {
        "schema_version",
        "engagement_id",
        "title",
        "authorized_by",
        "starts_at",
        "expires_at",
        "network_policy",
        "max_tool_runs",
        "scope",
    }
    unknown = set(data) - expected_fields
    if unknown:
        raise EngagementError("Champs inconnus: %s" % ", ".join(sorted(unknown)))
    if data.get("schema_version") != 2:
        raise EngagementError("schema_version doit valoir 2.")

    starts_at = parse_datetime(data.get("starts_at"), "starts_at")
    expires_at = parse_datetime(data.get("expires_at"), "expires_at")
    if starts_at >= expires_at:
        raise EngagementError("expires_at doit être postérieur à starts_at.")
    network_policy = data.get("network_policy")
    if network_policy not in NETWORK_POLICIES:
        raise EngagementError("network_policy est invalide.")
    max_tool_runs = data.get("max_tool_runs")
    if not isinstance(max_tool_runs, int) or isinstance(max_tool_runs, bool) or not 1 <= max_tool_runs <= 20:
        raise EngagementError("max_tool_runs doit être un entier compris entre 1 et 20.")

    raw_scope = data.get("scope")
    if not isinstance(raw_scope, list) or not raw_scope:
        raise EngagementError("scope doit contenir au moins une origine.")
    entries = []
    seen = set()
    for item in raw_scope:
        if not isinstance(item, dict) or not {"origin", "allowed_tools"} <= set(item):
            raise EngagementError("Chaque entrée de scope doit définir origin et allowed_tools.")
        if set(item) - {"origin", "allowed_tools", "auth"}:
            raise EngagementError("Une entrée de scope contient un champ inconnu.")
        origin = canonical_origin(item["origin"])
        parsed_origin = urlsplit(item["origin"])
        if parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment:
            raise EngagementError("Une origine de scope ne doit contenir ni chemin, requête ou fragment.")
        tools = item["allowed_tools"]
        if not isinstance(tools, list) or not tools or not all(isinstance(value, str) for value in tools):
            raise EngagementError("allowed_tools doit être une liste non vide.")
        tool_set = frozenset(tools)
        invalid = tool_set - TOOL_RISKS.keys()
        if invalid:
            raise EngagementError("Outils inconnus: %s" % ", ".join(sorted(invalid)))
        if origin in seen:
            raise EngagementError("Origine dupliquée dans le scope: %s" % origin)
        auth = _auth_from_dict(item.get("auth", {"mode": "none"}))
        if auth.mode != "none" and urlsplit(origin).scheme != "https":
            raise EngagementError("Une authentification distante exige une origine HTTPS.")
        seen.add(origin)
        entries.append(ScopeEntry(origin=origin, allowed_tools=tool_set, auth=auth))

    return Engagement(
        schema_version=2,
        engagement_id=_required_text(data, "engagement_id"),
        title=_required_text(data, "title"),
        authorized_by=_required_text(data, "authorized_by"),
        starts_at=starts_at,
        expires_at=expires_at,
        network_policy=network_policy,
        max_tool_runs=max_tool_runs,
        scope=entries,
    )


# Read an engagement from disk without accepting executable configuration.
def load_engagement(path: str) -> Engagement:
    with Path(path).open("r", encoding="utf-8") as handle:
        return engagement_from_dict(json.load(handle))


# Resolve all current addresses so policy checks cover multi-record hostnames.
def resolved_addresses(host: str, port: int) -> Iterable[ipaddress._BaseAddress]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise EngagementError("Impossible de résoudre l'hôte autorisé.") from exc
    addresses = {ipaddress.ip_address(record[4][0]) for record in records}
    if not addresses:
        raise EngagementError("L'hôte autorisé ne résout vers aucune adresse.")
    return addresses


# Enforce the engagement's explicit network class for every resolved address.
def network_allowed(address: ipaddress._BaseAddress, network_policy: str) -> bool:
    if network_policy == "public_only":
        return address.is_global
    if network_policy == "loopback_only":
        return address.is_loopback
    return address.is_loopback or address.is_private


# Authorize one exact origin and one enumerated tool immediately before use.
def authorize(
    engagement: Engagement,
    target: str,
    tool: str,
    now: Optional[datetime] = None,
    resolver: Callable[[str, int], Iterable[ipaddress._BaseAddress]] = resolved_addresses,
) -> Tuple[str, ScopeEntry]:
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if not engagement.starts_at <= instant < engagement.expires_at:
        raise EngagementError("Le contrat d'engagement n'est pas actif.")
    origin = canonical_origin(target)
    if target.rstrip("/") != origin:
        raise EngagementError("La cible d'un plan doit être une origine exacte, sans chemin.")
    entry = next((item for item in engagement.scope if item.origin == origin), None)
    if entry is None:
        raise EngagementError("La cible est hors du périmètre autorisé.")
    if tool not in entry.allowed_tools:
        raise EngagementError("L'outil %s n'est pas autorisé pour cette cible." % tool)
    parsed = urlsplit(origin)
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    addresses = tuple(resolver(parsed.hostname or "", port))
    if not addresses or not all(network_allowed(address, engagement.network_policy) for address in addresses):
        raise EngagementError("La résolution DNS viole la politique réseau de l'engagement.")
    return origin, entry


# Resolve a referenced secret only at the final HTTP boundary.
def _secret(env_name: Optional[str]) -> str:
    value = os.environ.get(env_name or "")
    if not value:
        raise EngagementError("La variable d'environnement %s est absente." % env_name)
    return value


# Build transient authorization headers without returning secret values to logs.
def authentication_headers(auth: AuthConfig) -> Dict[str, str]:
    if auth.mode == "none":
        return {}
    if auth.mode == "bearer":
        return {"Authorization": "Bearer %s" % _secret(auth.token_env)}
    raw = "%s:%s" % (_secret(auth.username_env), _secret(auth.password_env))
    token = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return {"Authorization": "Basic %s" % token}
