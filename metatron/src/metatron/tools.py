from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlsplit

from metatron.models import AuthConfig, ExecutionError, ToolResult
from metatron.policy import authentication_headers


MAX_EVIDENCE_CHARS = 65_536
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-security-policy",
        "content-type",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
        "referrer-policy",
        "server",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    }
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Turn redirects into observable responses so they cannot pivot to another host.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


# Trim untrusted tool output before it reaches audit storage or an optional model.
def _bounded(value: str) -> str:
    if len(value) <= MAX_EVIDENCE_CHARS:
        return value
    return value[:MAX_EVIDENCE_CHARS] + "\n[truncated]"


# Return selected non-cookie response headers from one verified HEAD request.
def _http_headers(origin: str, auth: AuthConfig, timeout_seconds: int) -> Dict[str, Any]:
    headers = {"User-Agent": "Metatron-Control-Plane/0.2", **authentication_headers(auth)}
    request = urllib.request.Request(origin + "/", headers=headers, method="HEAD")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=timeout_seconds)
    except urllib.error.HTTPError as exc:
        response = exc
    try:
        selected = {
            key.lower(): value
            for key, value in response.headers.items()
            if key.lower() in SAFE_RESPONSE_HEADERS
        }
        location = response.headers.get("Location")
        return {
            "status_code": response.getcode(),
            "headers": selected,
            "redirect_observed": bool(location),
            "redirect_origin": _safe_redirect_origin(location),
        }
    finally:
        response.close()


# Record only the destination origin of a redirect and never follow it.
def _safe_redirect_origin(location: Optional[str]) -> Optional[str]:
    if not location:
        return None
    parsed = urlsplit(location)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "relative-or-invalid"
    try:
        port = "" if parsed.port is None else ":%d" % parsed.port
    except ValueError:
        return "relative-or-invalid"
    return "%s://%s%s" % (parsed.scheme, parsed.hostname.lower(), port)


# Resolve the approved hostname for evidence without accepting a second target.
def _dns(origin: str) -> Dict[str, Any]:
    parsed = urlsplit(origin)
    records = socket.getaddrinfo(parsed.hostname or "", parsed.port or 443, type=socket.SOCK_STREAM)
    addresses = sorted({record[4][0] for record in records})
    return {"addresses": addresses}


# Construct fixed argv templates; the model and operator cannot add raw flags.
def _command(tool: str, origin: str) -> Iterable[str]:
    parsed = urlsplit(origin)
    host = parsed.hostname or ""
    templates = {
        "whois": ["whois", host],
        "nmap_service": ["nmap", "-sV", "-sC", "-T3", "--open", host],
        "whatweb": ["whatweb", "--no-errors", "--color=never", "--aggression=1", origin],
        "nikto": ["nikto", "-host", origin, "-nointeractive"],
    }
    return templates[tool]


# Run a fixed local adapter with a clean environment, timeout, and bounded output.
def _subprocess_tool(tool: str, origin: str, timeout_seconds: int) -> Dict[str, Any]:
    argv = list(_command(tool, origin))
    executable = shutil.which(argv[0])
    if not executable:
        raise ExecutionError("L'outil local %s n'est pas installé." % argv[0])
    argv[0] = executable
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.path.dirname(executable) + os.pathsep + os.defpath,
            },
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExecutionError("L'outil %s a dépassé son délai." % tool) from exc
    return {
        "argv_template": tool,
        "exit_code": result.returncode,
        "stdout": _bounded(result.stdout),
        "stderr": _bounded(result.stderr),
    }


# Execute exactly one enumerated adapter and return a structured evidence envelope.
def execute_tool(
    tool: str,
    origin: str,
    auth: AuthConfig,
    timeout_seconds: int = 120,
) -> ToolResult:
    started = time.monotonic()
    exit_code = None
    if tool == "http_headers":
        evidence = _http_headers(origin, auth, timeout_seconds)
    elif tool == "dns":
        evidence = _dns(origin)
    elif tool in {"whois", "nmap_service", "whatweb", "nikto"}:
        evidence = _subprocess_tool(tool, origin, timeout_seconds)
        exit_code = evidence["exit_code"]
    else:
        raise ExecutionError("Adaptateur inconnu: %s" % tool)
    json.dumps(evidence, ensure_ascii=False)
    return ToolResult(
        tool=tool,
        target_origin=origin,
        state="completed" if exit_code in {None, 0} else "failed",
        duration_ms=round((time.monotonic() - started) * 1000),
        exit_code=exit_code,
        evidence=evidence,
    )
