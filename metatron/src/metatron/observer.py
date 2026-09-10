from __future__ import annotations

from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from metatron.models import HeaderFinding, Observation


class ObservationError(RuntimeError):
    """Raised when the authorized observation cannot be completed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "permissions-policy": "Permissions-Policy",
    "referrer-policy": "Referrer-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
}


def _findings(headers: Dict[str, str], https: bool) -> List[HeaderFinding]:
    results = []
    for key, label in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and not https:
            continue
        if key in headers:
            results.append(HeaderFinding(label, "present", headers[key]))
        else:
            results.append(HeaderFinding(label, "missing", "En-tête absent de la réponse HEAD."))
    return results


def observe_http(
    target: str,
    target_origin: str,
    auth_headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    opener=None,
) -> Observation:
    request_headers = {"User-Agent": "Metatron/0.1 authorized-security-observer"}
    request_headers.update(auth_headers or {})
    request = Request(target, method="HEAD", headers=request_headers)
    opener = opener or build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except URLError as exc:
        raise ObservationError("La cible autorisée est inaccessible: %s" % exc.reason) from exc
    except OSError as exc:
        raise ObservationError("Échec réseau pendant l'observation autorisée.") from exc

    with response:
        raw_headers = {key.lower(): value for key, value in response.headers.items()}
        safe_headers = {
            key: value for key, value in raw_headers.items() if key in SECURITY_HEADERS
        }
        status = int(response.status)
    return Observation(
        target_origin=target_origin,
        status_code=status,
        headers=safe_headers,
        findings=_findings(safe_headers, urlsplit(target).scheme == "https"),
    )
