import ipaddress
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from metatron.models import EngagementError
from metatron.policy import authentication_headers, authorize, canonical_origin, engagement_from_dict


# Build a reusable valid contract so each test changes only the policy under review.
def contract(origin="https://saas.example", tools=None, network_policy="public_only", max_tool_runs=4):
    return engagement_from_dict(
        {
            "schema_version": 2,
            "engagement_id": "authorized-saas-test",
            "title": "Authorized SaaS test",
            "authorized_by": "System owner",
            "starts_at": "2026-01-01T00:00:00Z",
            "expires_at": "2027-01-01T00:00:00Z",
            "network_policy": network_policy,
            "max_tool_runs": max_tool_runs,
            "scope": [
                {
                    "origin": origin,
                    "allowed_tools": tools or ["dns", "http_headers"],
                    "auth": {"mode": "none"},
                }
            ],
        }
    )


# Supply a stable public address without touching external DNS.
def public_resolver(host, port):
    return [ipaddress.ip_address("93.184.216.34")]


class PolicyTests(unittest.TestCase):
    # Exact origin matching prevents path-based expansion of the approved target.
    def test_authorizes_exact_origin_only(self):
        engagement = contract()
        origin, _ = authorize(
            engagement,
            "https://saas.example/",
            "dns",
            now=datetime(2026, 6, 1, tzinfo=timezone.utc),
            resolver=public_resolver,
        )
        self.assertEqual(origin, "https://saas.example")
        with self.assertRaises(EngagementError):
            authorize(
                engagement,
                "https://saas.example/login",
                "dns",
                now=datetime(2026, 6, 1, tzinfo=timezone.utc),
                resolver=public_resolver,
            )

    # A tool absent from the signed engagement can never enter a plan.
    def test_rejects_unapproved_tool(self):
        with self.assertRaises(EngagementError):
            authorize(
                contract(tools=["dns"]),
                "https://saas.example",
                "nikto",
                now=datetime(2026, 6, 1, tzinfo=timezone.utc),
                resolver=public_resolver,
            )

    # Public engagements must fail closed if any DNS answer is non-public.
    def test_rejects_private_resolution_for_public_scope(self):
        with self.assertRaises(EngagementError):
            authorize(
                contract(),
                "https://saas.example",
                "dns",
                now=datetime(2026, 6, 1, tzinfo=timezone.utc),
                resolver=lambda host, port: [ipaddress.ip_address("127.0.0.1")],
            )

    # Credential values are read only from named environment variables.
    def test_reads_basic_credentials_from_environment(self):
        engagement = engagement_from_dict(
            {
                "schema_version": 2,
                "engagement_id": "auth-test",
                "title": "Auth test",
                "authorized_by": "Owner",
                "starts_at": "2026-01-01T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
                "network_policy": "public_only",
                "max_tool_runs": 1,
                "scope": [
                    {
                        "origin": "https://saas.example",
                        "allowed_tools": ["http_headers"],
                        "auth": {
                            "mode": "basic",
                            "username_env": "TEST_SAAS_USER",
                            "password_env": "TEST_SAAS_PASSWORD",
                        },
                    }
                ],
            }
        )
        with patch.dict(os.environ, {"TEST_SAAS_USER": "alice", "TEST_SAAS_PASSWORD": "secret"}):
            headers = authentication_headers(engagement.scope[0].auth)
        self.assertEqual(headers, {"Authorization": "Basic YWxpY2U6c2VjcmV0"})

    # Canonicalization rejects embedded credentials before any network call.
    def test_rejects_credentials_in_url(self):
        with self.assertRaises(EngagementError):
            canonical_origin("https://user:pass@saas.example")


if __name__ == "__main__":
    unittest.main()
