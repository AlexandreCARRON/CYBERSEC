import ipaddress
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from metatron.models import EngagementError
from metatron.policy import authentication_headers, authorize, engagement_from_dict


def contract(origin="http://127.0.0.1:8000", network_policy="loopback_only", auth=None):
    scope = {
        "origin": origin,
        "allowed_actions": ["http_observe", "ai_assess"],
    }
    if auth:
        scope["auth"] = auth
    return engagement_from_dict(
        {
            "schema_version": 1,
            "engagement_id": "test",
            "title": "Test autorisé",
            "authorized_by": "Fixture owner",
            "starts_at": "2026-01-01T00:00:00Z",
            "expires_at": "2027-01-01T00:00:00Z",
            "network_policy": network_policy,
            "scope": [scope],
        }
    )


NOW = datetime(2026, 9, 10, tzinfo=timezone.utc)


class PolicyTests(unittest.TestCase):
    def test_authorizes_path_on_exact_origin(self):
        origin, target, entry = authorize(
            contract(),
            "http://127.0.0.1:8000/login",
            "http_observe",
            now=NOW,
            resolver=lambda host, port: [ipaddress.ip_address("127.0.0.1")],
        )
        self.assertEqual(origin, "http://127.0.0.1:8000")
        self.assertEqual(target, "http://127.0.0.1:8000/login")
        self.assertEqual(entry.auth.mode, "none")

    def test_allows_public_address_only_with_public_policy(self):
        origin, _, _ = authorize(
            contract("https://mouci.example", "public_only"),
            "https://mouci.example/login",
            "http_observe",
            now=NOW,
            resolver=lambda host, port: [ipaddress.ip_address("93.184.216.34")],
        )
        self.assertEqual(origin, "https://mouci.example")

    def test_rejects_out_of_scope_origin(self):
        with self.assertRaisesRegex(EngagementError, "hors du périmètre"):
            authorize(
                contract(),
                "http://127.0.0.1:9000/",
                "http_observe",
                now=NOW,
                resolver=lambda host, port: [ipaddress.ip_address("127.0.0.1")],
            )

    def test_rejects_public_resolution_under_loopback_policy(self):
        with self.assertRaisesRegex(EngagementError, "politique réseau"):
            authorize(
                contract(origin="https://example.test"),
                "https://example.test/",
                "http_observe",
                now=NOW,
                resolver=lambda host, port: [ipaddress.ip_address("203.0.113.10")],
            )

    def test_rejects_expired_contract(self):
        with self.assertRaisesRegex(EngagementError, "n'est pas actif"):
            authorize(
                contract(),
                "http://127.0.0.1:8000/",
                "http_observe",
                now=datetime(2028, 1, 1, tzinfo=timezone.utc),
                resolver=lambda host, port: [ipaddress.ip_address("127.0.0.1")],
            )

    def test_reads_basic_credentials_from_environment(self):
        engagement = contract(
            origin="https://mouci.example",
            network_policy="public_only",
            auth={
                "mode": "basic",
                "username_env": "TEST_MOUCI_USER",
                "password_env": "TEST_MOUCI_PASSWORD",
            }
        )
        with patch.dict(os.environ, {"TEST_MOUCI_USER": "alice", "TEST_MOUCI_PASSWORD": "secret"}):
            headers = authentication_headers(engagement.scope[0].auth)
        self.assertEqual(headers["Authorization"], "Basic YWxpY2U6c2VjcmV0")


if __name__ == "__main__":
    unittest.main()
