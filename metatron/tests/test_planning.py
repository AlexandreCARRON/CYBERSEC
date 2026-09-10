import copy
import unittest
from datetime import datetime, timezone

from metatron.models import EngagementError
from metatron.planning import create_plan, plan_from_dict
from test_policy import contract, public_resolver


class PlanningTests(unittest.TestCase):
    # The plan identifier is reproducible for an unchanged payload.
    def test_plan_round_trip_preserves_content_hash(self):
        plan = create_plan(
            contract(),
            "https://saas.example",
            ["dns", "http_headers"],
            now=datetime(2026, 6, 1, tzinfo=timezone.utc),
            resolver=public_resolver,
        )
        rebuilt = plan_from_dict(plan.to_dict())
        self.assertEqual(rebuilt.plan_id, plan.plan_id)

    # Changing a tool after approval invalidates the content-addressed plan.
    def test_rejects_tampered_plan(self):
        plan = create_plan(
            contract(),
            "https://saas.example",
            ["dns"],
            now=datetime(2026, 6, 1, tzinfo=timezone.utc),
            resolver=public_resolver,
        ).to_dict()
        tampered = copy.deepcopy(plan)
        tampered["tools"] = ["http_headers"]
        tampered["risks"] = ["passive"]
        with self.assertRaises(EngagementError):
            plan_from_dict(tampered)

    # Tool count is bounded by the engagement, independently of model behavior.
    def test_enforces_tool_budget(self):
        engagement = contract(max_tool_runs=1)
        with self.assertRaises(EngagementError):
            create_plan(
                engagement,
                "https://saas.example",
                ["dns", "http_headers"],
                now=datetime(2026, 6, 1, tzinfo=timezone.utc),
                resolver=public_resolver,
            )


if __name__ == "__main__":
    unittest.main()
