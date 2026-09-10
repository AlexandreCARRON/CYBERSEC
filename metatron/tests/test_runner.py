import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from metatron.models import EngagementError, ToolResult
from metatron.planning import create_plan
from metatron.runner import execute_plan
from test_policy import contract, public_resolver


# Return controlled evidence without invoking a network or system binary.
def fake_executor(tool, origin, auth):
    return ToolResult(tool, origin, "completed", 1, None, {"controlled": True})


class RunnerTests(unittest.TestCase):
    # Execution requires the exact plan identifier shown to the operator.
    def test_rejects_wrong_approval(self):
        engagement = contract()
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        plan = create_plan(engagement, "https://saas.example", ["dns"], now=now, resolver=public_resolver)
        with self.assertRaises(EngagementError):
            execute_plan(engagement, plan, "wrong", now=now, resolver=public_resolver)

    # A valid approval performs only the enumerated adapter and writes metadata.
    def test_executes_approved_plan(self):
        engagement = contract()
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        plan = create_plan(engagement, "https://saas.example", ["dns"], now=now, resolver=public_resolver)
        with tempfile.TemporaryDirectory() as directory:
            audit = str(Path(directory) / "audit.jsonl")
            results = execute_plan(
                engagement,
                plan,
                plan.plan_id,
                audit_path=audit,
                now=now,
                resolver=public_resolver,
                tool_executor=fake_executor,
            )
            self.assertEqual([item.tool for item in results], ["dns"])
            self.assertIn('"tool": "dns"', Path(audit).read_text(encoding="utf-8"))
            with self.assertRaises(EngagementError):
                execute_plan(
                    engagement,
                    plan,
                    plan.plan_id,
                    audit_path=audit,
                    now=now,
                    resolver=public_resolver,
                    tool_executor=fake_executor,
                )

    # Noisy tools have a distinct human checkpoint beyond plan approval.
    def test_noisy_tool_requires_second_approval(self):
        engagement = contract(tools=["nikto"])
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        plan = create_plan(engagement, "https://saas.example", ["nikto"], now=now, resolver=public_resolver)
        with self.assertRaises(EngagementError):
            execute_plan(engagement, plan, plan.plan_id, now=now, resolver=public_resolver)


if __name__ == "__main__":
    unittest.main()
