import json
import unittest
from pathlib import Path

from metatron.assistant import ASSESSMENT_SCHEMA


ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_assessment_schema_matches_runtime(self):
        with (ROOT / "schemas" / "assessment.schema.json").open(encoding="utf-8") as handle:
            documented = json.load(handle)
        documented.pop("$schema")
        documented.pop("$id")
        documented.pop("title")
        self.assertEqual(documented, ASSESSMENT_SCHEMA)

    def test_agent_references_all_evaluations(self):
        with (ROOT / "agent.json").open(encoding="utf-8") as handle:
            agent = json.load(handle)
        with (ROOT / "evals" / "cases.json").open(encoding="utf-8") as handle:
            evaluations = json.load(handle)
        self.assertEqual(
            set(agent["evaluations"]),
            {case["id"] for case in evaluations["cases"]},
        )


if __name__ == "__main__":
    unittest.main()
