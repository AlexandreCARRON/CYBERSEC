import json
import unittest

from metatron.assistant import AssessmentError, assess


VALID_ASSESSMENT = {
    "summary": "Deux contrôles sont absents.",
    "findings": [
        {
            "title": "CSP absente",
            "severity": "low",
            "evidence": "En-tête non observé.",
            "recommendation": "Définir une politique adaptée.",
        }
    ],
    "next_tests": [
        {
            "name": "Vérification manuelle",
            "purpose": "Confirmer le comportement applicatif.",
            "requires_human_approval": True,
        }
    ],
}


class FakeResponses:
    def __init__(self, payload):
        self.payload = payload
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return type("Response", (), {"output_text": json.dumps(self.payload)})()


class FakeClient:
    def __init__(self, payload):
        self.responses = FakeResponses(payload)


class AssistantTests(unittest.TestCase):
    def test_uses_structured_outputs_without_storage(self):
        client = FakeClient(VALID_ASSESSMENT)
        result = assess({"status_code": 200}, "Revue SaaS autorisée", client=client)
        self.assertEqual(result, VALID_ASSESSMENT)
        self.assertFalse(client.responses.kwargs["store"])
        self.assertEqual(client.responses.kwargs["text"]["format"]["type"], "json_schema")

    def test_rejects_invalid_model_output(self):
        client = FakeClient({"summary": "incomplet"})
        with self.assertRaises(AssessmentError):
            assess({}, "Revue SaaS autorisée", client=client)


if __name__ == "__main__":
    unittest.main()
