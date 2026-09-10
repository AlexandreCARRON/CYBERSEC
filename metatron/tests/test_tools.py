import unittest

from metatron.tools import _command, _safe_redirect_origin


class ToolTests(unittest.TestCase):
    # Fixed argv templates expose no channel for model-supplied flags or commands.
    def test_command_uses_only_registered_template(self):
        argv = list(_command("nmap_service", "https://saas.example"))
        self.assertEqual(argv, ["nmap", "-sV", "-sC", "-T3", "--open", "saas.example"])

    # Redirect evidence is reduced to an origin and never includes a path or token.
    def test_redirect_evidence_drops_sensitive_path(self):
        value = _safe_redirect_origin("https://login.example/callback?token=secret")
        self.assertEqual(value, "https://login.example")

    # Malformed destination ports are represented as invalid data, never raised.
    def test_malformed_redirect_is_inert(self):
        self.assertEqual(_safe_redirect_origin("https://login.example:not-a-port/path"), "relative-or-invalid")


if __name__ == "__main__":
    unittest.main()
