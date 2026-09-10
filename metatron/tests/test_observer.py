import unittest
from email.message import Message

from metatron.observer import observe_http


class FakeResponse:
    def __init__(self, status, headers):
        self.status = status
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.calls = 0

    def open(self, request, timeout):
        self.request = request
        self.calls += 1
        return self.response


class ObserverTests(unittest.TestCase):
    def test_reports_safe_headers_only(self):
        opener = FakeOpener(
            FakeResponse(
                200,
                {
                    "X-Content-Type-Options": "nosniff",
                    "Set-Cookie": "session=must-not-be-logged",
                },
            )
        )
        observation = observe_http(
            "https://mouci.example/",
            "https://mouci.example",
            auth_headers={"Authorization": "Bearer secret"},
            opener=opener,
        )
        by_control = {item.control: item.status for item in observation.findings}
        self.assertEqual(observation.status_code, 200)
        self.assertEqual(by_control["X-Content-Type-Options"], "present")
        self.assertEqual(by_control["Content-Security-Policy"], "missing")
        self.assertNotIn("set-cookie", observation.headers)
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer secret")
        self.assertEqual(opener.request.get_method(), "HEAD")

    def test_does_not_follow_or_record_redirect_location(self):
        opener = FakeOpener(
            FakeResponse(302, {"Location": "/destination?token=must-not-be-logged"})
        )
        observation = observe_http(
            "https://mouci.example/redirect",
            "https://mouci.example",
            opener=opener,
        )
        self.assertEqual(observation.status_code, 302)
        self.assertNotIn("location", observation.headers)
        self.assertEqual(opener.calls, 1)


if __name__ == "__main__":
    unittest.main()
