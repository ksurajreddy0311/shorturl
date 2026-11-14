import unittest
import json
from app import app, links_db, is_valid_url, inspect_url_security

class TestURLShortener(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        # Keep clean in-memory state for testing
        links_db.clear()

    def test_url_validation_valid(self):
        self.assertTrue(is_valid_url("https://www.google.com"))
        self.assertTrue(is_valid_url("http://github.com/test"))
        self.assertTrue(is_valid_url("http://localhost:5000/test"))

    def test_url_validation_invalid(self):
        self.assertFalse(is_valid_url("javascript:alert(1)"))
        self.assertFalse(is_valid_url("ftp://example.com/file.zip"))
        self.assertFalse(is_valid_url("not_a_valid_url"))
        self.assertFalse(is_valid_url(""))
        self.assertFalse(is_valid_url("http://"))

    def test_malicious_detection(self):
        # Raw IP address
        is_susp, _ = inspect_url_security("http://192.168.1.1/login")
        self.assertTrue(is_susp)

        # Suspicious keyword
        is_susp, _ = inspect_url_security("https://example.com/claim-reward-today")
        self.assertTrue(is_susp)

        # Suspicious TLD
        is_susp, _ = inspect_url_security("http://freeprize.tk")
        self.assertTrue(is_susp)

        # Safe link
        is_susp, reason = inspect_url_security("https://en.wikipedia.org/wiki/Python")
        self.assertFalse(is_susp)
        self.assertEqual(reason, "Safe & Verified")

    def test_api_shorten_valid(self):
        response = self.client.post(
            "/api/shorten",
            data=json.dumps({"url": "https://python.org"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("short_code", data)
        self.assertIn("/r/", data["short_url"])
        self.assertEqual(data["original_url"], "https://python.org")

    def test_api_shorten_invalid_scheme(self):
        response = self.client.post(
            "/api/shorten",
            data=json.dumps({"url": "ftp://files.example.com"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])

    def test_api_links_listing(self):
        # Shorten 1 link
        self.client.post(
            "/api/shorten",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        response = self.client.get("/api/links")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["links"]), 1)

    def test_redirect_and_clicks(self):
        # 1. Shorten
        res = self.client.post(
            "/api/shorten",
            data=json.dumps({"url": "https://example.org"}),
            content_type="application/json"
        )
        code = res.get_json()["short_code"]

        # 2. Visit redirect endpoint
        red_res = self.client.get(f"/r/{code}")
        self.assertEqual(red_res.status_code, 302)
        self.assertEqual(red_res.headers["Location"], "https://example.org")

        # 3. Check clicks count incremented
        self.assertEqual(links_db[code]["clicks"], 1)

if __name__ == "__main__":
    unittest.main()
