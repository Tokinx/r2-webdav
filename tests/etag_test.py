"""ETag regression checks against the local Wrangler HTTP server.

TEST_URL=http://127.0.0.1:8787 TEST_USERNAME=test TEST_PASSWORD=test \
    python3 -m unittest discover -s tests -p '*_test.py' -v
"""

import base64
import os
import unittest
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET


class EtagTest(unittest.TestCase):
    def setUp(self):
        self.url = os.environ.get("TEST_URL", "http://127.0.0.1:8787").rstrip("/")
        credentials = "{}:{}".format(
            os.environ.get("TEST_USERNAME", "test"),
            os.environ.get("TEST_PASSWORD", "test"),
        )
        self.authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        self.path = "/etag-" + uuid.uuid4().hex

    def request(self, method, body=None, headers=None):
        request_headers = {"Authorization": self.authorization}
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.url + self.path, data=body, headers=request_headers, method=method
        )
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def tearDown(self):
        self.request("DELETE")

    def create(self, body=b"original"):
        status, headers, response_body = self.request("PUT", body)
        self.assertEqual(status, 201, response_body)
        etag = headers.get("ETag")
        self.assertIsNotNone(etag)
        self.assertRegex(etag, r'^"[^"\r\n]+"$')
        return etag

    def assert_stored(self, expected_body, expected_etag):
        status, headers, body = self.request("GET")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, expected_body)
        self.assertEqual(headers.get("ETag"), expected_etag)

    def test_put_get_head_and_propfind_return_the_same_quoted_etag(self):
        etag = self.create()
        self.assert_stored(b"original", etag)
        status, headers, body = self.request("HEAD")
        self.assertEqual(status, 200, body)
        self.assertEqual(headers.get("ETag"), etag)
        self.assertEqual(body, b"")
        status, _, body = self.request(
            "PROPFIND",
            b'<D:propfind xmlns:D="DAV:"><D:prop><D:getetag/></D:prop></D:propfind>',
            {"Content-Type": "application/xml", "Depth": "0"},
        )
        self.assertEqual(status, 207, body)
        self.assertEqual(ET.fromstring(body).findtext(".//{DAV:}getetag"), etag)

    def test_if_none_match_reads_return_304_or_the_content(self):
        etag = self.create()
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                status, headers, body = self.request(method, headers={"If-None-Match": etag})
                self.assertEqual(status, 304, body)
                self.assertEqual(headers.get("ETag"), etag)
                self.assertEqual(body, b"")
                status, headers, body = self.request(method, headers={"If-None-Match": '"different"'})
                self.assertEqual(status, 200, body)
                self.assertEqual(headers.get("ETag"), etag)
                self.assertEqual(body, b"original" if method == "GET" else b"")
        self.assert_stored(b"original", etag)

    def test_if_match_reads_require_the_current_etag(self):
        etag = self.create()
        status, headers, body = self.request("GET", headers={"If-Match": etag})
        self.assertEqual(status, 200, body)
        self.assertEqual(headers.get("ETag"), etag)
        self.assertEqual(body, b"original")
        status, _, body = self.request("GET", headers={"If-Match": '"different"'})
        self.assertEqual(status, 412, body)

    def test_if_match_put_failure_preserves_content_and_success_updates_etag(self):
        etag = self.create()
        status, _, body = self.request("PUT", b"must not be saved", {"If-Match": '"different"'})
        self.assertEqual(status, 412, body)
        self.assert_stored(b"original", etag)
        status, headers, body = self.request("PUT", b"updated", {"If-Match": etag})
        self.assertEqual(status, 204, body)
        updated_etag = headers.get("ETag")
        self.assertIsNotNone(updated_etag)
        self.assertNotEqual(updated_etag, etag)
        self.assert_stored(b"updated", updated_etag)
        status, _, body = self.request("PUT", b"stale overwrite", {"If-Match": etag})
        self.assertEqual(status, 412, body)
        self.assert_stored(b"updated", updated_etag)

    def test_if_none_match_put_rejects_matching_etag_and_accepts_other_etag(self):
        etag = self.create()
        status, _, body = self.request("PUT", b"must not be saved", {"If-None-Match": etag})
        self.assertEqual(status, 412, body)
        self.assert_stored(b"original", etag)
        status, headers, body = self.request("PUT", b"updated", {"If-None-Match": '"different"'})
        self.assertEqual(status, 204, body)
        self.assert_stored(b"updated", headers.get("ETag"))

    def test_if_none_match_star_creates_once_and_does_not_overwrite(self):
        status, headers, body = self.request("PUT", b"created once", {"If-None-Match": "*"})
        self.assertEqual(status, 201, body)
        etag = headers.get("ETag")
        self.assertIsNotNone(etag)
        status, _, body = self.request("PUT", b"must not overwrite", {"If-None-Match": "*"})
        self.assertEqual(status, 412, body)
        self.assert_stored(b"created once", etag)


if __name__ == "__main__":
    unittest.main()
