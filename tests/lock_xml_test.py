"""LOCK regression checks against the local Wrangler HTTP server.

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


DAV = "{DAV:}"


def lock_xml(scope="exclusive", prefix="", owner="smoke-test"):
    declaration = 'xmlns:{}="DAV:"'.format(prefix) if prefix else 'xmlns="DAV:"'
    tag = prefix + ":" if prefix else ""
    return (
        '<{0}lockinfo {1}><{0}lockscope><{0}{2}/></{0}lockscope>'
        '<{0}locktype><{0}write/></{0}locktype>'
        '<{0}owner>{3}</{0}owner></{0}lockinfo>'
    ).format(tag, declaration, scope, owner)


class LockXmlTest(unittest.TestCase):
    def setUp(self):
        self.url = os.environ.get("TEST_URL", "http://127.0.0.1:8787").rstrip("/")
        credentials = "{}:{}".format(
            os.environ.get("TEST_USERNAME", "test"),
            os.environ.get("TEST_PASSWORD", "test"),
        )
        self.authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        self.path = "/lock-xml-" + uuid.uuid4().hex
        self.tokens = set()

    def request(self, method, body=None, headers=None):
        request_headers = {"Authorization": self.authorization}
        request_headers.update(headers or {})
        if isinstance(body, str):
            body = body.encode()
            request_headers.setdefault("Content-Type", "application/xml")
        request = urllib.request.Request(
            self.url + self.path, data=body, headers=request_headers, method=method
        )
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            token = response.headers.get("Lock-Token")
            if method == "LOCK" and token:
                self.tokens.add(token)
            return response.status, response.headers, response.read().decode()

    def tearDown(self):
        for token in self.tokens:
            self.request("UNLOCK", headers={"Lock-Token": token})
        self.request("DELETE")

    def lock(self, scope="exclusive", prefix="", owner="smoke-test"):
        status, headers, body = self.request("LOCK", lock_xml(scope, prefix, owner))
        self.assertEqual(status, 201, body)
        active = ET.fromstring(body).find(DAV + "lockdiscovery/" + DAV + "activelock")
        self.assertIsNotNone(active)
        self.assertIsNotNone(active.find(DAV + "lockscope/" + DAV + scope))
        self.assertEqual(active.findtext(DAV + "owner"), owner)
        self.assertTrue(headers["Lock-Token"].startswith("<urn:uuid:"))
        return headers["Lock-Token"]

    def test_default_namespace_exclusive_lock_refresh_and_unlock(self):
        token = self.lock()
        self.assertEqual(self.request("LOCK", lock_xml())[0], 423)
        self.assertEqual(self.request("PUT", b"locked")[0], 423)
        status, headers, body = self.request("LOCK", headers={"If": "(" + token + ")"})
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Lock-Token"], token)
        active = ET.fromstring(body).find(DAV + "lockdiscovery/" + DAV + "activelock")
        self.assertEqual(active.findtext(DAV + "owner"), "smoke-test")
        self.assertIsNotNone(active.find(DAV + "lockscope/" + DAV + "exclusive"))
        self.assertEqual(self.request("UNLOCK")[0], 400)
        self.assertEqual(self.request("UNLOCK", headers={"Lock-Token": token})[0], 204)
        self.assertIn(self.request("PUT", b"unlocked")[0], (200, 201, 204))

    def test_explicit_prefix_exclusive_lock_and_owner(self):
        token = self.lock(prefix="D", owner="prefixed-owner")
        self.assertEqual(self.request("UNLOCK", headers={"Lock-Token": token})[0], 204)

    def test_shared_locks_coexist_and_unlock_independently(self):
        first = self.lock("shared", "D", "shared-owner-1")
        status, headers, body = self.request("LOCK", lock_xml("shared", "other", "shared-owner-2"))
        self.assertEqual(status, 201, body)
        second = headers["Lock-Token"]
        self.assertNotEqual(first, second)
        locks = ET.fromstring(body).findall(DAV + "lockdiscovery/" + DAV + "activelock")
        self.assertEqual(len(locks), 2)
        self.assertTrue(all(lock.find(DAV + "lockscope/" + DAV + "shared") is not None for lock in locks))
        self.assertEqual(self.request("LOCK", lock_xml(), {"If": "(" + first + ")"})[0], 423)
        status, _, body = self.request("LOCK", headers={"If": "(" + first + ")"})
        self.assertEqual(status, 200, body)
        self.assertEqual(len(ET.fromstring(body).findall(".//" + DAV + "shared")), 2)
        self.assertEqual(self.request("UNLOCK", headers={"Lock-Token": first})[0], 204)
        self.assertEqual(self.request("PUT", b"still locked")[0], 423)
        self.assertIn(self.request("PUT", b"authorized", {"If": "(" + second + ")"})[0], (200, 201, 204))
        self.assertEqual(self.request("UNLOCK", headers={"Lock-Token": second})[0], 204)
        self.assertIn(self.request("PUT", b"unlocked")[0], (200, 201, 204))

    def test_invalid_xml_namespaces_and_lock_structure_are_rejected(self):
        valid = lock_xml()
        invalid_bodies = {
            "mismatched XML": valid.replace("</lockinfo>", "</wrong>"),
            "unclosed XML": valid.replace("<exclusive/>", "<exclusive>"),
            "wrong root namespace": valid.replace('xmlns="DAV:"', 'xmlns="urn:other"'),
            "no namespace": valid.replace(' xmlns="DAV:"', ""),
            "wrong write namespace": valid.replace("<write/>", '<write xmlns="urn:other"/>'),
            "wrong scope namespace": valid.replace("<exclusive/>", '<exclusive xmlns="urn:other"/>'),
            "missing lockscope": valid.replace("<lockscope><exclusive/></lockscope>", ""),
            "two scopes": valid.replace("<exclusive/>", "<exclusive/><shared/>"),
            "nested write only": valid.replace("<write/>", "<wrapper><write/></wrapper>"),
            "wrong root": valid.replace("lockinfo", "other"),
        }
        for label, body in invalid_bodies.items():
            with self.subTest(label=label):
                self.assertEqual(self.request("LOCK", body)[0], 400)
                self.assertEqual(self.request("HEAD")[0], 404)

    def test_foreign_shared_and_owner_do_not_override_dav_elements(self):
        body = lock_xml().replace(
            "<owner>smoke-test</owner>",
            '<x:shared xmlns:x="urn:other"/><x:owner xmlns:x="urn:other">foreign</x:owner>',
        )
        status, _, response_body = self.request("LOCK", body)
        self.assertEqual(status, 201, response_body)
        active = ET.fromstring(response_body).find(DAV + "lockdiscovery/" + DAV + "activelock")
        self.assertIsNotNone(active.find(DAV + "lockscope/" + DAV + "exclusive"))
        self.assertIsNone(active.find(DAV + "owner"))

    def test_empty_refresh_without_a_lock_is_rejected(self):
        self.assertEqual(self.request("LOCK")[0], 400)
        self.assertEqual(self.request("HEAD")[0], 404)


if __name__ == "__main__":
    unittest.main()
