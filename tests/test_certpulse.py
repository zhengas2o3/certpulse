import datetime as dt
import unittest
from unittest import mock

from certpulse import CertResult, check_host, parse_target
from certpulse import core

FAKE_CERT = {
    "subject": ((("commonName", "example.test"),),),
    "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test CA R1"),)),
    "notAfter": "Jan 31 12:00:00 2030 GMT",
    "subjectAltName": (("DNS", "example.test"), ("DNS", "www.example.test"), ("IP Address", "127.0.0.1")),
}


class ParseTargetTests(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(parse_target("example.com"), ("example.com", 443, None))
        self.assertEqual(parse_target("example.com:8443"), ("example.com", 8443, None))
        self.assertEqual(parse_target("https://example.com/path?q=1"), ("example.com", 443, None))
        self.assertEqual(parse_target("https://example.com:9443/x"), ("example.com", 9443, None))
        self.assertEqual(parse_target("[2001:db8::1]:8443"), ("2001:db8::1", 8443, None))
        self.assertEqual(parse_target("10.0.0.5:443@internal.example"), ("10.0.0.5", 443, "internal.example"))

    def test_bad(self):
        with self.assertRaises(ValueError):
            parse_target("host:70000")
        with self.assertRaises(ValueError):
            parse_target("")


class StatusTests(unittest.TestCase):
    def test_thresholds(self):
        def r(days):
            return CertResult("t", "t", 443, ok=True, days_left=days)
        self.assertEqual(r(100).status(30, 7), "OK")
        self.assertEqual(r(20).status(30, 7), "WARNING")
        self.assertEqual(r(3).status(30, 7), "CRITICAL")
        self.assertEqual(r(-1).status(30, 7), "EXPIRED")
        self.assertEqual(CertResult("t", "t", 443, ok=False, error="x").status(30, 7), "ERROR")


class CheckHostTests(unittest.TestCase):
    def test_success(self):
        now = dt.datetime(2030, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
        with mock.patch.object(core, "_fetch", return_value=(FAKE_CERT, "TLSv1.3")):
            res = check_host("example.test", now=now)
        self.assertTrue(res.ok)
        self.assertEqual(res.days_left, 30.0)
        self.assertEqual(res.issuer, "Test CA R1")
        self.assertEqual(res.subject, "example.test")
        self.assertEqual(res.sans, ["example.test", "www.example.test"])
        self.assertTrue(res.verified)

    def test_connection_error(self):
        with mock.patch.object(core, "_fetch", side_effect=ConnectionRefusedError("refused")):
            res = check_host("example.test:1")
        self.assertFalse(res.ok)
        self.assertIn("refused", res.error)

    def test_unverified_still_reports_expiry(self):
        import ssl
        err = ssl.SSLCertVerificationError("bad")
        err.verify_message = "certificate has expired"
        calls = [err, (FAKE_CERT, "TLSv1.2")]

        def fake(*a, **k):
            item = calls.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with mock.patch.object(core, "_fetch", side_effect=fake):
            res = check_host("example.test")
        self.assertTrue(res.ok)
        self.assertFalse(res.verified)
        self.assertIn("expired", res.error)


if __name__ == "__main__":
    unittest.main()
