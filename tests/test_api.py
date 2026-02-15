import unittest
from unittest.mock import patch

from app.asn_lookup import ASNResult
from app.main import RateLimiter, _batch_lookup, _single_lookup


class TestASNAPI(unittest.TestCase):
    def test_rate_limiter_blocks_after_threshold(self) -> None:
        limiter = RateLimiter(max_requests=2, window_sec=10)
        self.assertEqual(limiter.check("127.0.0.1", now=1000.0), (True, -1))
        self.assertEqual(limiter.check("127.0.0.1", now=1001.0), (True, -1))
        allowed, retry_after = limiter.check("127.0.0.1", now=1002.0)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)

    def test_rate_limiter_resets_after_window(self) -> None:
        limiter = RateLimiter(max_requests=1, window_sec=5)
        self.assertEqual(limiter.check("127.0.0.1", now=1000.0), (True, -1))
        allowed, _ = limiter.check("127.0.0.1", now=1001.0)
        self.assertFalse(allowed)
        self.assertEqual(limiter.check("127.0.0.1", now=1006.0), (True, -1))

    def test_rate_limiter_can_be_disabled(self) -> None:
        limiter = RateLimiter(max_requests=0, window_sec=60)
        for _ in range(5):
            self.assertEqual(limiter.check("127.0.0.1", now=1000.0), (True, -1))

    @patch("app.main.lookup_asn")
    def test_lookup_success(self, mock_lookup) -> None:
        mock_lookup.return_value = ASNResult(
            ip="8.8.8.8",
            asn=15169,
            bgp_prefix="8.8.8.0/24",
            country_code="US",
            registry="arin",
            allocated_date="1992-12-01",
            as_name="GOOGLE, US",
        )
        status, payload = _single_lookup("8.8.8.8")
        self.assertEqual(status, 200)
        self.assertEqual(payload["asn"], 15169)

    @patch("app.main.lookup_asn")
    def test_lookup_invalid_ip(self, mock_lookup) -> None:
        from app.asn_lookup import InvalidIPError

        mock_lookup.side_effect = InvalidIPError("Invalid IP: bad")
        status, payload = _single_lookup("bad")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "Invalid IP: bad")

    @patch("app.main.lookup_asn")
    def test_lookup_upstream_error(self, mock_lookup) -> None:
        from app.asn_lookup import UpstreamLookupError

        mock_lookup.side_effect = UpstreamLookupError("Unable to reach upstream ASN service")
        status, payload = _single_lookup("1.1.1.1")
        self.assertEqual(status, 502)
        self.assertIn("Unable to reach upstream ASN service", payload["error"])

    @patch("app.main.lookup_asn")
    def test_batch_partial_success(self, mock_lookup) -> None:
        from app.asn_lookup import InvalidIPError

        def side_effect(ip: str, timeout_sec: float = 4.0):
            if ip == "bad":
                raise InvalidIPError("Invalid IP: bad")
            return ASNResult(
                ip=ip,
                asn=13335,
                bgp_prefix="1.1.1.0/24",
                country_code="US",
                registry="apnic",
                allocated_date="2011-08-11",
                as_name="CLOUDFLARENET, US",
            )

        mock_lookup.side_effect = side_effect
        status, payload = _batch_lookup(["1.1.1.1", "bad"])
        self.assertEqual(status, 200)
        self.assertEqual(payload["items"][0]["result"]["asn"], 13335)
        self.assertEqual(payload["items"][1]["error"], "Invalid IP: bad")

    def test_batch_size_validation(self) -> None:
        status, payload = _batch_lookup([])
        self.assertEqual(status, 400)
        self.assertIn("between 1 and 100", payload["error"])


if __name__ == "__main__":
    unittest.main()
