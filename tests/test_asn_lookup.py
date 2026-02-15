import json
import unittest
from unittest.mock import MagicMock, patch

from app.asn_lookup import ASNResult, lookup_asn


class TestASNLookupFallback(unittest.TestCase):
    @patch("app.asn_lookup.request.urlopen")
    @patch("app.asn_lookup.socket.create_connection")
    def test_fallback_to_bgpview_when_team_cymru_fails(self, mock_conn, mock_urlopen) -> None:
        mock_conn.side_effect = OSError("blocked")
        body = {
            "status": "ok",
            "data": {
                "rir_allocation": {"rir_name": "APNIC", "date_allocated": "2006-04-20"},
                "prefixes": [
                    {
                        "prefix": "118.163.128.0/17",
                        "asn": {
                            "asn": 3462,
                            "description_short": "HINET Data Communication Business Group",
                            "country_code": "TW",
                        },
                    }
                ],
            },
        }

        response = MagicMock()
        response.read.return_value = json.dumps(body).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = response

        result = lookup_asn("118.163.137.149")

        self.assertIsInstance(result, ASNResult)
        self.assertEqual(result.asn, 3462)
        self.assertEqual(result.bgp_prefix, "118.163.128.0/17")
        self.assertEqual(result.country_code, "TW")
        self.assertEqual(result.registry, "apnic")
        self.assertEqual(result.source, "bgpview.io")

    @patch("app.asn_lookup.request.urlopen")
    @patch("app.asn_lookup.socket.create_connection")
    def test_prefers_team_cymru_when_available(self, mock_conn, mock_urlopen) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [
            b"AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n",
            b"3462    | 118.163.137.149  | 118.163.128.0/17    | TW | apnic    | 2006-04-20 | HINET Data Communication Business Group\n",
            b"",
        ]
        mock_conn.return_value.__enter__.return_value = sock

        result = lookup_asn("118.163.137.149")

        self.assertEqual(result.asn, 3462)
        self.assertEqual(result.source, "team-cymru-whois")
        mock_urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
