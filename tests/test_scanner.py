"""Scanner validation and simulated inventory, with one owned loopback socket."""

from __future__ import annotations

import socket
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from rede_audit.scanner import scan_network


class ScannerTests(unittest.TestCase):
    def test_only_owned_loopback_listener_is_scanned_live(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            result = scan_network("127.0.0.1/32", [port], timeout=0.3, workers=1)

        self.assertIs(type(result["schema_version"]), int)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["network"], "127.0.0.1/32")
        self.assertEqual(result["ports_scanned"], [port])
        self.assertEqual(
            result["hosts"],
            [{"ip": "127.0.0.1", "responsive": True, "open_tcp_ports": [port]}],
        )
        self.assertEqual(
            result["stats"],
            {"hosts_scanned": 1, "hosts_responsive": 1, "open_ports": 1},
        )
        generated_at = datetime.fromisoformat(result["generated_at"].replace("Z", "+00:00"))
        self.assertEqual(generated_at.utcoffset(), timedelta(0))

    def test_mocked_scan_sorts_results_and_counts_tcp_responses(self) -> None:
        def probe(ip: str, port: int, timeout: float) -> str:
            if ip == "192.168.56.1" and port == 443:
                return "open"
            if ip == "192.168.56.1" and port == 22:
                return "refused"
            return "unresponsive"

        with patch("rede_audit.scanner._probe", side_effect=probe) as mocked:
            result = scan_network("192.168.56.0/30", [443, 80, 22], timeout=0.2, workers=2)

        self.assertEqual(len(mocked.call_args_list), 6)
        self.assertEqual(result["ports_scanned"], [22, 80, 443])
        self.assertEqual(
            result["hosts"],
            [
                {"ip": "192.168.56.1", "responsive": True, "open_tcp_ports": [443]},
                {"ip": "192.168.56.2", "responsive": False, "open_tcp_ports": []},
            ],
        )
        self.assertEqual(
            result["stats"],
            {"hosts_scanned": 2, "hosts_responsive": 1, "open_ports": 1},
        )

    def test_connection_refused_counts_as_responsive_without_open_port(self) -> None:
        with patch("rede_audit.scanner._probe", return_value="refused"):
            result = scan_network("127.0.0.1/32", [443], workers=1)
        self.assertEqual(result["hosts"][0]["responsive"], True)
        self.assertEqual(result["hosts"][0]["open_tcp_ports"], [])
        self.assertEqual(result["stats"]["hosts_responsive"], 1)
        self.assertEqual(result["stats"]["open_ports"], 0)

    def test_each_explicit_private_range_is_accepted_without_network_io(self) -> None:
        for network in (
            "10.1.2.3/32",
            "172.16.5.6/32",
            "172.31.5.6/32",
            "192.168.1.2/32",
            "127.0.0.2/32",
        ):
            with self.subTest(network=network):
                with patch("rede_audit.scanner._probe", return_value="unresponsive") as mocked:
                    result = scan_network(network, [80], workers=1)
                self.assertEqual(result["network"], network)
                self.assertEqual(result["stats"]["hosts_scanned"], 1)
                mocked.assert_called_once()

    def test_public_special_ipv6_hostname_and_oversized_networks_are_rejected(self) -> None:
        for network in (
            "8.8.8.8/32",
            "169.254.0.1/32",
            "100.64.0.1/32",
            "0.0.0.0/32",
            "192.0.0.1/32",
            "172.15.0.1/32",
            "172.32.0.1/32",
            "localhost",
            "example.com/32",
            "::1/128",
            "fd00::/120",
            "::ffff:127.0.0.1/128",
            "192.168.56.1/24",
            "192.168.56.0/23",
            "10.0.0.0/8",
        ):
            with self.subTest(network=network):
                with patch("rede_audit.scanner._probe") as mocked:
                    with self.assertRaises(ValueError):
                        scan_network(network, [80])
                    mocked.assert_not_called()

    def test_invalid_duplicate_or_excessive_ports_are_rejected_before_probing(self) -> None:
        for ports in ([], [0], [-1], [65536], [True], [80.5], ["80"], [80, 80], list(range(1, 66))):
            with self.subTest(ports=ports):
                with patch("rede_audit.scanner._probe") as mocked:
                    with self.assertRaises(ValueError):
                        scan_network("127.0.0.1/32", ports)
                    mocked.assert_not_called()

    def test_invalid_timeouts_are_rejected_before_probing(self) -> None:
        for timeout in (0, 0.049, 3.01, float("nan"), float("inf"), True, "0.3"):
            with self.subTest(timeout=timeout):
                with patch("rede_audit.scanner._probe") as mocked:
                    with self.assertRaises(ValueError):
                        scan_network("127.0.0.1/32", [80], timeout=timeout)
                    mocked.assert_not_called()

    def test_invalid_worker_counts_are_rejected_before_probing(self) -> None:
        for workers in (0, 33, True, 1.5, "2"):
            with self.subTest(workers=workers):
                with patch("rede_audit.scanner._probe") as mocked:
                    with self.assertRaises(ValueError):
                        scan_network("127.0.0.1/32", [80], workers=workers)
                    mocked.assert_not_called()

    def test_boundary_limits_are_accepted_with_only_mocked_probes(self) -> None:
        with patch("rede_audit.scanner._probe", return_value="unresponsive") as mocked:
            result = scan_network(
                "192.168.56.0/24", list(range(1, 65)), timeout=0.05, workers=32
            )
        self.assertEqual(result["stats"]["hosts_scanned"], 254)
        # Mock.call_count uses a read/modify/write increment across threads;
        # the appended call history verifies every submitted probe instead.
        self.assertEqual(len(mocked.call_args_list), 254 * 64)
        self.assertEqual(result["stats"]["hosts_responsive"], 0)
        with patch("rede_audit.scanner._probe", return_value="unresponsive"):
            result = scan_network("127.0.0.1/32", [80], timeout=3, workers=1)
        self.assertEqual(result["stats"]["hosts_scanned"], 1)


if __name__ == "__main__":
    unittest.main()
