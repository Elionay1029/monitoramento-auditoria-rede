"""Inventory rules against synthetic snapshots; no network access."""

from __future__ import annotations

import copy
import json
import unittest

from rede_audit.audit import audit_snapshot, validate_baseline, validate_snapshot


def snapshot() -> dict:
    return {
        "schema_version": 1,
        "network": "192.168.56.0/24",
        "generated_at": "2026-11-10T12:00:00+00:00",
        "ports_scanned": [21, 22, 23, 80, 110, 143, 443, 8080],
        "hosts": [
            {"ip": "192.168.56.1", "responsive": True, "open_tcp_ports": [22, 443]},
        ],
        "stats": {"hosts_scanned": 1, "hosts_responsive": 1, "open_ports": 2},
    }


def baseline() -> dict:
    return {
        "schema_version": 1,
        "network": "192.168.56.0/24",
        "hosts": {"192.168.56.1": {"allowed_tcp_ports": [22, 443]}},
    }


class InventoryAuditTests(unittest.TestCase):
    def test_matching_inventory_has_no_findings(self) -> None:
        self.assertEqual(audit_snapshot(snapshot(), baseline()), [])

    def test_responsive_unknown_host_is_reported_once(self) -> None:
        observed = snapshot()
        observed["hosts"] = [
            {"ip": "192.168.56.2", "responsive": True, "open_tcp_ports": []}
        ]

        findings = audit_snapshot(observed, baseline())

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["id"], "HOST_NOT_IN_BASELINE")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["host"], "192.168.56.2")
        self.assertEqual(finding["source"], "inventory")
        for key in ("title", "evidence", "recommendation"):
            self.assertTrue(finding[key], key)

    def test_no_tcp_response_does_not_imply_device_absence(self) -> None:
        observed = snapshot()
        observed["hosts"] = [
            {"ip": "192.168.56.1", "responsive": False, "open_tcp_ports": []},
            {"ip": "192.168.56.2", "responsive": False, "open_tcp_ports": []},
        ]
        expected = baseline()
        expected["hosts"]["192.168.56.10"] = {"allowed_tcp_ports": [443]}

        self.assertEqual(audit_snapshot(observed, expected), [])

    def test_unexpected_ports_are_combined_into_one_finding_per_host(self) -> None:
        observed = snapshot()
        observed["hosts"][0]["open_tcp_ports"] = [22, 80, 443, 8080]

        findings = audit_snapshot(observed, baseline())

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["id"], "UNEXPECTED_OPEN_PORT")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["host"], "192.168.56.1")
        self.assertEqual(finding["source"], "inventory")
        evidence = json.dumps(finding["evidence"], ensure_ascii=False)
        self.assertIn("80", evidence)
        self.assertIn("8080", evidence)

    def test_legacy_ports_are_low_severity_even_if_allowed(self) -> None:
        observed = snapshot()
        observed["hosts"][0]["open_tcp_ports"] = [21, 23, 110, 143]
        expected = baseline()
        expected["hosts"]["192.168.56.1"]["allowed_tcp_ports"] = [21, 23, 110, 143]

        findings = audit_snapshot(observed, expected)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "LEGACY_SERVICE_PORT")
        self.assertEqual(findings[0]["severity"], "low")
        self.assertEqual(findings[0]["host"], "192.168.56.1")
        evidence = json.dumps(findings[0]["evidence"])
        for port in (21, 23, 110, 143):
            self.assertIn(str(port), evidence)

    def test_legacy_and_unexpected_port_rules_can_both_apply(self) -> None:
        observed = snapshot()
        observed["hosts"][0]["open_tcp_ports"] = [23, 8080]

        findings = audit_snapshot(observed, baseline())

        self.assertEqual(
            sorted(finding["id"] for finding in findings),
            ["LEGACY_SERVICE_PORT", "UNEXPECTED_OPEN_PORT"],
        )
        self.assertTrue(all(finding["source"] == "inventory" for finding in findings))

    def test_baseline_ports_outside_scan_are_not_assumed_missing(self) -> None:
        observed = snapshot()
        observed["ports_scanned"] = [443]
        observed["hosts"][0]["open_tcp_ports"] = [443]

        self.assertEqual(audit_snapshot(observed, baseline()), [])

    def test_different_networks_cannot_be_compared(self) -> None:
        expected = baseline()
        expected["network"] = "192.168.57.0/24"
        expected["hosts"] = {}
        with self.assertRaises(ValueError):
            audit_snapshot(snapshot(), expected)

    def test_metadata_is_optional_and_input_statistics_are_not_trusted(self) -> None:
        observed = snapshot()
        del observed["generated_at"]
        observed["stats"] = {"hosts_scanned": 9999, "open_ports": 0}
        self.assertEqual(audit_snapshot(observed, baseline()), [])

    def test_snapshot_rejects_invalid_versions_and_host_shapes(self) -> None:
        mutations = (
            ("schema_version", True),
            ("schema_version", 2),
            ("hosts", {}),
            ("hosts", ["192.168.56.1"]),
            ("network", "192.168.56.1/24"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                observed = snapshot()
                observed[field] = value
                with self.assertRaises(ValueError):
                    validate_snapshot(observed)

    def test_required_snapshot_and_baseline_fields_cannot_be_missing(self) -> None:
        for field in ("schema_version", "network", "ports_scanned", "hosts"):
            with self.subTest(document="snapshot", field=field):
                observed = snapshot()
                del observed[field]
                with self.assertRaises(ValueError):
                    validate_snapshot(observed)
        for field in ("schema_version", "network", "hosts"):
            with self.subTest(document="baseline", field=field):
                expected = baseline()
                del expected[field]
                with self.assertRaises(ValueError):
                    validate_baseline(expected)

    def test_snapshot_rejects_invalid_or_duplicate_ports(self) -> None:
        for ports in ([0], [65536], [-1], [True], [22.5], ["22"], [22, 22]):
            for location in ("ports_scanned", "open_tcp_ports"):
                with self.subTest(ports=ports, location=location):
                    observed = snapshot()
                    if location == "ports_scanned":
                        observed["ports_scanned"] = ports
                        observed["hosts"] = []
                    else:
                        observed["hosts"][0]["open_tcp_ports"] = ports
                    with self.assertRaises(ValueError):
                        validate_snapshot(observed)

    def test_snapshot_requires_open_ports_to_belong_to_the_scan(self) -> None:
        observed = snapshot()
        observed["hosts"][0]["open_tcp_ports"] = [8443]
        with self.assertRaises(ValueError):
            validate_snapshot(observed)

    def test_snapshot_rejects_inconsistent_responsiveness(self) -> None:
        for responsive in (False, 1, "true", None):
            with self.subTest(responsive=responsive):
                observed = snapshot()
                observed["hosts"][0]["responsive"] = responsive
                with self.assertRaises(ValueError):
                    validate_snapshot(observed)

    def test_snapshot_rejects_out_of_scope_or_duplicate_hosts(self) -> None:
        for address in ("192.168.57.1", "8.8.8.8", "::1", "localhost"):
            with self.subTest(address=address):
                observed = snapshot()
                observed["hosts"][0]["ip"] = address
                with self.assertRaises(ValueError):
                    validate_snapshot(observed)
        observed = snapshot()
        observed["hosts"].append(copy.deepcopy(observed["hosts"][0]))
        with self.assertRaises(ValueError):
            validate_snapshot(observed)

    def test_baseline_rejects_invalid_schema_hosts_and_ports(self) -> None:
        for field, value in (("schema_version", True), ("schema_version", 2), ("hosts", [])):
            with self.subTest(field=field, value=value):
                expected = baseline()
                expected[field] = value
                with self.assertRaises(ValueError):
                    validate_baseline(expected)
        for ports in ([0], [65536], [True], ["22"], [22, 22]):
            with self.subTest(ports=ports):
                expected = baseline()
                expected["hosts"]["192.168.56.1"]["allowed_tcp_ports"] = ports
                with self.assertRaises(ValueError):
                    validate_baseline(expected)
        for address in ("192.168.57.1", "8.8.8.8", "::1", "localhost"):
            with self.subTest(address=address):
                expected = baseline()
                expected["hosts"] = {address: {"allowed_tcp_ports": [443]}}
                with self.assertRaises(ValueError):
                    validate_baseline(expected)


if __name__ == "__main__":
    unittest.main()
