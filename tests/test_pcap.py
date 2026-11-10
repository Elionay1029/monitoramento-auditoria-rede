"""Testes offline com capturas temporárias sintéticas; nenhuma operação de rede."""

from __future__ import annotations

from pathlib import Path
import runpy
import struct
import tempfile
import unittest

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from rede_audit.pcap import analyze_pcap


BASE = 1767225600


def syn(port=80, *, source="192.168.56.99", destination="192.168.56.1", flags="S"):
    return (Ether(src="02:00:00:00:00:99", dst="02:00:00:00:00:01")
            / IP(src=source, dst=destination) / TCP(sport=40000, dport=port, flags=flags))


def write_capture(path, packets, *, nano=False, endian="<"):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    resolution = 1_000_000_000 if nano else 1_000_000
    with Path(path).open("wb") as stream:
        stream.write(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1))
        for instant, packet in packets:
            content = bytes(packet)
            seconds = int(instant)
            fraction = round((instant - seconds) * resolution)
            stream.write(struct.pack(endian + "IIII", seconds, fraction, len(content), len(content)))
            stream.write(content)


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "capture.pcap"

    def analyze(self, packets, **kwargs):
        write_capture(self.path, packets)
        return analyze_pcap(self.path, **kwargs)

    def test_scan_threshold_includes_all_ports_in_first_alert_window(self):
        report = self.analyze([(BASE + index, syn(20 + index)) for index in range(12)])
        self.assertEqual(report["packets_total"], 12)
        self.assertEqual(report["protocol_counts"], {"TCP": 12, "UDP": 0, "ARP": 0, "OTHER": 0})
        self.assertEqual(report["ips_observed"], ["192.168.56.1", "192.168.56.99"])
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["id"], "PORT_SCAN_PATTERN")
        self.assertEqual(finding["host"], "192.168.56.99")
        self.assertIn("12 portas", finding["evidence"])
        self.assertIn("20, 21", finding["evidence"])
        self.assertIn("30, 31", finding["evidence"])
        self.assertIn("2026-01-01T00:00:00", finding["evidence"])

    def test_syn_retransmissions_do_not_count_as_new_ports(self):
        report = self.analyze([(BASE + index, syn(443)) for index in range(30)], unique_port_threshold=2)
        self.assertEqual(report["findings"], [])

    def test_syn_ack_and_regular_ack_do_not_trigger(self):
        report = self.analyze([(BASE + i, syn(20 + i, flags="SA" if i % 2 else "A")) for i in range(12)])
        self.assertEqual(report["findings"], [])

    def test_below_threshold_does_not_trigger(self):
        report = self.analyze([(BASE + i, syn(20 + i)) for i in range(7)])
        self.assertEqual(report["findings"], [])

    def test_windows_expire_and_do_not_accumulate_whole_capture(self):
        report = self.analyze([(BASE, syn(20)), (BASE + 61, syn(21))], unique_port_threshold=2)
        self.assertEqual(report["findings"], [])

    def test_exact_window_boundary_is_included(self):
        report = self.analyze([(BASE, syn(20)), (BASE + 60, syn(21))], unique_port_threshold=2)
        self.assertEqual(len(report["findings"]), 1)

    def test_sliding_window_can_find_later_burst(self):
        packets = [(BASE, syn(1))] + [(BASE + 100 + i, syn(20 + i)) for i in range(8)]
        report = self.analyze(packets)
        self.assertEqual(len(report["findings"]), 1)
        self.assertIn("8 portas", report["findings"][0]["evidence"])

    def test_one_finding_per_pair_across_multiple_bursts(self):
        packets = [(BASE + i, syn(20 + i)) for i in range(8)]
        packets += [(BASE + 200 + i, syn(100 + i)) for i in range(8)]
        report = self.analyze(packets)
        self.assertEqual(len(report["findings"]), 1)
        self.assertNotIn("100, 101", report["findings"][0]["evidence"])

    def test_pairs_are_kept_separate(self):
        packets = [(BASE + i, syn(20 + i, destination="192.168.56.1" if i % 2 else "192.168.56.2"))
                   for i in range(8)]
        report = self.analyze(packets)
        self.assertEqual(report["findings"], [])

    def test_arp_conflict_is_an_indication_not_confirmed_attack(self):
        packets = []
        for i, mac in enumerate(["02:00:00:00:00:20", "02:00:00:00:00:21"]):
            packet = Ether(src=mac, dst="02:00:00:00:00:01") / ARP(
                op=2, hwsrc=mac, psrc="192.168.56.2", pdst="192.168.56.1", hwdst="02:00:00:00:00:01")
            packets.append((BASE + i, packet))
        report = self.analyze(packets)
        self.assertEqual(report["protocol_counts"]["ARP"], 2)
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["id"], "ARP_IP_CONFLICT")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["host"], "192.168.56.2")
        self.assertIn("não confirma ataque", finding["evidence"])

    def test_same_arp_mac_and_unspecified_probe_do_not_trigger(self):
        packets = []
        for i, mac in enumerate(["02:00:00:00:00:20", "02:00:00:00:00:21"]):
            packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, hwsrc=mac, psrc="0.0.0.0", pdst="192.168.56.2")
            packets.append((BASE + i, packet))
        report = self.analyze(packets)
        self.assertEqual(report["findings"], [])

    def test_udp_and_other_protocol_counts(self):
        udp = Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01") / IP(
            src="192.168.56.3", dst="192.168.56.1") / UDP(sport=53000, dport=53)
        other = Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01", type=0x9000) / b"demo"
        report = self.analyze([(BASE, udp), (BASE + 1, other)])
        self.assertEqual(report["protocol_counts"], {"TCP": 0, "UDP": 1, "ARP": 0, "OTHER": 1})

    def test_timestamps_out_of_order_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "fora de ordem"):
            self.analyze([(BASE + 1, syn(80)), (BASE, syn(81))])

    def test_packet_limit_is_enforced_before_analysis(self):
        with self.assertRaisesRegex(ValueError, "limite configurado de 1"):
            self.analyze([(BASE, syn(80)), (BASE + 1, syn(81))], max_packets=1)

    def test_invalid_argument_values(self):
        write_capture(self.path, [(BASE, syn())])
        for value in [0, -1, float("nan"), float("inf"), True, "60"]:
            with self.subTest(window_seconds=value), self.assertRaisesRegex(ValueError, "window_seconds"):
                analyze_pcap(self.path, window_seconds=value)
        for value in [0, 65536, 1.5, True, "8"]:
            with self.subTest(threshold=value), self.assertRaisesRegex(ValueError, "unique_port_threshold"):
                analyze_pcap(self.path, unique_port_threshold=value)
        for value in [0, -1, 1_000_001, True, 1.5]:
            with self.subTest(max_packets=value), self.assertRaisesRegex(ValueError, "max_packets"):
                analyze_pcap(self.path, max_packets=value)

    def test_empty_and_header_only_captures_are_rejected(self):
        self.path.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "vazio"):
            analyze_pcap(self.path)
        write_capture(self.path, [])
        with self.assertRaisesRegex(ValueError, "não contém pacotes"):
            analyze_pcap(self.path)

    def test_truncated_global_and_record_headers_are_rejected(self):
        self.path.write_bytes(b"\xd4\xc3\xb2\xa1")
        with self.assertRaisesRegex(ValueError, "truncado"):
            analyze_pcap(self.path)
        write_capture(self.path, [])
        with self.path.open("ab") as stream:
            stream.write(b"\x00" * 8)
        with self.assertRaisesRegex(ValueError, "registro PCAP truncado"):
            analyze_pcap(self.path)

    def test_truncated_packet_body_is_rejected(self):
        write_capture(self.path, [(BASE, syn())])
        data = self.path.read_bytes()
        self.path.write_bytes(data[:-1])
        with self.assertRaisesRegex(ValueError, "truncado"):
            analyze_pcap(self.path)

    def test_partial_snaplen_capture_is_rejected_explicitly(self):
        write_capture(self.path, [(BASE, syn())])
        data = bytearray(self.path.read_bytes())
        captured = struct.unpack_from("<I", data, 32)[0]
        struct.pack_into("<I", data, 36, captured + 20)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "caplen"):
            analyze_pcap(self.path)

    def test_malformed_ethernet_or_ip_packet_is_rejected(self):
        for packet in [b"\x00" * 10,
                       bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x0800)) + b"short"]:
            with self.subTest(packet=packet):
                write_capture(self.path, [(BASE, packet)])
                with self.assertRaisesRegex(ValueError, "malformado"):
                    analyze_pcap(self.path)

    def test_big_endian_and_nanosecond_captures(self):
        for endian, nano in [("<", True), (">", False), (">", True)]:
            with self.subTest(endian=endian, nano=nano):
                write_capture(self.path, [(BASE, syn())], endian=endian, nano=nano)
                self.assertEqual(analyze_pcap(self.path)["packets_total"], 1)

    def test_invalid_magic_and_missing_path(self):
        self.path.write_bytes(b"not-pcap" * 4)
        with self.assertRaisesRegex(ValueError, "Formato não suportado"):
            analyze_pcap(self.path)
        with self.assertRaisesRegex(ValueError, "não encontrado"):
            analyze_pcap(Path(self.temp.name) / "missing.pcap")

    def test_demo_generation_is_deterministic_and_has_two_findings(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "generate_demo_pcap.py"
        generate = runpy.run_path(str(script))["generate_demo_pcap"]
        second = Path(self.temp.name) / "second.pcap"
        generate(self.path)
        generate(second)
        self.assertEqual(self.path.read_bytes(), second.read_bytes())
        report = analyze_pcap(self.path)
        self.assertEqual(report["packets_total"], 16)
        self.assertEqual(report["protocol_counts"], {"TCP": 13, "UDP": 1, "ARP": 2, "OTHER": 0})
        self.assertEqual([item["id"] for item in report["findings"]], ["ARP_IP_CONFLICT", "PORT_SCAN_PATTERN"])
        self.assertEqual(report["ips_observed"], ["192.168.56.1", "192.168.56.2", "192.168.56.3", "192.168.56.99"])


if __name__ == "__main__":
    unittest.main()
