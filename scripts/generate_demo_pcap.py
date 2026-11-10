"""Gere tráfego inteiramente fictício em arquivo, sem capturar ou enviar pacotes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter


def generate_demo_pcap(output: str | Path) -> Path:
    """Grave exatamente 16 pacotes determinísticos, com dois indícios esperados."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    base_time = int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())
    packets = []
    for offset, port in enumerate(range(20, 32)):
        packet = (
            Ether(src="02:00:00:00:00:99", dst="02:00:00:00:00:01")
            / IP(src="192.168.56.99", dst="192.168.56.1", id=offset + 1)
            / TCP(sport=41000, dport=port, flags="S", seq=1000 + offset, window=8192)
        )
        packet.time = base_time + offset
        packets.append(packet)
    for offset, mac in [(20, "02:00:00:00:00:20"), (21, "02:00:00:00:00:21")]:
        packet = Ether(src=mac, dst="02:00:00:00:00:01") / ARP(
            op=2, hwsrc=mac, psrc="192.168.56.2", hwdst="02:00:00:00:00:01", pdst="192.168.56.1"
        )
        packet.time = base_time + offset
        packets.append(packet)
    dns = (
        Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")
        / IP(src="192.168.56.3", dst="192.168.56.1", id=30)
        / UDP(sport=53000, dport=53)
        / DNS(id=42, rd=1, qd=DNSQR(qname="example.demo.invalid"))
    )
    dns.time = base_time + 22
    packets.append(dns)
    normal = (
        Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")
        / IP(src="192.168.56.3", dst="192.168.56.1", id=31)
        / TCP(sport=42000, dport=443, flags="A", seq=2000, ack=3000, window=8192)
    )
    normal.time = base_time + 23
    packets.append(normal)
    with PcapWriter(str(output), linktype=1, endianness="<", sync=True) as writer:
        for packet in packets:
            writer.write(packet)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera 16 pacotes fictícios em PCAP; não utiliza a rede.")
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "demo" / "traffic_demo.pcap",
    )
    args = parser.parse_args()
    destination = generate_demo_pcap(args.output)
    print(f"PCAP fictício gerado: {destination} (16 pacotes, 2 indícios esperados).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
