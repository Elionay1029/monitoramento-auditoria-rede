"""Análise defensiva e offline de arquivos PCAP clássicos.

O módulo não captura nem transmite pacotes. A estrutura do arquivo é validada
antes da dissecação em streaming, pois um leitor PCAP pode interpretar um fim
de registro truncado como fim normal do arquivo.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import ipaddress
import math
from numbers import Real
from pathlib import Path
import re
import struct
from typing import BinaryIO

from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.utils import PcapReader


_MAX_PACKETS = 1_000_000
_MAX_PACKET_BYTES = 1_048_576
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


@dataclass
class _SynWindow:
    events: deque = field(default_factory=deque)
    ports: Counter = field(default_factory=Counter)


@dataclass
class _ScanEvidence:
    first: Decimal
    last: Decimal
    ports: set[int]


def _validate_arguments(window_seconds: float, unique_port_threshold: int, max_packets: int) -> Decimal:
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, Real):
        raise ValueError("window_seconds deve ser um número positivo e finito.")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds deve ser um número positivo e finito.")
    if isinstance(unique_port_threshold, bool) or not isinstance(unique_port_threshold, int):
        raise ValueError("unique_port_threshold deve ser um inteiro entre 1 e 65535.")
    if not 1 <= unique_port_threshold <= 65535:
        raise ValueError("unique_port_threshold deve ser um inteiro entre 1 e 65535.")
    if isinstance(max_packets, bool) or not isinstance(max_packets, int) or not 1 <= max_packets <= _MAX_PACKETS:
        raise ValueError(f"max_packets deve ser um inteiro entre 1 e {_MAX_PACKETS}.")
    return Decimal(str(window_seconds))


def _validate_capture(stream: BinaryIO, max_packets: int) -> tuple[int, int]:
    """Valide os registros sem carregar seus conteúdos na memória."""
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    if not size:
        raise ValueError("O arquivo PCAP está vazio.")
    header = stream.read(24)
    if len(header) < 24:
        raise ValueError("Cabeçalho PCAP truncado ou inválido.")
    if header[:4] not in _MAGICS:
        raise ValueError("Formato não suportado: informe PCAP clássico, sem compressão; PCAPNG não é aceito.")
    endian, resolution = _MAGICS[header[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4):
        raise ValueError("Versão PCAP não suportada; é esperado o formato clássico 2.4.")
    if not 1 <= snaplen <= _MAX_PACKET_BYTES:
        raise ValueError(f"snaplen inválido: o limite por pacote é de {_MAX_PACKET_BYTES} bytes.")

    count = 0
    previous = None
    while stream.tell() < size:
        record = stream.read(16)
        if len(record) != 16:
            raise ValueError("Cabeçalho de registro PCAP truncado.")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
        count += 1
        if count > max_packets:
            raise ValueError(f"O PCAP excede o limite configurado de {max_packets} pacotes.")
        if fraction >= resolution:
            raise ValueError(f"Timestamp inválido no pacote {count}.")
        instant = seconds * 1_000_000_000 + fraction * (1_000_000_000 // resolution)
        if previous is not None and instant < previous:
            raise ValueError(f"Timestamps fora de ordem no pacote {count}; ordene a captura antes da análise.")
        previous = instant
        if not 1 <= captured <= min(snaplen, _MAX_PACKET_BYTES):
            raise ValueError(f"Tamanho capturado inválido no pacote {count}.")
        if captured != original:
            raise ValueError(f"Pacote {count} truncado ou inconsistente: caplen difere do tamanho original.")
        if captured > size - stream.tell():
            raise ValueError(f"Conteúdo do pacote {count} truncado no arquivo PCAP.")
        stream.seek(captured, 1)

    if not count:
        raise ValueError("O PCAP não contém pacotes.")
    stream.seek(0)
    return count, linktype


def _validate_packet(packet, position: int, linktype: int) -> None:
    """Rejeite cabeçalhos incompletos em vez de classificá-los como OTHER."""
    def invalid(reason: str) -> None:
        raise ValueError(f"Pacote {position} malformado: {reason}.")

    if linktype == 1:
        if Ether not in packet or len(bytes(packet)) < 14:
            invalid("cabeçalho Ethernet incompleto")
        ethernet_type = int(packet[Ether].type)
        if Dot1Q in packet:
            ethernet_type = int(packet[Dot1Q].type)
        expected = {0x0800: IP, 0x86DD: IPv6, 0x0806: ARP}.get(ethernet_type)
        if expected is not None and expected not in packet:
            invalid("cabeçalho de rede incompleto ou inválido")
    if IP in packet:
        network = packet[IP]
        if int(network.version) != 4 or int(network.ihl) < 5:
            invalid("cabeçalho IPv4 inválido")
        if int(network.len) < int(network.ihl) * 4 or int(network.len) > len(bytes(network)):
            invalid("comprimento IPv4 inconsistente")
        fragmented = bool(int(network.frag) or int(network.flags) & 1)
        if not fragmented and int(network.proto) == 6 and TCP not in packet:
            invalid("cabeçalho TCP incompleto")
        if not fragmented and int(network.proto) == 17 and UDP not in packet:
            invalid("cabeçalho UDP incompleto")
    elif IPv6 in packet:
        network = packet[IPv6]
        if int(network.version) != 6 or 40 + int(network.plen) > len(bytes(network)):
            invalid("comprimento IPv6 inconsistente")
        fragmented = True  # Não confundir fragmentação/extensões IPv6 com truncamento UDP.
    else:
        fragmented = False
    if TCP in packet:
        tcp = packet[TCP]
        if int(tcp.dataofs) < 5 or int(tcp.dataofs) * 4 > len(bytes(tcp)):
            invalid("comprimento do cabeçalho TCP inconsistente")
    if UDP in packet:
        udp = packet[UDP]
        if int(udp.len) < 8 or (not fragmented and int(udp.len) > len(bytes(udp))):
            invalid("comprimento UDP inconsistente")


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _iso_utc(value: Decimal) -> str:
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def analyze_pcap(
    path: str | Path,
    window_seconds: float = 60,
    unique_port_threshold: int = 8,
    max_packets: int = 100000,
) -> dict:
    """Analise um PCAP offline, com janela SYN deslizante e evidências limitadas.

    Para cada par origem/destino é reportada a primeira janela que alcança o
    limiar. Portas adicionais são agregadas até o término dessa mesma janela;
    não é feita uma contagem cumulativa de toda a captura. Cada registro é
    lido em streaming e a quantidade total é limitada por ``max_packets``.
    """
    window = _validate_arguments(window_seconds, unique_port_threshold, max_packets)
    capture = Path(path)
    if not capture.is_file():
        raise ValueError(f"Arquivo PCAP não encontrado ou não é um arquivo: {capture}")
    protocol_counts = {"TCP": 0, "UDP": 0, "ARP": 0, "OTHER": 0}
    ips: set[str] = set()
    active: dict[tuple[str, str], _SynWindow] = {}
    expiry: deque = deque()
    scans: dict[tuple[str, str], _ScanEvidence] = {}
    arp_macs: dict[str, set[str]] = {}
    arp_times: dict[str, tuple[Decimal, Decimal]] = {}
    count = 0

    try:
        with capture.open("rb") as stream:
            expected_count, linktype = _validate_capture(stream, max_packets)
            with PcapReader(stream) as reader:
                for count, packet in enumerate(reader, start=1):
                    if count > max_packets:
                        raise ValueError("O PCAP mudou durante a leitura ou excedeu o limite de pacotes.")
                    _validate_packet(packet, count, linktype)
                    timestamp = Decimal(str(packet.time))
                    cutoff = timestamp - window
                    while expiry and expiry[0][0] < cutoff:
                        _, pair, port = expiry.popleft()
                        state = active.get(pair)
                        if state is None:
                            continue
                        state.events.popleft()
                        state.ports[port] -= 1
                        if not state.ports[port]:
                            del state.ports[port]
                        if not state.events:
                            del active[pair]

                    network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
                    endpoints = None
                    if network is not None:
                        source, destination = _ip(network.src), _ip(network.dst)
                        ips.update(value for value in (source, destination) if value is not None)
                        if source is not None and destination is not None:
                            endpoints = (source, destination)

                    if ARP in packet:
                        protocol_counts["ARP"] += 1
                        arp = packet[ARP]
                        claimed, target = _ip(arp.psrc), _ip(arp.pdst)
                        ips.update(value for value in (claimed, target) if value is not None)
                        mac = str(arp.hwsrc).lower()
                        # Anúncios 0.0.0.0 de sondas DHCP não representam posse de IP.
                        if claimed and not ipaddress.ip_address(claimed).is_unspecified and _MAC.fullmatch(mac):
                            if mac not in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
                                arp_macs.setdefault(claimed, set()).add(mac)
                                first, _ = arp_times.get(claimed, (timestamp, timestamp))
                                arp_times[claimed] = (first, timestamp)
                    elif TCP in packet:
                        protocol_counts["TCP"] += 1
                        tcp = packet[TCP]
                        flags = int(tcp.flags)
                        if endpoints is not None and flags & 0x02 and not flags & 0x10:
                            port = int(tcp.dport)
                            prior = scans.get(endpoints)
                            if prior is not None:
                                if timestamp - prior.first <= window:
                                    prior.ports.add(port)
                                    prior.last = timestamp
                                continue
                            state = active.setdefault(endpoints, _SynWindow())
                            state.events.append((timestamp, port))
                            state.ports[port] += 1
                            expiry.append((timestamp, endpoints, port))
                            if len(state.ports) >= unique_port_threshold:
                                scans[endpoints] = _ScanEvidence(state.events[0][0], timestamp, set(state.ports))
                                # O par já tem achado; suas filas serão descartadas na expiração global.
                                del active[endpoints]
                    elif UDP in packet:
                        protocol_counts["UDP"] += 1
                    else:
                        protocol_counts["OTHER"] += 1
            if count != expected_count:
                raise ValueError("Leitura PCAP incompleta: o arquivo foi alterado ou contém registro inválido.")
    except (Scapy_Exception, EOFError, struct.error, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError("PCAP inválido ou pacote malformado; confira o formato e a integridade da captura.") from exc
    except OSError as exc:
        raise ValueError(f"Não foi possível ler o arquivo PCAP: {exc.strerror or 'erro de leitura'}") from exc

    findings = []
    for (source, destination), evidence in sorted(scans.items()):
        ports = ", ".join(str(port) for port in sorted(evidence.ports))
        findings.append({
            "id": "PORT_SCAN_PATTERN",
            "severity": "high",
            "title": "Indício de varredura TCP SYN",
            "evidence": (
                f"Origem {source} para destino {destination}: {len(evidence.ports)} portas de destino únicas "
                f"em pacotes SYN sem ACK ({ports}), entre {_iso_utc(evidence.first)} e "
                f"{_iso_utc(evidence.last)}, dentro de uma janela de {window_seconds:g} segundos."
            ),
            "recommendation": (
                "Verificar se a origem pertence a uma ferramenta de monitoramento ou teste autorizada; "
                "correlacionar os horários com os registros de firewall antes de concluir que há atividade indevida."
            ),
            "source": "pcap",
            "host": source,
        })
    for claimed, macs in sorted(arp_macs.items()):
        if len(macs) < 2:
            continue
        first, last = arp_times[claimed]
        findings.append({
            "id": "ARP_IP_CONFLICT",
            "severity": "medium",
            "title": "IP anunciado por múltiplos endereços MAC",
            "evidence": (
                f"O IP {claimed} foi anunciado por {len(macs)} MACs distintos: {', '.join(sorted(macs))}, "
                f"entre {_iso_utc(first)} e {_iso_utc(last)}. Pode haver IP duplicado, mudança legítima de "
                "equipamento ou outra inconsistência; o achado não confirma ataque."
            ),
            "recommendation": (
                "Conferir o inventário, as concessões DHCP e os equipamentos envolvidos; investigar "
                "duplicidade de IP e mudanças de interface antes de aplicar medidas de contenção."
            ),
            "source": "pcap",
            "host": claimed,
        })

    return {
        "schema_version": 1,
        "packets_total": count,
        "protocol_counts": protocol_counts,
        "ips_observed": sorted(ips),
        "findings": sorted(findings, key=lambda item: (item["id"], item["host"])),
    }
