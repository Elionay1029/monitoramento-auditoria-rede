"""Comandos para demonstracao offline e auditoria com escopo explicito."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import audit_snapshot, validate_snapshot
from .pcap import analyze_pcap
from .report import build_report, write_json, write_report
from .scanner import scan_network


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Chave JSON duplicada: {key}')
        result[key] = value
    return result


def read_json(path):
    with Path(path).open(encoding='utf-8-sig') as stream:
        return json.load(stream, object_pairs_hook=_object)


def perform_audit(snapshot, baseline, output, pcap_path=None):
    normalized = validate_snapshot(snapshot)
    findings = audit_snapshot(normalized, baseline)
    packet_report = analyze_pcap(pcap_path) if pcap_path else None
    if packet_report:
        findings.extend(packet_report['findings'])
    report = build_report(normalized, findings, packet_report)
    files = write_report(report, output)
    return {'summary': report['summary'], 'files': files}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inventario TCP local e auditoria offline com Scapy.')
    commands = parser.add_subparsers(dest='command', required=True)
    demo = commands.add_parser('demo', help='Demonstracao com inventario e PCAP ficticios; sem conexoes de scan.')
    demo.add_argument('--output', default='reports/demo')
    scan = commands.add_parser('scan', help='Conexoes TCP em escopo local numerico explicito.')
    scan.add_argument('--network', required=True)
    scan.add_argument('--ports', default='22,80,443')
    scan.add_argument('--timeout', type=float, default=.3)
    scan.add_argument('--workers', type=int, default=16)
    scan.add_argument('--output', default='reports/scan.json')
    audit = commands.add_parser('audit', help='Comparar um snapshot com uma baseline do mesmo CIDR.')
    audit.add_argument('--snapshot', required=True)
    audit.add_argument('--baseline', required=True)
    audit.add_argument('--pcap')
    audit.add_argument('--output', default='reports/auditoria')
    pcap = commands.add_parser('analyze-pcap', help='Analisar um arquivo PCAP classico Ethernet, sem captura ao vivo.')
    pcap.add_argument('--pcap', required=True)
    pcap.add_argument('--output', default='reports/pcap.json')
    pcap.add_argument('--window-seconds', type=float, default=60)
    pcap.add_argument('--unique-port-threshold', type=int, default=8)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == 'demo':
            result = perform_audit(read_json('data/demo/snapshot_demo.json'),
                read_json('config/baseline.example.json'), arguments.output, 'data/demo/traffic_demo.pcap')
        elif arguments.command == 'scan':
            try:
                ports = [int(port.strip()) for port in arguments.ports.split(',')]
            except ValueError as error:
                raise ValueError('Informe portas inteiras separadas por virgulas.') from error
            result = scan_network(arguments.network, ports, arguments.timeout, arguments.workers)
            write_json(arguments.output, result)
        elif arguments.command == 'audit':
            result = perform_audit(read_json(arguments.snapshot), read_json(arguments.baseline), arguments.output, arguments.pcap)
        else:
            result = analyze_pcap(arguments.pcap, arguments.window_seconds, arguments.unique_port_threshold)
            write_json(arguments.output, result)
    except (ValueError, OSError) as error:
        print(f'Erro: {error}', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
