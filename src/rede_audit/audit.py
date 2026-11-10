"""Validacao de inventario e comparacao com uma referencia explicita."""
from __future__ import annotations

import ipaddress

from .scanner import parse_network, validate_ports


def _ip(value, scope):
    if not isinstance(value, str):
        raise ValueError('O endereco IP deve ser um texto IPv4 numerico.')
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError(f'Endereco IPv4 invalido: {value!r}.') from error
    if ip not in scope or (scope.prefixlen < 31 and ip in {scope.network_address, scope.broadcast_address}):
        raise ValueError('O host informado esta fora dos hosts utilizaveis do escopo.')
    return str(ip)


def _ports_or_empty(value):
    if not isinstance(value, list):
        raise ValueError('As portas devem ser uma lista de inteiros.')
    return validate_ports(value) if value else []


def validate_snapshot(snapshot: dict) -> dict:
    if not isinstance(snapshot, dict) or type(snapshot.get('schema_version')) is not int or snapshot.get('schema_version') != 1:
        raise ValueError('Snapshot deve usar schema_version 1.')
    scope = parse_network(snapshot.get('network'))
    ports = validate_ports(snapshot.get('ports_scanned'))
    if not isinstance(snapshot.get('hosts'), list) or len(snapshot['hosts']) > 256:
        raise ValueError('Snapshot deve conter uma lista com ate 256 hosts.')
    seen, normalized = set(), []
    for host in snapshot['hosts']:
        if not isinstance(host, dict):
            raise ValueError('Cada host deve ser um objeto.')
        ip = _ip(host.get('ip'), scope)
        if ip in seen:
            raise ValueError('Snapshot possui hosts duplicados.')
        seen.add(ip)
        responsive = host.get('responsive')
        if type(responsive) is not bool:
            raise ValueError('O campo responsive deve ser booleano.')
        opened = _ports_or_empty(host.get('open_tcp_ports'))
        if not set(opened) <= set(ports):
            raise ValueError('Uma porta aberta deve pertencer a ports_scanned.')
        if opened and not responsive:
            raise ValueError('Um host com portas abertas deve ser responsivo.')
        normalized.append({'ip': ip, 'responsive': responsive, 'open_tcp_ports': opened})
    normalized.sort(key=lambda host: int(ipaddress.IPv4Address(host['ip'])))
    return {**snapshot, 'network': str(scope), 'ports_scanned': ports, 'hosts': normalized,
            'stats': {'hosts_scanned': len(normalized), 'hosts_responsive': sum(h['responsive'] for h in normalized),
                      'open_ports': sum(len(h['open_tcp_ports']) for h in normalized)}}


def validate_baseline(baseline: dict) -> dict:
    if not isinstance(baseline, dict) or type(baseline.get('schema_version')) is not int or baseline.get('schema_version') != 1:
        raise ValueError('Baseline deve usar schema_version 1.')
    scope = parse_network(baseline.get('network'))
    if not isinstance(baseline.get('hosts'), dict) or len(baseline['hosts']) > 256:
        raise ValueError('Baseline deve conter um mapa de ate 256 hosts.')
    hosts = {}
    for address, host in baseline['hosts'].items():
        ip = _ip(address, scope)
        if not isinstance(host, dict):
            raise ValueError('Cada host da baseline deve ser um objeto.')
        hosts[ip] = {'allowed_tcp_ports': _ports_or_empty(host.get('allowed_tcp_ports'))}
    return {**baseline, 'network': str(scope), 'hosts': hosts}


def audit_snapshot(snapshot: dict, baseline: dict) -> list[dict]:
    observed = validate_snapshot(snapshot)
    reference = validate_baseline(baseline)
    if observed['network'] != reference['network']:
        raise ValueError('Snapshot e baseline devem representar o mesmo CIDR.')
    findings = []
    for host in observed['hosts']:
        if not host['responsive']:
            continue
        address = host['ip']
        expected = reference['hosts'].get(address)
        if expected is None:
            findings.append({'id': 'HOST_NOT_IN_BASELINE', 'severity': 'medium',
                'title': 'Host observado fora da referencia', 'host': address, 'source': 'inventory',
                'evidence': f'O host respondeu a TCP e nao consta na baseline. Portas abertas: {host["open_tcp_ports"]}.',
                'recommendation': 'Confirme a identidade e a autorizacao do equipamento no inventario; considere mudancas legitimas de DHCP antes de agir.'})
        else:
            unexpected = sorted(set(host['open_tcp_ports']) - set(expected['allowed_tcp_ports']))
            if unexpected:
                findings.append({'id': 'UNEXPECTED_OPEN_PORT', 'severity': 'medium',
                    'title': 'Porta aberta fora da referencia', 'host': address, 'source': 'inventory',
                    'evidence': f'Portas TCP abertas que nao estao na baseline: {unexpected}.',
                    'recommendation': 'Confirme a finalidade dos servicos; desative os desnecessarios ou restrinja o acesso por firewall e atualize a referencia apos revisao.'})
        legacy = sorted(set(host['open_tcp_ports']) & {21, 23, 110, 143})
        if legacy:
            findings.append({'id': 'LEGACY_SERVICE_PORT', 'severity': 'low',
                'title': 'Revisar portas associadas a protocolos legados', 'host': address, 'source': 'inventory',
                'evidence': f'Portas abertas: {legacy}. O numero da porta sugere um servico, mas nao comprova protocolo ou ausencia de TLS.',
                'recommendation': 'Identifique o servico de fato e confira criptografia, autenticacao e necessidade de exposicao; prefira alternativas protegidas quando aplicavel.'})
    return findings
