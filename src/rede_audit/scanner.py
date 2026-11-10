"""Scanner TCP connect limitado a enderecos numericos de redes locais."""
from __future__ import annotations

import errno
import ipaddress
import math
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

LOCAL_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in
                       ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'])


def parse_network(value: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise ValueError('Informe a rede como texto IPv4 numerico com prefixo CIDR.')
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError) as error:
        raise ValueError('Informe uma rede IPv4 numerica canonica, como 192.168.56.0/28 ou 127.0.0.1/32.') from error
    if not isinstance(network, ipaddress.IPv4Network) or not any(network.subnet_of(allowed) for allowed in LOCAL_NETWORKS):
        raise ValueError('O escopo deve estar inteiramente em uma rede RFC1918 ou loopback IPv4.')
    count = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
    if count > 256:
        raise ValueError('O limite e de 256 hosts por execucao; escolha um CIDR menor.')
    return network


def validate_ports(ports: list[int]) -> list[int]:
    if not isinstance(ports, (list, tuple)) or not 1 <= len(ports) <= 64:
        raise ValueError('Informe de 1 a 64 portas TCP.')
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError('Cada porta deve ser um inteiro entre 1 e 65535.')
    if len(set(ports)) != len(ports):
        raise ValueError('A lista de portas nao pode conter duplicatas.')
    return sorted(ports)


def _probe(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            result = connection.connect_ex((ip, port))
        if result == 0:
            return 'open'
        if result in {errno.ECONNREFUSED, 10061}:
            return 'refused'
    except OSError:
        pass
    return 'unresponsive'


def scan_network(network: str, ports: list[int], timeout: float = .3, workers: int = 16) -> dict:
    scope = parse_network(network)
    selected_ports = validate_ports(ports)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not .05 <= timeout <= 3:
        raise ValueError('Timeout deve estar entre 0.05 e 3 segundos.')
    if type(workers) is not int or not 1 <= workers <= 32:
        raise ValueError('Concorrencia deve ser um inteiro entre 1 e 32.')
    targets = [str(ip) for ip in scope.hosts()]
    inventory = {ip: {'ip': ip, 'responsive': False, 'open_tcp_ports': []} for ip in targets}
    tasks = [(ip, port) for ip in targets for port in selected_ports]
    def probe_target(target):
        ip, port = target
        return ip, port, _probe(ip, port, float(timeout))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, port, result in pool.map(probe_target, tasks):
            if result in {'open', 'refused'}:
                inventory[ip]['responsive'] = True
            if result == 'open':
                inventory[ip]['open_tcp_ports'].append(port)
    hosts = list(inventory.values())
    return {
        'schema_version': 1, 'mode': 'tcp_connect', 'network': str(scope),
        'generated_at': datetime.now(timezone.utc).isoformat(), 'ports_scanned': selected_ports,
        'hosts': hosts, 'stats': {
            'hosts_scanned': len(hosts),
            'hosts_responsive': sum(host['responsive'] for host in hosts),
            'open_ports': sum(len(host['open_tcp_ports']) for host in hosts),
        },
    }
