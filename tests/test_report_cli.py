"""Relatorios escapados, comandos integrados e demonstracao sem scan."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rede_audit.cli import main, perform_audit
from rede_audit.report import build_report, write_json, write_report

ROOT = Path(__file__).resolve().parents[1]


class ReportAndCliTests(unittest.TestCase):
    def test_demo_is_offline_and_generates_consistent_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('rede_audit.scanner._probe', side_effect=AssertionError('Demo must not scan')):
                with contextlib.redirect_stdout(io.StringIO()):
                    code = main(['demo', '--output', directory])
            self.assertEqual(code, 0)
            root = Path(directory)
            report = json.loads((root / 'relatorio.json').read_text(encoding='utf-8'))
            self.assertEqual(report['summary']['findings_total'], 5)
            self.assertEqual(report['summary']['packets_analyzed'], 16)
            self.assertEqual(report['summary']['hosts_responsive'], 3)
            rules = {finding['id'] for finding in report['findings']}
            self.assertEqual(rules, {'HOST_NOT_IN_BASELINE', 'UNEXPECTED_OPEN_PORT',
                                    'LEGACY_SERVICE_PORT', 'PORT_SCAN_PATTERN', 'ARP_IP_CONFLICT'})
            self.assertTrue((root / 'relatorio.html').is_file())
            self.assertTrue((root / 'relatorio.md').is_file())
            with (root / 'alertas.csv').open(encoding='utf-8-sig', newline='') as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 5)

    def test_rendered_data_cannot_insert_html_or_spreadsheet_formulas(self):
        snapshot = {'network': '127.0.0.1/32', 'stats': {'hosts_scanned': 1, 'hosts_responsive': 1, 'open_ports': 1}}
        findings = [{'id': '=1+1', 'severity': 'medium', 'title': '<script>alert(1)</script>',
                     'host': '127.0.0.1', 'source': 'inventory', 'evidence': '<img src=x onerror=alert(1)>',
                     'recommendation': 'Review <b>literally</b>'}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_report(build_report(snapshot, findings), root)
            html = (root / 'relatorio.html').read_text(encoding='utf-8')
            self.assertNotIn('<script>', html)
            self.assertNotIn('<img src=x', html)
            self.assertIn('&lt;script&gt;', html)
            self.assertNotIn('<script>', (root / 'relatorio.md').read_text(encoding='utf-8'))
            with (root / 'alertas.csv').open(encoding='utf-8-sig', newline='') as stream:
                self.assertEqual(next(csv.DictReader(stream))['id'], "'=1+1")

    def test_empty_report_is_legible(self):
        snapshot = {'network': '127.0.0.1/32', 'stats': {'hosts_scanned': 1, 'hosts_responsive': 0, 'open_ports': 0}}
        with tempfile.TemporaryDirectory() as directory:
            write_report(build_report(snapshot, []), directory)
            self.assertIn('Nenhum achado', (Path(directory) / 'relatorio.html').read_text(encoding='utf-8'))

    def test_public_scope_and_duplicate_json_keys_fail_before_scanning(self):
        with patch('rede_audit.scanner._probe') as probe, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', '--network', '8.8.8.8/32', '--ports', '443']), 2)
            probe.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.json'
            path.write_text('{"schema_version":1,"schema_version":2}', encoding='utf-8')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['audit', '--snapshot', str(path), '--baseline', str(path), '--output', str(Path(directory) / 'out')]), 2)
            self.assertFalse((Path(directory) / 'out').exists())

    def test_nonfinite_json_is_not_written(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.json'
            with self.assertRaises(ValueError):
                write_json(path, {'invalid': float('nan')})
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])
