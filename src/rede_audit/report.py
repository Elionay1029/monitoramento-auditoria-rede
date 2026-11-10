"""Relatorios locais legiveis, com escape de dados para HTML e planilhas."""
from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from uuid import uuid4

SEVERITIES = {'high': 'Alta', 'medium': 'Média', 'low': 'Baixa', 'info': 'Informativa'}
CSV_FIELDS = ['severity', 'id', 'host', 'title', 'evidence', 'recommendation', 'source']


def write_json(path: str | Path, data: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid4().hex + '.tmp')
    try:
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _markdown(value) -> str:
    return escape(str(value), quote=False).replace('\\', '\\\\').replace('|', '\\|').replace('\n', ' ')


def build_report(snapshot: dict, findings: list[dict], pcap: dict | None = None) -> dict:
    order = {name: position for position, name in enumerate(SEVERITIES)}
    findings = sorted(findings, key=lambda item: (order.get(item['severity'], 99), item['host'], item['id']))
    return {
        'schema_version': 1, 'generated_at': datetime.now(timezone.utc).isoformat(),
        'mode': snapshot.get('mode', 'inventory'), 'network': snapshot['network'],
        'pcap_scope': 'entire_capture' if pcap else None,
        'snapshot_generated_at': snapshot.get('generated_at', 'Não informado'),
        'summary': {**snapshot['stats'], 'findings_total': len(findings),
                    'packets_analyzed': pcap['packets_total'] if pcap else 0,
                    'by_severity': {level: sum(item['severity'] == level for item in findings) for level in SEVERITIES}},
        'findings': findings,
        'pcap_summary': {key: value for key, value in (pcap or {}).items() if key != 'findings'},
    }


def _spreadsheet_cell(value):
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def write_report(report: dict, output: str | Path) -> dict[str, str]:
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    write_json(destination / 'relatorio.json', report)
    with (destination / 'alertas.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for finding in report['findings']:
            writer.writerow({key: _spreadsheet_cell(finding.get(key, '')) for key in CSV_FIELDS})
    demonstration = report.get('mode') == 'synthetic_demo'
    mode = 'Demonstração com dados fictícios' if demonstration else 'Auditoria de inventário TCP'
    summary = report['summary']
    metrics = [('Hosts no inventário', summary['hosts_scanned']), ('Hosts responsivos', summary['hosts_responsive']),
               ('Portas abertas', summary['open_ports']), ('Achados para revisão', summary['findings_total'])]
    cards = ''.join(f'<div class="metric"><span>{escape(label)}</span><strong>{value}</strong></div>' for label, value in metrics)
    articles = []
    for finding in report['findings']:
        level = finding['severity'] if finding['severity'] in SEVERITIES else 'info'
        articles.append(f'''<article class="finding">
<div class="line"><span class="badge {level}">{SEVERITIES[level]}</span><code>{escape(str(finding['id']))}</code></div>
<h3>{escape(str(finding['title']))}</h3>
<p class="host">Host: <strong>{escape(str(finding['host']))}</strong> · Origem: {escape(str(finding['source']))}</p>
<p><strong>Evidência:</strong> {escape(str(finding['evidence']))}</p>
<p><strong>Ação sugerida:</strong> {escape(str(finding['recommendation']))}</p>
</article>''')
    findings_html = '\n'.join(articles) or '<p class="empty">Nenhum achado pelas regras e pelo escopo avaliados.</p>'
    html = f'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Monitoramento e Auditoria de Segurança de Rede</title>
<style>
:root{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#183044;background:#f3f6f9}}
*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:1000px;margin:auto;padding:40px 24px 56px}}
header{{border-top:5px solid #087c83;padding-top:24px}}.eyebrow{{color:#08757b;font-size:13px;font-weight:750;letter-spacing:.1em;text-transform:uppercase}}
h1{{font-size:clamp(28px,4vw,40px);line-height:1.14;margin:12px 0 16px;max-width:820px}}h2{{font-size:23px;margin-top:32px}}
.intro,.meta{{color:#506474;line-height:1.6}}.meta{{font-size:13px}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:28px 0}}
.metric{{background:#fff;border:1px solid #dce5ec;border-radius:10px;padding:17px}}.metric span{{display:block;color:#506474;font-size:13px}}.metric strong{{display:block;font-size:31px;margin-top:5px}}
.finding{{background:#fff;border:1px solid #dce5ec;border-radius:10px;padding:22px;margin:14px 0;break-inside:avoid}}.finding h3{{font-size:19px;margin:13px 0 8px}}
.finding p{{font-size:14px;line-height:1.6;margin:10px 0}}.line{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}code{{font-size:12px;overflow-wrap:anywhere}}
.badge{{font-size:12px;font-weight:750;padding:5px 10px;border-radius:20px}}.high{{background:#fbe4e5;color:#a12731}}.medium{{background:#fff0cf;color:#835600}}.low{{background:#dff2ee;color:#146454}}.info{{background:#e6eef7;color:#315a85}}
.host{{color:#506474}}.note{{border-left:3px solid #087c83;padding:2px 16px;margin-top:28px;color:#506474;font-size:13px;line-height:1.6}}
@media(max-width:600px){{main{{padding:24px 16px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.finding{{padding:17px}}}}
@media print{{:root{{background:white}}main{{padding:0}}.metrics{{gap:6px}}.finding{{border-radius:0}}}}
</style></head><body><main><header>
<div class="eyebrow">{mode}</div><h1>Monitoramento e Auditoria<br>de Segurança de Rede</h1>
<p class="intro">Inventário TCP comparado à referência e sinais observados em um arquivo de pacotes.</p>
<p class="meta">Escopo do inventário: <strong>{escape(report['network'])}</strong> · Pacotes analisados: {summary['packets_analyzed']}<br>
PCAP: {'captura inteira, sem filtro pelo CIDR do inventário' if summary['packets_analyzed'] else 'não fornecido'}<br>
Inventário: {escape(str(report['snapshot_generated_at']))}<br>Relatório gerado em UTC: {escape(report['generated_at'])}</p>
</header><section class="metrics" aria-label="Resumo">{cards}</section>
<h2>Evidências e recomendações</h2>{findings_html}
<div class="note">As regras indicam pontos para investigação, não confirmam invasão ou vulnerabilidade. Portas abertas não identificam o protocolo com certeza. Ausência de resposta TCP não comprova que um dispositivo esteja desligado. Este relatório não certifica conformidade com a ISO/IEC 27001.</div>
</main></body></html>'''
    (destination / 'relatorio.html').write_text(html, encoding='utf-8')
    markdown = ['# Monitoramento e Auditoria de Segurança de Rede', '', f'**{mode}**', '',
                f'Escopo do inventário: `{report["network"]}`. Pacotes analisados: {summary["packets_analyzed"]}.',
                'O PCAP é analisado integralmente, sem filtro automático pelo CIDR do inventário.' if summary['packets_analyzed'] else 'PCAP não fornecido.', '',
                '| Indicador | Valor |', '| --- | ---: |']
    markdown.extend(f'| {label} | {value} |' for label, value in metrics)
    markdown.extend(['', '## Achados', ''])
    for finding in report['findings']:
        markdown.extend([f'### {_markdown(finding["id"])} - {_markdown(finding["title"])}', '',
            f'**Prioridade:** {SEVERITIES.get(finding["severity"], "Informativa")} · **Host:** `{_markdown(finding["host"])}`', '',
            f'**Evidência:** {_markdown(finding["evidence"])}', '',
            f'**Ação sugerida:** {_markdown(finding["recommendation"])}', ''])
    if not report['findings']:
        markdown.append('Nenhum achado pelas regras e pelo escopo avaliados.')
    markdown.extend(['', 'As heurísticas exigem revisão humana. O relatório não comprova invasão, vulnerabilidade ou conformidade ISO/IEC 27001.', ''])
    (destination / 'relatorio.md').write_text('\n'.join(markdown), encoding='utf-8')
    return {name: str(destination / name) for name in ['relatorio.json', 'relatorio.html', 'alertas.csv', 'relatorio.md']}
