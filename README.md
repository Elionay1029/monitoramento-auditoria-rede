# Monitoramento e auditoria de rede com Python

Ferramenta de linha de comando para inventariar portas TCP, comparar o resultado com uma baseline e analisar arquivos PCAP com Scapy. Os achados incluem evidências e sugestões de mitigação, com relatórios em HTML, Markdown, JSON e CSV.

**Projeto pessoal de portfólio criado em 2026.** A demonstração usa inventário e pacotes, incluídos no repositório. Ela permite conhecer o fluxo sem acessar uma rede real.

## Funcionalidades

- Inventário TCP por conexão, com rede e portas definidas explicitamente.
- Comparação de hosts e portas abertas com uma baseline JSON.
- Identificação de serviços legados e dispositivos fora do inventário esperado.
- Análise offline de PCAP: padrões de tentativas TCP SYN e associações IP/MAC conflitantes.
- Relatórios HTML e Markdown para leitura, JSON para processamento e CSV de alertas.
- Limites de escopo, timeout e concorrência, com testes automatizados.

```text
Snapshot de inventário + Baseline JSON
                 |              PCAP local
                 v                  |
        Comparação de regras        v
                 |          Análise com Scapy
                 +---------+--------+
                           v
                  Evidências e mitigações
                           |
                           v
               HTML / Markdown / JSON / CSV
```

## Instalar no Windows

Requisito: [Python 3.11 ou superior](https://www.python.org/downloads/). A demonstração e a análise de arquivos PCAP funcionam offline, sem Npcap e sem abrir o terminal como administrador.

Clone o repositório com Git ou use **Code > Download ZIP** no GitHub. Para clonar e instalar pelo PowerShell:

```powershell
git clone https://github.com/Elionay1029/monitoramento-auditoria-rede.git
cd monitoramento-auditoria-rede
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Se você baixou o ZIP, abra o PowerShell na pasta que contém `pyproject.toml` e comece pelo comando de criação do ambiente virtual.

Caso a ativação seja bloqueada pelo PowerShell, use o interpretador diretamente:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m rede_audit demo --output reports/demo
```

## Executar a demonstração offline

Na raiz do projeto, com o ambiente virtual ativo:

```powershell
python -m rede_audit demo --output reports/demo
```

O comando combina `data/demo/snapshot_demo.json`, `config/baseline.example.json` e `data/demo/traffic_demo.pcap`. Não inicia uma varredura: trabalha com os arquivos locais incluídos.

| Saída | Uso |
| --- | --- |
| `reports/demo/relatorio.html` | Resumo visual dos achados, evidências e mitigações |
| `reports/demo/relatorio.md` | Relatório em Markdown, adequado para leitura no GitHub |
| `reports/demo/relatorio.json` | Resultado estruturado da auditoria |
| `reports/demo/alertas.csv` | Alertas em formato tabular |

Uma cópia do relatório de demonstração fica em [docs/exemplo-relatorio.md](docs/exemplo-relatorio.md), para consultar o resultado pelo GitHub.

Para abrir o relatório no Windows:

```powershell
Invoke-Item reports/demo/relatorio.html
```

### O que existe nos dados 

O snapshot representa quatro hosts consultados: três respondem e somam cinco portas TCP abertas. A baseline contém dois hosts conhecidos. A massa foi construída para demonstrar estes achados:

| Origem | Cenário | Regra esperada |
| --- | --- | --- |
| Inventário | `192.168.56.1` expõe a porta 23, ausente das portas aprovadas | `UNEXPECTED_OPEN_PORT` |
| Inventário | A porta 23 está associada a um serviço legado que merece revisão | `LEGACY_SERVICE_PORT` |
| Inventário | `192.168.56.99` responde, mas não consta da baseline | `HOST_NOT_IN_BASELINE` |
| PCAP sintético | Uma origem tenta várias portas em uma janela de tempo | `PORT_SCAN_PATTERN` |
| PCAP sintético | Um IP aparece associado a MACs diferentes em mensagens ARP | `ARP_IP_CONFLICT` |

Esses eventos são exemplos para exercitar as regras, não incidentes encontrados em uma organização.

## Analisar somente um PCAP

```powershell
python -m rede_audit analyze-pcap --pcap data/demo/traffic_demo.pcap --output reports/pcap.json
```

A leitura aceita PCAP clássico com quadros Ethernet e processa o arquivo de forma incremental. PCAPNG e arquivos compactados não fazem parte deste contrato de entrada. Ela não captura tráfego ao vivo nem transmite os pacotes do arquivo. Arquivos PCAP reais podem conter informações sensíveis; escolha quais arquivos e relatórios podem ser compartilhados.

### Recriar os pacotes de exemplo

```powershell
python scripts/generate_demo_pcap.py
```

O gerador cria `data/demo/traffic_demo.pcap` com data fixa em 1º de janeiro de 2026. São 16 pacotes sintéticos: 12 tentativas TCP SYN para portas distintas, duas mensagens ARP com associação IP/MAC conflitante, um pacote UDP/DNS e um TCP ACK. A geração grava somente o arquivo local; não transmite pacotes.

## Inventariar uma rede de laboratório

O comando `scan` é ativo: abre tentativas de conexão TCP. Use uma rede própria ou para a qual você tenha autorização. O exemplo abaixo pressupõe um laboratório configurado em `192.168.56.0/28`:

```powershell
python -m rede_audit scan --network 192.168.56.0/28 --ports 22,80,443 --output reports/scan.json
```

O escopo deve ser IPv4 e estar integralmente contido em uma das faixas admitidas: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` ou loopback `127.0.0.0/8`. A ferramenta limita a operação a 256 hosts, 64 portas e 32 workers, com timeout por conexão.

Para um primeiro teste na própria máquina, você pode apontar o comando para um serviço local que tenha iniciado:

```powershell
python -m rede_audit scan --network 127.0.0.1/32 --ports 8000 --output reports/loopback.json
```

Uma conexão bem-sucedida indica que a porta estava alcançável naquele momento. Timeout e outros erros têm significado diferente de uma recusa explícita de conexão.

## Comparar o inventário com uma baseline

Crie uma cópia local de `config/baseline.example.json` e ajuste os hosts, as portas permitidas e o CIDR ao seu laboratório:

```powershell
Copy-Item config/baseline.example.json config/baseline.local.json
```

A referência e o snapshot precisam ter **exatamente o mesmo CIDR**. O arquivo da demonstração usa `/24`; para o exemplo de scan anterior, edite `network` na cópia para `192.168.56.0/28`. A cópia local fica fora do versionamento. Sua estrutura será:

```json
{
  "schema_version": 1,
  "network": "192.168.56.0/28",
  "hosts": {
    "192.168.56.1": {"allowed_tcp_ports": [22, 443]},
    "192.168.56.2": {"allowed_tcp_ports": [443]}
  }
}
```

Depois de gerar um snapshot:

```powershell
python -m rede_audit audit --snapshot reports/scan.json --baseline config/baseline.local.json --output reports/auditoria
```

Para incluir também a análise de um arquivo PCAP na mesma auditoria:

```powershell
python -m rede_audit audit --snapshot reports/scan.json --baseline config/baseline.local.json --output reports/auditoria --pcap data/demo/traffic_demo.pcap
```

A baseline é uma referência aprovada para comparação. Atualize-a após revisar uma mudança legítima, em vez de aprovar automaticamente tudo o que aparece em um novo snapshot.

O arquivo PCAP é analisado integralmente, inclusive endereços que estejam fora do CIDR do inventário. Os achados indicam sua origem (`inventory` ou `pcap`); não existe filtro implícito de pacotes pelo escopo do scan.

## Testes

```powershell
python -m unittest discover -s tests -v
```

Esse comando permite verificar o estado atual do projeto no seu ambiente. Os testes de conexão devem usar loopback e um servidor local controlado; a demonstração usa os arquivos sintéticos.

O workflow `.github/workflows/ci.yml` executa a suíte e a demonstração em Linux/Python 3.11 e Windows/Python 3.12. A validação local foi feita com Scapy 2.8.0; as versões estão em `requirements-tested-py312.txt`. No Windows sem Npcap, o Scapy pode mostrar um aviso de ausência de libpcap: a leitura dos arquivos e a demonstração offline continuam funcionando.

## Estrutura

```text
config/baseline.example.json   Hosts conhecidos e portas permitidas
data/demo/snapshot_demo.json   Inventário fictício de demonstração
data/demo/traffic_demo.pcap    Pacotes sintéticos para análise offline
docs/descricao-curriculo.md    Descrição do projeto para o currículo
scripts/generate_demo_pcap.py  Gerador dos pacotes sintéticos
src/rede_audit/                Pacote, scanner, análise e relatórios
tests/                        Testes automatizados
reports/                      Saídas geradas pelas execuções
```

## Interpretação e escopo

Os alertas são sinais para investigação. Uma porta aberta não comprova uma vulnerabilidade; um host fora da baseline não comprova invasão; mudanças IP/MAC e padrões TCP também podem ter explicações legítimas. Revise a evidência e o contexto antes de aplicar uma mitigação.

O projeto demonstra inventário, análise de arquivos e geração de relatórios. Não implementa um SIEM nem monitoramento contínuo de produção. A documentação usa princípios de gestão de riscos inspirados na ISO/IEC 27001 e orientações de logs da NIST SP 800-92; isso não constitui certificação ou declaração de conformidade com essas referências.

## Referências

- [Scapy: PcapReader e escrita de PCAP](https://scapy.readthedocs.io/en/latest/api/scapy.utils.html).
- Python: [ipaddress](https://docs.python.org/3/library/ipaddress.html) e [socket](https://docs.python.org/3/library/socket.html).
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final).
- [ISO/IEC 27001:2022: Information security management systems](https://www.iso.org/standard/27001).
