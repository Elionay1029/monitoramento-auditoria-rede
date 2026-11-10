# Monitoramento e Auditoria de Segurança de Rede

**Demonstração com dados fictícios**

Escopo do inventário: `192.168.56.0/24`. Pacotes analisados: 16.
O PCAP é analisado integralmente, sem filtro automático pelo CIDR do inventário.

| Indicador | Valor |
| --- | ---: |
| Hosts no inventário | 4 |
| Hosts responsivos | 3 |
| Portas abertas | 5 |
| Achados para revisão | 5 |

## Achados

### PORT_SCAN_PATTERN - Indício de varredura TCP SYN

**Prioridade:** Alta · **Host:** `192.168.56.99`

**Evidência:** Origem 192.168.56.99 para destino 192.168.56.1: 12 portas de destino únicas em pacotes SYN sem ACK (20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31), entre 2026-01-01T00:00:00.000000Z e 2026-01-01T00:00:11.000000Z, dentro de uma janela de 60 segundos.

**Ação sugerida:** Verificar se a origem pertence a uma ferramenta de monitoramento ou teste autorizada; correlacionar os horários com os registros de firewall antes de concluir que há atividade indevida.

### UNEXPECTED_OPEN_PORT - Porta aberta fora da referencia

**Prioridade:** Média · **Host:** `192.168.56.1`

**Evidência:** Portas TCP abertas que nao estao na baseline: [23].

**Ação sugerida:** Confirme a finalidade dos servicos; desative os desnecessarios ou restrinja o acesso por firewall e atualize a referencia apos revisao.

### ARP_IP_CONFLICT - IP anunciado por múltiplos endereços MAC

**Prioridade:** Média · **Host:** `192.168.56.2`

**Evidência:** O IP 192.168.56.2 foi anunciado por 2 MACs distintos: 02:00:00:00:00:20, 02:00:00:00:00:21, entre 2026-01-01T00:00:20.000000Z e 2026-01-01T00:00:21.000000Z. Pode haver IP duplicado, mudança legítima de equipamento ou outra inconsistência; o achado não confirma ataque.

**Ação sugerida:** Conferir o inventário, as concessões DHCP e os equipamentos envolvidos; investigar duplicidade de IP e mudanças de interface antes de aplicar medidas de contenção.

### HOST_NOT_IN_BASELINE - Host observado fora da referencia

**Prioridade:** Média · **Host:** `192.168.56.99`

**Evidência:** O host respondeu a TCP e nao consta na baseline. Portas abertas: [8080].

**Ação sugerida:** Confirme a identidade e a autorizacao do equipamento no inventario; considere mudancas legitimas de DHCP antes de agir.

### LEGACY_SERVICE_PORT - Revisar portas associadas a protocolos legados

**Prioridade:** Baixa · **Host:** `192.168.56.1`

**Evidência:** Portas abertas: [23]. O numero da porta sugere um servico, mas nao comprova protocolo ou ausencia de TLS.

**Ação sugerida:** Identifique o servico de fato e confira criptografia, autenticacao e necessidade de exposicao; prefira alternativas protegidas quando aplicavel.


As heurísticas exigem revisão humana. O relatório não comprova invasão, vulnerabilidade ou conformidade ISO/IEC 27001.
