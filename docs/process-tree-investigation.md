# Process Tree Investigation with Wazuh and Sysmon

## Objetivo

Esta etapa do Home Lab teve como objetivo investigar alertas de endpoint utilizando a telemetria do Sysmon recebida pelo Wazuh e reconstruir a árvore de processos associada a uma detecção.

O foco foi trabalhar com:

- Sysmon Event ID 1
- ProcessGuid
- ParentProcessGuid
- Wazuh Detection Rules
- MITRE ATT&CK
- Process Tree
- Historical Alerts
- SOC N1 Triage

---

## Cenário de teste

Foi utilizada uma sessão elevada do PowerShell para iniciar o Windows Command Shell:

~~cmd
whoami && hostname && ipconfig && net user
~~

O objetivo foi gerar uma sequência controlada de ações de Discovery.

A cadeia principal observada foi:

~~text
powershell.exe
└── cmd.exe
    ├── whoami.exe
    ├── HOSTNAME.EXE
    ├── ipconfig.exe
    └── net.exe
        └── net1.exe
~~

---

## Sysmon Event ID 1

O Sysmon registrou a criação dos processos utilizando o Event ID:

~~text
Event ID 1 - Process Create
~~

Entre os campos utilizados na investigação:

- ProcessGuid
- ProcessId
- Image
- CommandLine
- User
- IntegrityLevel
- Hashes
- ParentProcessGuid
- ParentProcessId
- ParentImage
- ParentCommandLine

---

## ProcessGuid

O `ProcessGuid` identifica uma instância específica de processo.

Exemplo:

~~text
ProcessGuid:
{3aa82e30-1a15-6a89-9003-000000001b00}
~~

Durante a investigação, esse GUID correspondia ao processo:

~~text
C:\Windows\System32\cmd.exe
~~

---

## ParentProcessGuid

O `ParentProcessGuid` foi utilizado para localizar os processos criados pelo processo investigado.

A lógica utilizada foi:

~~text
ProcessGuid do processo atual
        ↓
buscar eventos onde
ParentProcessGuid == ProcessGuid
        ↓
localizar processos filhos
        ↓
repetir recursivamente
~~

---

## Investigação manual com jq

Inicialmente a árvore foi investigada manualmente.

Exemplo:

~~bash
sudo jq -c '
select(
  .data.win.eventdata.parentProcessGuid ==
  "{PROCESS-GUID}"
)
|
{
  timestamp: .timestamp,
  rule: .rule.id,
  description: .rule.description,
  processGuid: .data.win.eventdata.processGuid,
  image: .data.win.eventdata.image,
  commandLine: .data.win.eventdata.commandLine,
  parentImage: .data.win.eventdata.parentImage
}' /var/ossec/logs/alerts/alerts.json
~~

Isso permitia localizar os filhos diretos de determinado processo.

---

## Detecção customizada

A principal regra utilizada neste cenário foi:

~~text
Rule ID: 100130
Level: 12

SOC LAB:
Multiple Windows discovery commands executed
from elevated PowerShell.
~~

A regra identifica a combinação:

~~text
PowerShell
   ↓
cmd.exe
   ↓
High Integrity
   ↓
whoami
hostname
ipconfig
net user
~~

---

## MITRE ATT&CK

A Rule 100130 foi associada às seguintes técnicas:

| Technique | Description |
|---|---|
| T1033 | System Owner/User Discovery |
| T1016 | System Network Configuration Discovery |
| T1087.001 | Local Account |
| T1059.003 | Windows Command Shell |

As táticas observadas incluíram:

- Discovery
- Execution

---

## Regras observadas na árvore

Durante o cenário foram observadas regras customizadas e nativas do Wazuh.

| Process | Rule | Level |
|---|---:|---:|
| cmd.exe | 100130 | 12 |
| whoami.exe | 92032 | 3 |
| HOSTNAME.EXE | 92032 | 3 |
| ipconfig.exe | 92032 | 3 |
| net.exe | 92036 | 3 |
| net1.exe | 92031 | 3 |

---

# Automação

A investigação manual foi posteriormente automatizada utilizando Bash.

Arquivo:

~~text
scripts/process-tree.sh
~~

A ferramenta reconstrói a árvore de processos utilizando os relacionamentos entre:

~~text
ProcessGuid
+
ParentProcessGuid
~~

---

## Buscar diretamente por ProcessGuid

~~bash
./scripts/process-tree.sh '{PROCESS-GUID}'
~~

---

## Buscar pelo Rule ID

~~bash
./scripts/process-tree.sh --rule 100130
~~

A ferramenta encontra o alerta mais recente da regra e extrai automaticamente o `ProcessGuid`.

---

## Modo resumido

~~bash
./scripts/process-tree.sh --rule 100130 --summary
~~

Exemplo:

~~text
powershell.exe
└── cmd.exe [Rule 100130 | L12]
    ├── whoami.exe [Rule 92032 | L3]
    ├── HOSTNAME.EXE [Rule 92032 | L3]
    ├── ipconfig.exe [Rule 92032 | L3]
    └── net.exe [Rule 92036 | L3]
        └── net1.exe [Rule 92031 | L3]
~~

---

# Wazuh Log Rotation

Durante os testes foi identificado um problema importante.

Inicialmente a ferramenta pesquisava somente:

~~text
/var/ossec/logs/alerts/alerts.json
~~

Após a rotação dos logs, alertas antigos deixavam de aparecer nesse arquivo.

Os eventos estavam preservados em:

~~text
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json
~~

Exemplo:

~~text
/var/ossec/logs/alerts/2026/Aug/ossec-alerts-22.json
~~

A ferramenta foi então modificada para pesquisar:

~~text
alerts.json atual
        +
ossec-alerts-*.json históricos
~~

---

## Janela temporal

Foi adicionada a opção:

~~text
--days
~~

Exemplo:

~~bash
./scripts/process-tree.sh --rule 100130 --days 7 --summary
~~

Isso limita a investigação aos arquivos de alerta da janela especificada.

---

# SOC Triage Report

Também foi implementado:

~~text
--report
~~

Exemplo:

~~bash
./scripts/process-tree.sh --rule 100130 --days 7 --report
~~

O relatório inclui:

- Rule ID
- Level
- Host
- IP
- User
- Timestamp
- ProcessGuid
- Description
- MITRE ATT&CK
- Image
- Parent Image
- Parent GUID
- Integrity Level
- CommandLine
- SHA256
- Process Tree
- Analyst Assessment

---

## Resultado da triagem

Para o cenário do laboratório:

~~text
Classification:
True Positive

Disposition:
Close - Authorized Security Test
~~

A regra identificou corretamente o comportamento para o qual havia sido criada.

Entretanto, a atividade havia sido executada intencionalmente dentro do ambiente controlado.

Portanto:

~~text
Detection:
True Positive

Malicious activity:
No

Incident:
No

Escalation:
Not required
~~

---

## Conceito importante

Um True Positive não significa automaticamente um comprometimento confirmado.

~~text
True Positive
      !=
Confirmed Malicious Activity
~~

O contexto precisa ser analisado antes da disposição final do alerta.

---

# Troubleshooting realizado

## Sysmon Event Flood

A configuração inicial do Sysmon produziu grande quantidade de eventos.

O Wazuh Agent chegou a indicar saturação do buffer.

Foi realizado tuning da configuração do Sysmon para reduzir telemetria desnecessária.

---

## Arquivo ativo sendo escrito

O `alerts.json` é continuamente atualizado pelo Wazuh.

Durante a primeira versão da ferramenta, o `jq` chegou a encontrar uma linha JSON incompleta enquanto o arquivo estava sendo escrito.

A solução incluiu:

- leitura tolerante com `fromjson?`;
- criação de snapshot temporário dos alertas;
- processamento consistente da investigação.

---

## Process Tree recursiva

A primeira implementação também apresentou duplicação de GUIDs durante a recursão.

O problema foi corrigido utilizando:

- controle de GUIDs visitados;
- variáveis locais dentro das funções Bash;
- proteção contra GUID vazio;
- profundidade máxima de recursão.

---

# Resultado final

Foi possível automatizar o fluxo:

~~text
Alert
  ↓
Rule ID
  ↓
ProcessGuid
  ↓
ParentProcessGuid
  ↓
Recursive Process Tree
  ↓
MITRE ATT&CK
  ↓
SOC Triage Report
~~

Esta etapa demonstra integração prática entre:

- Windows
- Sysmon
- Wazuh
- Bash
- jq
- MITRE ATT&CK
- SOC Alert Triage

---

## Disclaimer

Todos os comandos e testes foram executados em ambiente de laboratório controlado e autorizado.
