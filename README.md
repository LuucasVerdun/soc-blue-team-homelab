# SOC Blue Team Home Lab

Laboratório prático de Security Operations Center (SOC) focado em Blue Team, monitoramento, detecção, correlação e investigação de eventos de segurança.

O ambiente foi construído para reproduzir fluxos reais de um SOC: coleta de telemetria de endpoint, autenticação Windows, análise de processos, correlação de eventos, monitoramento de RDP e visibilidade de rede com Suricata e Zeek integrados ao Wazuh.

> Todos os testes descritos neste repositório foram executados em ambiente de laboratório controlado e autorizado.

---

## Objetivos

Este projeto tem como objetivos:

- desenvolver experiência prática em operações de SOC;
- compreender a geração, coleta e análise de logs;
- criar e ajustar regras de detecção;
- correlacionar múltiplos eventos para identificar comportamento suspeito;
- trabalhar com telemetria de endpoint e rede;
- mapear detecções para MITRE ATT&CK;
- praticar triagem, investigação e documentação de alertas;
- reduzir falsos positivos e alert fatigue por meio de tuning;
- construir evidências técnicas reproduzíveis.

---

## Arquitetura do Laboratório

```text
                         WINDOWS 11 HOST
                               |
                        VirtualBox 7.x
                               |
          +--------------------+--------------------+
          |                    |                    |
          |                    |                    |
      SOC01                WIN10              WINSERVER2022
   Ubuntu Server        Windows 10          Windows Server 2022
  192.168.100.10      192.168.100.20        192.168.100.30
          |                    |                    |
          |                    +---------+----------+
          |                              |
          |                     Host-Only Network
          |                              |
          |                         east-west
          |                           traffic
          |                              |
          +------------------------------+
                         |
                       enp0s9
                  Passive Sensor NIC
                         |
                 +-------+-------+
                 |               |
              Suricata          Zeek
                 |               |
              eve.json     conn.log / dns.log
                 |               |
                 +-------+-------+
                         |
                       Wazuh
                         |
              Detection / Correlation
```

### Redes utilizadas

```text
NAT
10.0.2.0/24

Host-Only
192.168.100.0/24
```

A rede NAT fornece conectividade externa para as VMs quando necessário.

A rede Host-Only é usada para comunicação e simulações internas entre os sistemas do laboratório.

---

## Ambiente

### Host

```text
Operating System: Windows 11
Virtualization:   VirtualBox 7.x
RAM:              24 GB
CPU:              Intel Core i5 13th Gen
```

### SOC01

```text
Operating System: Ubuntu Server 24.04.4 LTS
Hostname:         soc01

NAT:
enp0s3
10.0.2.15/24

Management:
enp0s8
192.168.100.10/24

Passive sensor:
enp0s9
No IPv4 address
No IPv6 link-local address
Promiscuous mode enabled
```

Principais componentes:

- Wazuh Manager 4.14.7
- Wazuh Indexer
- Wazuh Dashboard
- Suricata 7.0.3
- Zeek 8.2.2
- jq
- ferramentas Linux de análise e troubleshooting

### Windows 10 Endpoint

```text
Hostname: WIN10
Host-Only: 192.168.100.20
NAT:       10.0.2.3
```

Componentes:

- Wazuh Agent
- Sysmon 15.21
- PowerShell logging
- Windows Security Event Log

### Windows Server 2022

```text
Hostname: WINSERVER2022
Host-Only: 192.168.100.30
RDP:       TCP/3389
```

Uso no laboratório:

- autenticação Windows;
- Remote Desktop Protocol;
- falhas de login;
- password guessing;
- account lockout;
- successful RDP logon;
- alvo de monitoramento de rede.

---

## Componentes

| Componente | Função |
|---|---|
| Wazuh | SIEM/XDR, análise, correlação e alertas |
| Sysmon | Telemetria detalhada de endpoint Windows |
| Windows Event Logs | Autenticação, segurança e PowerShell |
| Suricata | Network IDS e inspeção de tráfego |
| EVE JSON | Telemetria estruturada gerada pelo Suricata |
| MITRE ATT&CK | Classificação das técnicas observadas |
| VirtualBox | Virtualização e segmentação do laboratório |
| Bash / jq | Consulta, filtragem e investigação de alertas |

---

# Endpoint Monitoring

## Sysmon + Wazuh

O Sysmon foi instalado no Windows 10 e integrado ao Wazuh.

Canal monitorado:

```text
Microsoft-Windows-Sysmon/Operational
```

A configuração utilizada prioriza eventos úteis para investigação de SOC, incluindo:

- Process Create;
- Network Connect;
- File Create;
- DNS Query.

Eventos de Registry Event foram reduzidos para evitar excesso de ruído durante esta fase do laboratório.

### Process Creation

A telemetria de criação de processos permite analisar:

```text
Parent process
      |
      v
Child process
      |
      v
Command line
      |
      v
User / Integrity Level
```

Essa visibilidade foi usada para detectar cadeias envolvendo PowerShell, `cmd.exe` e comandos de discovery.

---

# PowerShell Monitoring

O PowerShell Script Block Logging foi habilitado e coletado pelo Wazuh.

Evento principal:

```text
Event ID 4104
Microsoft-Windows-PowerShell/Operational
```

Foi criado um marcador controlado para validar a ingestão do evento.

## Rule 100100

```text
Rule ID: 100100
Level:   10
MITRE:   T1059.001 - PowerShell
```

Objetivo:

Detectar um Script Block contendo o marcador controlado utilizado no laboratório.

---

# Process Execution and Discovery Detection

## Rule 100110

```text
Rule ID: 100110
Level:   8
MITRE:   T1059.003 - Windows Command Shell
```

Detecta:

```text
PowerShell
    |
    v
cmd.exe
```

em contexto de alta integridade.

---

## Rule 100120

```text
Rule ID: 100120
Level:   10
MITRE:
T1033     - System Owner/User Discovery
T1059.003 - Windows Command Shell
```

Detecta execução de:

```text
whoami
```

quando associada à cadeia de processos monitorada.

---

## Rule 100130

```text
Rule ID: 100130
Level:   12
```

Detecta uma sequência controlada de discovery:

```text
whoami
hostname
ipconfig
net user
```

MITRE ATT&CK:

```text
T1033     - System Owner/User Discovery
T1016     - System Network Configuration Discovery
T1087.001 - Local Account Discovery
T1059.003 - Windows Command Shell
```

Classificação do teste:

```text
True Positive
Authorized Security Test
```

Evidência:

```text
cases/case-100130-discovery.txt
```

---

# Process Tree Investigation Utility

Foi criada uma ferramenta Bash para investigação de árvores de processo em alertas Wazuh.

Arquivo:

```text
scripts/process-tree.sh
```

A ferramenta permite pesquisar por:

```text
ProcessGuid
Rule ID
```

e reconstruir processos descendentes.

Principais recursos:

```text
--days
--summary
--report
```

Também realiza busca em:

```text
current alerts.json
historical ossec-alerts-*.json
```

Os alertas históricos são consultados em estruturas como:

```text
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-*.json
```

O processamento utiliza `jq` e tolera registros JSON incompletos por meio de parsing seguro.

Documentação:

```text
docs/process-tree-investigation.md
```

---

# Windows Authentication Monitoring

A segunda camada do laboratório concentra-se em eventos de autenticação Windows.

Eventos analisados:

```text
4624 - Successful logon
4625 - Failed logon
4740 - User account locked out
```

---

## Event ID 4625 - Failed Logon

Um teste com usuário inexistente gerou:

```text
Event ID:       4625
Logon Type:     3
Auth Package:   NTLM
Source Address: 127.0.0.1
Status:         0xC000006D
SubStatus:      0xC0000064
```

O Wazuh classificou o evento pela regra nativa:

```text
60122
```

---

## Rule 60204 - Multiple Windows Logon Failures

Regra nativa do Wazuh:

```text
Rule:      60204
Level:     10
Frequency: 8
Timeframe: 240 seconds
MITRE:     T1110
```

Utilizada para detectar múltiplas falhas de autenticação Windows.

---

## Rule 100135 - Wrong Password for Existing Account

Foi necessário diferenciar:

```text
usuário inexistente
```

de:

```text
usuário existente + senha incorreta
```

A regra `100135` utiliza:

```text
SubStatus 0xC000006A
```

Configuração lógica:

```text
Parent: 60122
Condition: win.eventdata.subStatus = 0xc000006a
```

Resultado:

```text
Rule:  100135
Level: 6
```

---

## Rule 100140 - Password Guessing

Correlação de várias falhas contra:

```text
mesmo usuário
+
mesmo endereço IP
```

Configuração:

```text
Rule:      100140
Level:     12
Frequency: 5
Timeframe: 60 seconds
```

MITRE ATT&CK:

```text
T1110.001 - Password Guessing
```

Evidência:

```text
cases/case-100140-password-guessing.txt
```

---

# Successful Authentication

## Event ID 4624

Foram analisados diferentes Logon Types.

### Logon Type 2

```text
Interactive logon
```

Regra nativa observada:

```text
60118
```

### Logon Type 3

```text
Network logon
```

Regra nativa observada:

```text
60106
```

---

## Rule 100145 - Successful Network Logon

```text
Rule ID: 100145
Level:   4
Parent:  60106
```

Objetivo:

Identificar autenticação de rede bem-sucedida.

MITRE:

```text
T1078 - Valid Accounts
```

---

## Rule 100150 - Successful Logon After Password Guessing

A regra correlaciona:

```text
Password Guessing
Rule 100140
      |
      v
Successful Network Logon
Rule 100145
```

utilizando:

```text
same target username
+
same source IP
```

Configuração:

```text
Rule:      100150
Level:     14
Timeframe: 300 seconds
```

Fluxo:

```text
Repeated authentication failures
        |
        v
Password Guessing
Rule 100140
        |
        v
Successful authentication
        |
        v
Rule 100150
```

Evidência:

```text
cases/case-100150-success-after-password-guessing.txt
```

---

# Account Lockout Detection

## Event ID 4740

O Windows foi configurado para bloquear a conta após repetidas falhas de autenticação.

Política utilizada durante os testes:

```text
Account lockout threshold: 10 attempts
Lockout duration:          10 minutes
Observation window:        10 minutes
```

O Event ID 4740 representa:

```text
A user account was locked out
```

---

## Rule 60115

Regra nativa do Wazuh observada para account lockout:

```text
Rule: 60115
Level: 9
```

MITRE:

```text
T1110 - Brute Force
T1531 - Account Access Removal
```

---

## Rule 100155 - Account Lockout After Password Guessing

A regra correlaciona:

```text
Password Guessing
100140
      |
      v
Account Lockout
60115
      |
      v
100155
```

Configuração:

```text
Rule:      100155
Level:     13
Timeframe: 300 seconds
```

Correlação:

```text
same target username
```

MITRE ATT&CK:

```text
T1110.001 - Password Guessing
T1531     - Account Access Removal
```

Evidência:

```text
cases/case-100155-account-lockout-after-password-guessing.txt
```

---

# Authentication Correlation Chains

## Password Guessing → Successful Logon

```text
4625
  |
  v
60122
  |
  v
100135
Wrong password
  |
  v
100140
Password Guessing
  |
  v
4624 Type 3
  |
  v
60106
  |
  v
100145
Successful Network Logon
  |
  v
100150
Successful Logon After Password Guessing
```

---

## Password Guessing → Account Lockout

```text
4625
  |
  v
100135
  |
  v
100140
Password Guessing
  |
  v
4740
  |
  v
60115
Account Locked
  |
  v
100155
Account Lockout After Password Guessing
```

---

# RDP Detection and Correlation

Foi implementado monitoramento específico de autenticação via Remote Desktop Protocol no Windows Server 2022.

Um detalhe importante identificado durante os testes é que falhas de autenticação RDP com Network Level Authentication podem aparecer no Security Log como:

```text
Event ID 4625
Logon Type 3
```

Portanto, um `4625 Type 3` isolado não deve ser automaticamente classificado como falha RDP.

Para aumentar a precisão, foi utilizada correlação com telemetria do serviço Remote Desktop.

---

## Event ID 261

Provider:

```text
Microsoft-Windows-TerminalServices-RemoteConnectionManager
```

Evento:

```text
261
Listener RDP-Tcp received a connection
```

A regra nativa Wazuh utilizada como parent foi:

```text
60009
```

---

## Rule 100160 - RDP Connection Received

```text
Rule:  100160
Level: 5
MITRE: T1021.001
```

Detecta o Event ID 261 do RemoteConnectionManager.

---

## Rule 100165 - Failed Authentication Associated with RDP

Correlação:

```text
Recent RDP connection
100160
      +
Failed Windows authentication
100135
```

Resultado:

```text
Rule:  100165
Level: 7
```

MITRE:

```text
T1021.001 - Remote Desktop Protocol
T1110.001 - Password Guessing
```

---

## Rule 100170 - Repeated RDP Authentication Failures

Correlação:

```text
same target username
+
same source IP
```

Configuração validada:

```text
Rule:      100170
Level:     12
Frequency: 4
Timeframe: 60 seconds
```

MITRE:

```text
T1021.001 - Remote Desktop Protocol
T1110.001 - Password Guessing
```

---

## Successful RDP Logon

Um login RDP bem-sucedido gerou:

```text
Event ID:   4624
Logon Type: 10
```

A regra nativa Wazuh identificada foi:

```text
92653
```

---

## Rule 100175 - Successful RDP Logon After Password Guessing

Correlação final:

```text
Repeated RDP failures
100170
       |
       v
Successful RDP logon
92653
       |
       v
100175
```

Configuração:

```text
Rule:      100175
Level:     14
Timeframe: 300 seconds
```

Correlação:

```text
same target username
+
same source IP
```

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
T1078.003 - Local Accounts
```

### Validação

Usuário controlado:

```text
SOC-RDP-TEST
```

Origem:

```text
192.168.100.20
```

Alvo:

```text
192.168.100.30
```

Alertas finais:

```text
2026-08-27T05:49:28.245+0000
Rule: 100170
Level: 12
User: SOC-RDP-TEST
Source IP: 192.168.100.20
```

seguido por:

```text
2026-08-27T05:49:34.744+0000
Rule: 100175
Level: 14
User: SOC-RDP-TEST
Source IP: 192.168.100.20
Logon Type: 10
```

Intervalo aproximado:

```text
6 seconds
```

Classificação:

```text
True Positive
Authorized Security Test
```

Evidência:

```text
cases/case-100175-rdp-success-after-password-guessing.txt
```

---

# Suricata Network Monitoring

A fase seguinte adicionou uma camada de Network Detection and Response ao laboratório por meio do Suricata.

## Passive Sensor Architecture

O SOC01 possui uma terceira interface:

```text
enp0s9
```

Características:

```text
IPv4:            none
IPv6 link-local: none
Capture:         AF_PACKET
Promiscuous:     Allow All
```

A interface não é utilizada para gerenciamento.

Gerenciamento permanece em:

```text
enp0s8
192.168.100.10
```

O sensor foi validado capturando tráfego unicast entre:

```text
WIN10          192.168.100.20
WINSERVER2022  192.168.100.30
```

---

## Suricata Configuration

Versão:

```text
Suricata 7.0.3 RELEASE
```

HOME_NET:

```text
192.168.100.0/24
```

Capture mode:

```text
AF_PACKET
```

Interface:

```text
enp0s9
```

Ruleset carregado:

```text
ET Open / suricata.rules
+
local.rules
```

O engine foi validado com:

```text
2 rule files processed
0 rules failed
Engine started
```

---

## RDP Protocol Visibility

O Suricata identificou tráfego RDP real entre os endpoints:

```text
192.168.100.20 -> 192.168.100.30:3389
```

Eventos observados em `eve.json`:

```text
event_type: rdp
proto:      TCP
```

Isso confirmou que a interface passiva conseguia observar e interpretar tráfego east-west.

---

# Suricata Custom Rules

Arquivo:

```text
suricata/rules/local.rules
```

Configuração validada:

```text
alert tcp 192.168.100.20 any -> 192.168.100.30 3389 (msg:"SOC LAB: RDP connection attempt detected"; flags:S; flow:to_server,stateless; sid:1000001; rev:1;)

alert tcp 192.168.100.20 any -> 192.168.100.30 any (msg:"SOC LAB: Possible TCP port scan detected"; flags:S; flow:stateless; threshold:type threshold,track by_src,count 10,seconds 10; sid:1000002; rev:2;)
```

---

## SID 1000001 - RDP Connection Attempt

```text
SID:       1000001
Revision:  1
Protocol:  TCP
Target:    192.168.100.30:3389
```

Assinatura:

```text
SOC LAB: RDP connection attempt detected
```

Exemplo validado:

```text
Source:      192.168.100.20
Destination: 192.168.100.30:3389
Action:      allowed
```

`allowed` é esperado porque o Suricata está operando como IDS passivo, não como IPS inline.

---

## Suricata → Wazuh Integration

O Suricata grava telemetria estruturada em:

```text
/var/log/suricata/eve.json
```

O Wazuh coleta o arquivo como JSON:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

O Wazuh 4.14.7 possui suporte nativo para eventos Suricata.

Arquivo de regras:

```text
/var/ossec/ruleset/rules/0475-suricata_rules.xml
```

Regra nativa utilizada:

```text
86601
Suricata: Alert - $(alert.signature)
```

---

## Rule 100180 - Suricata RDP Detection

```text
Rule:  100180
Level: 6
Parent: 86601
```

Condição:

```text
alert.signature_id = 1000001
```

Descrição:

```text
SOC LAB: Suricata detected an RDP connection attempt from WIN10 to WINSERVER2022.
```

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
Tactic: Lateral Movement
```

Pipeline validado:

```text
WIN10
192.168.100.20
       |
       | TCP SYN / 3389
       v
WINSERVER2022
192.168.100.30
       |
       v
enp0s9
       |
       v
Suricata
SID 1000001
       |
       v
eve.json
       |
       v
Wazuh 86601
       |
       v
Wazuh 100180
```

Evidência:

```text
cases/case-100180-suricata-rdp.txt
```

---

# TCP Port Scan Detection

## SID 1000002

Assinatura:

```text
SOC LAB: Possible TCP port scan detected
```

Threshold:

```text
10 TCP SYN attempts
within 10 seconds
tracked by source IP
```

Configuração:

```text
SID:      1000002
Revision: 2
```

Fluxo controlado:

```text
192.168.100.20
       |
       | TCP SYN -> multiple ports
       v
192.168.100.30
```

---

## Detection Tuning

A primeira implementação utilizou:

```text
detection_filter
```

Após o limite ser atingido, pacotes adicionais continuavam gerando alertas, aumentando o volume de eventos.

A regra foi alterada para:

```text
threshold:type threshold,track by_src,count 10,seconds 10
```

Com 21 tentativas, o comportamento validado foi aproximadamente:

```text
Tentativas 1-10   -> alert
Tentativas 11-20  -> alert
Tentativa 21      -> no additional group completed
```

Isso reduziu ruído e melhorou o controle de alertas enviados ao SIEM.

---

## Rule 100185 - TCP Port Scan

```text
Rule:  100185
Level: 8
Parent: 86601
```

Condição:

```text
alert.signature_id = 1000002
```

Descrição:

```text
SOC LAB: Suricata detected a possible TCP port scan against WINSERVER2022.
```

MITRE ATT&CK:

```text
T1046 - Network Service Discovery
Tactic: Discovery
```

Alertas validados:

```text
192.168.100.20 -> 192.168.100.30:29
192.168.100.20 -> 192.168.100.30:39
```

Pipeline:

```text
Multiple TCP SYN attempts
        |
        v
enp0s9
        |
        v
Suricata SID 1000002
        |
        v
eve.json
        |
        v
Wazuh 86601
        |
        v
Wazuh 100185
```

Evidência:

```text
cases/case-100185-suricata-port-scan.txt
```

Documentação detalhada:

```text
docs/suricata-network-monitoring.md
```

---


# Zeek Network Monitoring

A fase Zeek adicionou Network Security Monitoring orientado a metadata ao laboratório, complementando as assinaturas e alertas do Suricata.

## Arquitetura Zeek

O Zeek utiliza a mesma interface passiva dedicada:

```text
enp0s9
```

Configuração:

```text
type=standalone
host=localhost
interface=enp0s9
```

Rede local:

```text
192.168.100.0/24    SOC-LAB
```

A interface permanece sem endereço IP e não é utilizada para gerenciamento.

## JSON Logging

Os logs do Zeek foram convertidos para JSON utilizando:

```text
@load policy/tuning/json-logs
```

Principais logs utilizados nesta fase:

```text
conn.log
dns.log
notice.log
capture_loss.log
```

Isso permitiu ingestão direta pelo decoder JSON do Wazuh.

## Capture Validation

A captura do sensor foi validada com:

```text
41650 packets received
0 packets dropped
0.00% capture loss
```

Também foram observados:

```text
TCP/3389 -> service ssl
UDP/3389 -> service rdpeudp
```

entre:

```text
WIN10          192.168.100.20
WINSERVER2022  192.168.100.30
```

## Zeek Service Persistence

Após um reboot, `zeekctl status` mostrou o estado `crashed`.

A investigação confirmou:

```text
received termination signal
TERMINATED [atexit]
```

sem:

```text
OOM
segmentation fault
core dump
```

O journal mostrou que o sistema inteiro havia sido desligado no mesmo momento.

Conclusão:

```text
Zeek was terminated by system shutdown.
It was not an internal Zeek crash.
```

Foi criado um serviço systemd para executar o Zeek automaticamente após boot.

Estado final:

```text
zeek standalone localhost running
```

Suricata e os componentes Wazuh permaneceram ativos em paralelo.

## Zeek → Wazuh

O ruleset do Wazuh possui regras Zeek voltadas ao formato OwlH, utilizando campos como:

```text
bro_engine
```

Para este laboratório foi escolhida ingestão direta dos logs JSON nativos do Zeek.

Arquivos coletados:

```text
/opt/zeek/logs/current/conn.log
/opt/zeek/logs/current/dns.log
```

Campos Zeek:

```text
id.orig_h
id.orig_p
id.resp_h
id.resp_p
```

são representados pelo Wazuh como:

```text
data.id.orig_h
data.id.orig_p
data.id.resp_h
data.id.resp_p
```

---

## Rule 100190 - Zeek RDP Connection Metadata

```text
Rule:  100190
Level: 5
```

Objetivo:

Detectar metadata de conexão TCP do WIN10 para o Windows Server na porta 3389.

Evento validado:

```text
Source:           192.168.100.20:50044
Destination:      192.168.100.30:3389
Protocol:         TCP
Duration:         120.073743
Connection State: RSTO
```

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
Tactic: Lateral Movement
```

Pipeline:

```text
WIN10
  |
  v
enp0s9
  |
  v
Zeek
  |
  v
conn.log JSON
  |
  v
Wazuh
  |
  v
100190
```

A regra representa visibilidade de conexão na porta RDP e, isoladamente, não comprova autenticação RDP bem-sucedida.

Evidência:

```text
cases/case-100190-zeek-rdp-connection.txt
```

---

## Rule 100195 - Controlled Suspicious DNS Query

Foi utilizado o indicador controlado:

```text
soc-lab-beacon.example
```

Fluxo de teste:

```text
192.168.100.20
       |
       | UDP/53
       v
192.168.100.30
```

O Zeek registrou consultas:

```text
A
AAAA
```

Regra:

```text
Rule:  100195
Level: 7
```

MITRE ATT&CK:

```text
T1071.004 - DNS
Tactic: Command and Control
```

Pipeline:

```text
WIN10
  |
  v
DNS Query
  |
  v
Zeek dns.log
  |
  v
Wazuh
  |
  v
100195
```

Essa regra utiliza um indicador criado especificamente para o laboratório. Uma consulta DNS isolada não comprova atividade de Command and Control.

Evidência:

```text
cases/case-100195-zeek-dns-query.txt
```

---

## Rule 100200 - DNS Beacon-Like Activity

A regra `100200` correlaciona múltiplas ocorrências da `100195`.

Configuração:

```text
Rule:      100200
Level:     10
Frequency: 4
Timeframe: 15 seconds
```

Correlação:

```text
same source IP
+
same DNS query
```

Alerta validado:

```text
2026-08-29T05:37:40.241+0000

Source:
192.168.100.20

Destination:
192.168.100.30

Query:
soc-lab-beacon.example

QType:
AAAA
```

MITRE ATT&CK:

```text
T1071.004 - DNS
Tactic: Command and Control
```

Pipeline:

```text
Repeated DNS Queries
        |
        v
Zeek dns.log
        |
        v
100195
        |
        | 4 events / 15 seconds
        | same source
        | same query
        v
100200
Beacon-Like DNS Activity
```

A `100200` identifica um padrão compatível com beaconing no cenário controlado, não uma confirmação independente de C2 malicioso.

Evidência:

```text
cases/case-100200-zeek-dns-beacon-like.txt
```

Documentação detalhada:

```text
docs/zeek-network-monitoring.md
```

---

## Suricata + Zeek

As duas ferramentas exercem funções complementares:

```text
Suricata
    |
    +--> signature / IDS detection
    +--> custom network alerts
    +--> eve.json

Zeek
    |
    +--> connection metadata
    +--> DNS metadata
    +--> protocol visibility
    +--> behavioral context
```

Arquitetura resultante:

```text
                   enp0s9
                      |
           +----------+----------+
           |                     |
           v                     v
       Suricata                Zeek
           |                     |
       eve.json          conn.log / dns.log
           |                     |
           +----------+----------+
                      |
                      v
                    Wazuh
```

---

# Custom Detection Rules

## Wazuh Rules

| Rule | Level | Detection | MITRE |
|---|---:|---|---|
| 100100 | 10 | PowerShell Script Block marker | T1059.001 |
| 100110 | 8 | PowerShell spawning cmd.exe | T1059.003 |
| 100120 | 10 | whoami discovery | T1033, T1059.003 |
| 100130 | 12 | Multi-command discovery | T1033, T1016, T1087.001, T1059.003 |
| 100135 | 6 | Wrong password for existing account | Authentication |
| 100140 | 12 | Password guessing | T1110.001 |
| 100145 | 4 | Successful network logon | T1078 |
| 100150 | 14 | Successful logon after password guessing | Valid Accounts |
| 100155 | 13 | Account lockout after password guessing | T1110.001, T1531 |
| 100160 | 5 | RDP connection received | T1021.001 |
| 100165 | 7 | Failed authentication associated with RDP | T1021.001, T1110.001 |
| 100170 | 12 | Repeated RDP authentication failures | T1021.001, T1110.001 |
| 100175 | 14 | Successful RDP logon after password guessing | T1021.001, T1078.003 |
| 100180 | 6 | Suricata RDP connection detection | T1021.001 |
| 100185 | 8 | Suricata TCP port scan detection | T1046 |
| 100190 | 5 | Zeek RDP connection metadata | T1021.001 |
| 100195 | 7 | Zeek controlled suspicious DNS query | T1071.004 |
| 100200 | 10 | Zeek DNS beacon-like correlation | T1071.004 |

Arquivo:

```text
wazuh/rules/local_rules.xml
```

---

# Detection Correlation Overview

O laboratório atualmente possui correlação em múltiplas camadas.

## Endpoint Discovery

```text
Process Creation
      |
      v
PowerShell / cmd.exe
      |
      v
Discovery commands
      |
      v
100130
```

## Authentication

```text
Failed authentication
      |
      v
Password Guessing
100140
      |
      +---------------------+
      |                     |
      v                     v
Successful Logon       Account Lockout
100150                 100155
```

## RDP Authentication

```text
RDP connection
100160
      |
      v
Failed Authentication
100165
      |
      v
Repeated Failures
100170
      |
      v
Successful RDP Logon
100175
```

## Network Detection

```text
Network Traffic
      |
      +--------------------+
      |                    |
      v                    v
Suricata                 Zeek
      |                    |
      v                    v
eve.json            conn.log / dns.log
      |                    |
      +---------+----------+
                |
                v
              Wazuh
                |
      +---------+--------------------+
      |         |          |         |
      v         v          v         v
   100180     100185     100190    100195
   RDP IDS    Port Scan  RDP Meta  DNS Query
                                      |
                                      v
                                    100200
                              DNS Beacon-Like
```

---

# SOC Interpretation

As regras customizadas não existem apenas para aumentar o número de alertas.

O objetivo é transformar eventos técnicos isolados em contexto operacional.

Exemplo:

```text
Five failed logons
```

isoladamente podem representar:

- erro do usuário;
- credencial antiga;
- serviço configurado incorretamente;
- tentativa de ataque.

Entretanto:

```text
Repeated failed logons
same user
same source IP
        |
        v
Successful logon
```

é um comportamento mais relevante e merece maior prioridade.

O mesmo princípio é aplicado ao RDP:

```text
Event 4625 Type 3
```

sozinho não prova que a tentativa ocorreu via RDP.

A correlação com:

```text
TerminalServices Event 261
```

aumenta a confiança da detecção.

---

# SOC Triage

Durante uma investigação, os principais campos analisados incluem:

```text
timestamp
rule.id
rule.level
rule.description
agent.name
src_ip
src_port
dest_ip
dest_port
targetUserName
logonType
authenticationPackageName
processGuid
parentProcessGuid
processName
commandLine
alert.signature_id
alert.signature
MITRE technique
```

Fluxo de triagem utilizado:

```text
Alert
  |
  v
Validate source
  |
  v
Validate destination
  |
  v
Identify user / process
  |
  v
Review preceding events
  |
  v
Review subsequent events
  |
  v
Correlate endpoint + authentication + network
  |
  v
Classify
```

Classificações utilizadas nos testes controlados:

```text
True Positive
Authorized Security Test
```

---

# MITRE ATT&CK Coverage

Técnicas atualmente representadas no laboratório:

| Technique | Description | Detection |
|---|---|---|
| T1059.001 | PowerShell | 100100 |
| T1059.003 | Windows Command Shell | 100110, 100120, 100130 |
| T1033 | System Owner/User Discovery | 100120, 100130 |
| T1016 | System Network Configuration Discovery | 100130 |
| T1087.001 | Local Account Discovery | 100130 |
| T1110.001 | Password Guessing | 100140, 100155, 100165, 100170 |
| T1531 | Account Access Removal | 100155 |
| T1078 | Valid Accounts | 100145 |
| T1078.003 | Local Accounts | 100175 |
| T1021.001 | Remote Desktop Protocol | 100160, 100165, 100170, 100175, 100180, 100190 |
| T1046 | Network Service Discovery | 100185 |
| T1071.004 | DNS | 100195, 100200 |

---

# Project Structure

```text
soc-blue-team-homelab/
|
+-- README.md
|
+-- cases/
|   +-- case-100130-discovery.txt
|   +-- case-100140-password-guessing.txt
|   +-- case-100150-success-after-password-guessing.txt
|   +-- case-100155-account-lockout-after-password-guessing.txt
|   +-- case-100175-rdp-success-after-password-guessing.txt
|   +-- case-100180-suricata-rdp.txt
|   +-- case-100185-suricata-port-scan.txt
|   +-- case-100190-zeek-rdp-connection.txt
|   +-- case-100195-zeek-dns-query.txt
|   +-- case-100200-zeek-dns-beacon-like.txt
|
+-- docs/
|   +-- process-tree-investigation.md
|   +-- windows-authentication-monitoring.md
|   +-- suricata-network-monitoring.md
|   +-- zeek-network-monitoring.md
|
+-- scripts/
|   +-- process-tree.sh
|
+-- suricata/
|   +-- rules/
|       +-- local.rules
|
+-- zeek/
|   +-- config/
|       +-- node.cfg
|       +-- networks.cfg
|       +-- local.zeek
|
+-- wazuh/
    +-- rules/
        +-- local_rules.xml
```

---

# Current Detection Flow

O laboratório atualmente combina telemetria de endpoint, autenticação e duas fontes complementares de monitoramento de rede:

```text
Endpoint Telemetry
Sysmon / PowerShell
        |
        +-------------------+
                            |
Windows Authentication     |
4624 / 4625 / 4740 / RDP   |
        |                   |
        +-------------------+
                            |
Suricata                    |
IDS / EVE JSON              |
        |                   |
        +-------------------+
                            |
Zeek                        |
conn.log / dns.log          |
        |                   |
        +-------------------+
                            |
                            v
                          Wazuh
                            |
                            v
                 Custom Detection Rules
                            |
                            v
                     Correlated Alerts
                            |
                            v
                      SOC Investigation
```

---

# Troubleshooting Realizado

Alguns problemas resolvidos durante a construção do laboratório:

## Wazuh Agent

Foi necessário validar:

```text
agent registration
manager connectivity
Windows service
event channel collection
```

## Sysmon

Foi ajustada a configuração para equilibrar:

```text
visibility
vs.
event volume
```

## RDP

Foi identificado que:

```text
Windows 10 Home
```

não funciona como servidor RDP nativo.

O Windows Server 2022 foi utilizado como alvo RDP.

Também foi identificado que falhas RDP com NLA podem aparecer como:

```text
4625 Logon Type 3
```

e, portanto, precisam de contexto adicional antes de serem classificadas como RDP.

## Wazuh Logtest

Durante troubleshooting do Event 261, foi observado que reproduzir um `full_log` via `wazuh-logtest` pode não representar exatamente o pipeline real de um evento Windows EventChannel.

A validação final foi realizada em produção no próprio laboratório.

## VirtualBox Network Visibility

Inicialmente, a interface de gerenciamento `enp0s8` não recebia tráfego unicast entre as outras VMs.

Foi criada uma terceira interface:

```text
enp0s9
```

com:

```text
Host-Only Network
Promiscuous Mode: Allow All
```

Após o ajuste, o sensor passou a observar tráfego bidirecional entre:

```text
192.168.100.20
and
192.168.100.30
```

## Suricata Rule Tuning

A regra de port scan inicialmente gerava alertas excessivos após o threshold.

A mudança de:

```text
detection_filter
```

para:

```text
threshold:type threshold
```

reduziu alertas repetitivos.

---


## Zeek Shutdown Investigation

Após um reboot, o Zeek apareceu como:

```text
crashed
```

O diagnóstico mostrou:

```text
received termination signal
TERMINATED [atexit]
```

Não houve evidência de:

```text
OOM
segfault
core dump
```

O journal confirmou desligamento completo do sistema no mesmo timestamp, incluindo SSH, Suricata e todos os componentes Wazuh.

Foi criado um serviço systemd para garantir inicialização automática do Zeek após boot.

## Zeek WebSocket Warning

O ZeekControl apresentou aviso relacionado ao módulo Python `websockets`.

Esse aviso afeta comandos auxiliares do ZeekControl, mas não impediu:

```text
packet capture
conn.log
dns.log
JSON logging
Wazuh ingestion
custom detections
```

---

# Status

## Endpoint Visibility

```text
Wazuh Agent                   VALIDATED
Sysmon                        VALIDATED
Process Creation              VALIDATED
Network Connect               VALIDATED
DNS Query                     VALIDATED
PowerShell 4104               VALIDATED
```

## Authentication Visibility

```text
4625 Failed Logon             VALIDATED
4624 Successful Logon         VALIDATED
4740 Account Lockout          VALIDATED
Password Guessing             VALIDATED
Success After Guessing        VALIDATED
Lockout After Guessing        VALIDATED
```

## RDP Visibility

```text
RDP Listener Event 261        VALIDATED
Failed RDP correlation        VALIDATED
Repeated RDP failures         VALIDATED
Successful RDP Logon          VALIDATED
Success After RDP Guessing    VALIDATED
```

## Network Visibility

```text
Passive packet capture        VALIDATED
Promiscuous visibility        VALIDATED
Suricata AF_PACKET            VALIDATED
Suricata EVE JSON             VALIDATED
Wazuh Suricata ingestion      VALIDATED
Suricata RDP alert            VALIDATED
TCP port scan alert           VALIDATED
Zeek standalone               VALIDATED
Zeek JSON logging             VALIDATED
Zeek capture loss 0.00%       VALIDATED
Zeek conn.log                 VALIDATED
Zeek dns.log                  VALIDATED
Zeek RDP metadata             VALIDATED
Wazuh Zeek ingestion          VALIDATED
Zeek DNS query alert          VALIDATED
DNS beacon-like correlation   VALIDATED
```

---

# Current Detection Layers

```text
Windows Endpoint Telemetry
          +
Sysmon
          +
PowerShell Monitoring
          +
Windows Authentication
          +
RDP Authentication Correlation
          +
Suricata IDS Telemetry
          +
Zeek Network Metadata
          |
          v
        Wazuh
          |
          v
Detection Engineering
          |
          v
SOC Investigation
```

---

# Next Steps

Próximas evoluções planejadas para o laboratório:

1. correlacionar telemetria Suricata + Zeek + endpoint em cenários únicos;
2. expandir detecções de DNS, reconnaissance e lateral movement;
3. analisar e documentar regras ET Open relevantes;
4. criar hunting queries usando metadata Zeek;
5. evoluir dashboards e visualizações no Wazuh;
6. adicionar novos protocolos e cenários de rede;
7. adicionar mais automação para investigação;
8. continuar documentando cada cenário com evidência técnica reproduzível.

---

# Disclaimer

Este projeto existe exclusivamente para:

- estudo;
- treinamento defensivo;
- análise de logs;
- Detection Engineering;
- Threat Hunting;
- DFIR;
- Cybersecurity.

Os testes foram executados em um laboratório isolado e autorizado.

Nenhum dos procedimentos descritos deve ser utilizado contra sistemas, contas ou redes sem autorização explícita.
