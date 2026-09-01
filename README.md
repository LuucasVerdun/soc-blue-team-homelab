# SOC Blue Team Home Lab

Laboratório prático de **Security Operations Center (SOC)** focado em Blue Team, monitoramento, detecção, correlação e investigação de eventos de segurança.

O ambiente foi construído para reproduzir fluxos reais de um SOC: coleta de telemetria de endpoint, autenticação Windows, análise de processos, correlação temporal, monitoramento de RDP, Network IDS com Suricata, Network Security Monitoring com Zeek e correlação multi-source no Wazuh.

> Todos os testes descritos neste repositório foram executados em ambiente de laboratório próprio, controlado e autorizado.

---

## Objetivos

Este projeto tem como objetivos:

- desenvolver experiência prática em operações de SOC;
- compreender geração, coleta, normalização e análise de logs;
- trabalhar com telemetria de endpoint e de rede;
- criar, testar e ajustar regras de detecção;
- correlacionar múltiplos eventos para identificar comportamento suspeito;
- diferenciar eventos isolados de sequências com maior confiança analítica;
- mapear detecções para MITRE ATT&CK;
- praticar triagem, investigação e documentação de alertas;
- reduzir falsos positivos e alert fatigue por meio de tuning;
- construir evidências técnicas reproduzíveis;
- evoluir de alertas individuais para investigação multi-source.

---

# Arquitetura do Laboratório

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
                            |
                            v
                      SOC Investigation
```

---

## Redes utilizadas

```text
NAT
10.0.2.0/24

Host-Only
192.168.100.0/24
```

A rede NAT fornece conectividade externa às VMs quando necessário.

A rede Host-Only é utilizada para comunicação, monitoramento e simulações internas entre os sistemas do laboratório.

---

# Ambiente

## Host

```text
Operating System: Windows 11
Virtualization:   VirtualBox 7.x
RAM:              24 GB
CPU:              Intel Core i5 13th Gen
```

---

## SOC01

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
- Bash
- jq
- systemd
- ferramentas Linux de análise e troubleshooting

Dashboard:

```text
https://192.168.100.10
```

---

## Windows 10 Endpoint

```text
Hostname:  WIN10
Host-Only: 192.168.100.20
NAT:       10.0.2.3
```

Componentes:

- Wazuh Agent
- Sysmon
- PowerShell logging
- Windows Security Event Log

Função no laboratório:

- geração controlada de telemetria;
- execução de comandos de discovery;
- origem dos testes de autenticação;
- origem dos testes RDP;
- origem dos testes de rede e DNS.

---

## Windows Server 2022

```text
Hostname:  WINSERVER2022
Host-Only: 192.168.100.30
RDP:       TCP/3389
Wazuh Agent ID: 002
```

Uso no laboratório:

- autenticação Windows;
- Remote Desktop Protocol;
- falhas de login;
- password guessing;
- account lockout;
- successful RDP logon;
- alvo de reconhecimento de rede;
- correlação de eventos de endpoint e rede.

---

# Componentes

| Componente | Função |
|---|---|
| Wazuh | SIEM/XDR, análise, correlação e alertas |
| Wazuh Agent | Coleta de eventos nos endpoints Windows |
| Sysmon | Telemetria detalhada de endpoint |
| PowerShell Logging | Visibilidade de Script Block e execução |
| Windows Event Logs | Autenticação, segurança e RDP |
| Suricata | Network IDS e inspeção de tráfego |
| EVE JSON | Telemetria estruturada do Suricata |
| Zeek | Network Security Monitoring e metadata |
| conn.log | Metadata de conexões observadas pelo Zeek |
| dns.log | Metadata de DNS observada pelo Zeek |
| MITRE ATT&CK | Classificação das técnicas observadas |
| VirtualBox | Virtualização e segmentação do laboratório |
| Bash / jq | Consulta, filtragem e investigação |
| Git / GitHub | Versionamento e documentação |

---

# Endpoint Monitoring

## Sysmon + Wazuh

O Sysmon foi instalado no Windows 10 e integrado ao Wazuh.

Canal monitorado:

```text
Microsoft-Windows-Sysmon/Operational
```

A configuração prioriza eventos úteis para investigação em SOC, incluindo:

```text
Process Create
Network Connect
File Create
DNS Query
```

Eventos de Registry Event foram reduzidos durante a fase inicial para controlar volume e ruído.

---

## Process Creation

A telemetria de criação de processos permite investigar:

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

Essa visibilidade foi utilizada para detectar cadeias envolvendo PowerShell, `cmd.exe` e comandos de discovery.

---

# PowerShell Monitoring

O PowerShell Script Block Logging foi habilitado e coletado pelo Wazuh.

Evento principal:

```text
Event ID 4104
Microsoft-Windows-PowerShell/Operational
```

Foi utilizado um marcador controlado para validar a ingestão.

---

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

Classificação:

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

Foi criada uma ferramenta Bash para investigação de árvores de processos em alertas Wazuh.

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

Utilizada para identificar múltiplas falhas de autenticação Windows.

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

A Rule `100135` utiliza:

```text
SubStatus 0xC000006A
```

Lógica:

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

O Windows foi configurado para bloquear uma conta após repetidas falhas de autenticação.

Política utilizada durante os testes:

```text
Account lockout threshold: 10 attempts
Lockout duration:          10 minutes
Observation window:        10 minutes
```

O Event ID `4740` representa:

```text
A user account was locked out
```

---

## Rule 60115

Regra nativa observada:

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

Configuração:

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

Regra nativa Wazuh identificada:

```text
92653
```

---

## Rule 100175 - Successful RDP Logon After Password Guessing

Correlação:

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

Validação:

```text
2026-08-27T05:49:28.245+0000
Rule: 100170
Level: 12
User: SOC-RDP-TEST
Source IP: 192.168.100.20

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

---

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

Gerenciamento:

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

Ruleset:

```text
ET Open / suricata.rules
+
local.rules
```

---

## RDP Protocol Visibility

O Suricata identificou tráfego RDP entre:

```text
192.168.100.20 -> 192.168.100.30:3389
```

Eventos observados:

```text
event_type: rdp
proto:      TCP
```

Isso confirmou que a interface passiva consegue observar e interpretar tráfego east-west.

---

# Suricata Custom Rules

Arquivo:

```text
suricata/rules/local.rules
```

Regras:

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

`allowed` é esperado porque o Suricata opera como IDS passivo, não como IPS inline.

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

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
```

Pipeline:

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

Fluxo:

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

Após o limite ser atingido, pacotes adicionais continuavam gerando alertas.

A regra foi alterada para:

```text
threshold:type threshold,track by_src,count 10,seconds 10
```

Com 21 tentativas, o comportamento validado gerou alertas agrupados aproximadamente nos ports:

```text
29
39
```

Isso reduziu ruído e melhorou o controle de eventos enviados ao SIEM.

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
```

Evidência:

```text
cases/case-100185-suricata-port-scan.txt
```

Documentação:

```text
docs/suricata-network-monitoring.md
```

---

# Zeek Network Monitoring

A fase Zeek adicionou Network Security Monitoring orientado a metadata, complementando as assinaturas e alertas do Suricata.

---

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

---

## JSON Logging

Os logs do Zeek foram convertidos para JSON utilizando:

```text
@load policy/tuning/json-logs
```

Principais logs utilizados:

```text
conn.log
dns.log
notice.log
capture_loss.log
```

---

## Capture Validation

A captura foi validada com:

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

---

## Zeek Service Persistence

Após um reboot, `zeekctl status` mostrou inicialmente:

```text
crashed
```

A investigação encontrou:

```text
received termination signal
TERMINATED [atexit]
```

sem evidência de:

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

Foi criado um serviço systemd para iniciar o Zeek automaticamente.

Arquivo versionado:

```text
zeek/systemd/zeek.service
```

Estado operacional validado:

```text
zeek standalone localhost running
```

---

## Zeek WebSocket Warning

O `zeekctl` pode apresentar:

```text
UseWebSocket is set, but websockets non-functional
```

No estado atual do laboratório, isso afeta comandos auxiliares como:

```text
print
netstats
```

A captura, geração de logs e integração com o Wazuh continuam funcionais.

---

# Zeek → Wazuh Integration

Foi escolhida ingestão direta dos logs JSON nativos do Zeek.

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

são representados no evento Wazuh como:

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

A Rule `100190` representa visibilidade de conexão TCP/3389.

Ela **não comprova**, isoladamente, autenticação RDP bem-sucedida.

Evidência:

```text
cases/case-100190-zeek-rdp-connection.txt
```

---

## Rule 100195 - Controlled Suspicious DNS Query

Indicador controlado:

```text
soc-lab-beacon.example
```

Fluxo:

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

Uma consulta DNS isolada não comprova atividade de Command and Control.

Evidência:

```text
cases/case-100195-zeek-dns-query.txt
```

---

## Rule 100200 - DNS Beacon-Like Activity

A Rule `100200` correlaciona múltiplas ocorrências da `100195`.

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

A `100200` identifica um padrão **compatível com beaconing no cenário controlado**, não uma confirmação independente de C2 malicioso.

Evidência:

```text
cases/case-100200-zeek-dns-beacon-like.txt
```

Documentação:

```text
docs/zeek-network-monitoring.md
```

---

# Suricata + Zeek

As duas ferramentas exercem funções complementares.

```text
Suricata
    |
    +--> signatures / IDS detection
    +--> custom network alerts
    +--> eve.json

Zeek
    |
    +--> connection metadata
    +--> DNS metadata
    +--> protocol visibility
    +--> behavioral context
```

Arquitetura:

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

# Multi-Source Correlation

Após validar Suricata e Zeek isoladamente, o laboratório evoluiu para correlação entre fontes diferentes.

O objetivo passou a ser:

```text
Network reconnaissance
+
Network session metadata
+
Windows authentication telemetry
        |
        v
Higher-confidence incident
```

---

## Rule 100205 - Suricata + Windows Correlation

A primeira correlação multi-source liga reconhecimento de rede a uma autenticação RDP bem-sucedida após password guessing.

Lógica:

```text
Suricata 100185
Port Scan
       |
       v
Windows 100170
Repeated RDP failures
       |
       v
Windows 4624 Type 10
Successful RDP logon
       |
       v
100205
```

Configuração principal:

```xml
<rule id="100205" level="15" timeframe="600">
  <if_sid>100175</if_sid>
  <if_matched_sid>100185</if_matched_sid>
  <global_frequency />

  <field name="win.eventdata.ipAddress">^192\.168\.100\.20$</field>

  <description>SOC LAB: Network reconnaissance followed by successful RDP access after password guessing.</description>

  <group>correlation,multi_source,suricata,windows,rdp,reconnaissance,lateral_movement,soc_lab,</group>

  <mitre>
    <id>T1046</id>
    <id>T1021.001</id>
    <id>T1078.003</id>
  </mitre>
</rule>
```

A opção:

```text
global_frequency
```

foi necessária porque os eventos envolvidos são processados por agentes diferentes:

```text
100185
Suricata
Agent 000
soc01

100175
Windows
Agent 002
WINSERVER2022
```

Validação:

```text
Rule:  100205
Level: 15
User:  Administrator
Source: 192.168.100.20
```

Descrição validada:

```text
SOC LAB: Network reconnaissance followed by successful RDP access after password guessing.
```

---

# Tri-Source RDP Correlation

A etapa seguinte adicionou o Zeek à cadeia anterior.

Objetivo:

```text
Suricata
+
Zeek
+
Windows Security Events
        |
        v
Wazuh tri-source correlation
```

---

## Rule 100210 - Tri-Source Correlation

Lógica:

```text
Suricata 100185
Network reconnaissance
        |
        v
Zeek 100190
TCP/3389 metadata
        |
        v
Windows 100170
Repeated RDP authentication failures
        |
        v
Successful RDP logon
        |
        v
100205
Suricata + Windows correlation
        |
        v
100210
TRI-SOURCE CORRELATION
LEVEL 15
```

Regra:

```xml
<rule id="100210" level="15" timeframe="300">
  <if_sid>100205</if_sid>
  <if_matched_sid>100190</if_matched_sid>

  <global_frequency />

  <field name="win.eventdata.ipAddress">^192\.168\.100\.20$</field>

  <description>SOC LAB: Tri-source correlation - Suricata reconnaissance, Zeek RDP network activity, and successful Windows RDP access after password guessing.</description>

  <group>correlation,multi_source,suricata,zeek,windows,rdp,reconnaissance,credential_access,lateral_movement,soc_lab,</group>

  <mitre>
    <id>T1046</id>
    <id>T1110.001</id>
    <id>T1021.001</id>
    <id>T1078.003</id>
  </mitre>
</rule>
```

---

## Final Validated Timeline

Teste final:

```text
Date: 2026-09-01
```

| Timestamp UTC | Rule | Source | Observation |
|---|---:|---|---|
| 02:51:57 | 100185 | Suricata | TCP port scan from 192.168.100.20 to 192.168.100.30 |
| 02:51:59 | 100185 | Suricata | Additional thresholded scan alert |
| 02:52:45 | 100190 | Zeek | TCP connection to 192.168.100.30:3389 |
| 02:52:48 | 100190 | Zeek | Additional RDP network metadata |
| 02:52:51 | 100170 | Windows/Wazuh | Repeated RDP authentication failures |
| 02:52:52 | 100190 | Zeek | Additional TCP/3389 metadata |
| 02:52:57 | 100190 | Zeek | Additional TCP/3389 metadata |
| 02:53:11 | 100190 | Zeek | Additional TCP/3389 metadata |
| 02:53:17 | 100210 | Wazuh | Tri-source correlated incident |

Resultado final:

```text
Rule:      100210
Level:     15
Agent:     WINSERVER2022
User:      Administrator
Source IP: 192.168.100.20
```

Descrição:

```text
SOC LAB: Tri-source correlation - Suricata reconnaissance, Zeek RDP network activity, and successful Windows RDP access after password guessing.
```

---

## Detection Engineering Interpretation

Cada fonte responde a uma pergunta diferente.

### Suricata

```text
Houve reconhecimento de rede antes da atividade RDP?
```

### Zeek

```text
O sensor de rede observou conexões TCP para o serviço RDP?
```

### Windows Security Events

```text
Houve falhas de autenticação?
Qual conta foi afetada?
Houve autenticação RDP bem-sucedida depois?
Qual foi o IP de origem?
```

### Wazuh

```text
Esses eventos fazem parte da mesma sequência temporal?
```

A combinação aumenta a confiança da investigação.

É importante distinguir os níveis de evidência:

```text
Port scan
!= compromise

TCP/3389 connection
!= successful RDP authentication

Repeated failed authentication
= password guessing pattern

4624 Logon Type 10
= endpoint-side evidence of successful RDP logon

All signals correlated
= higher-confidence incident
```

---

## Why Rule 100205 May Not Appear Separately

Na execução tri-source final, a Rule `100210` foi emitida como alerta final.

Cadeia:

```text
100175
  |
  v
100205
  |
  v
100210
```

O evento atual pode satisfazer a lógica intermediária da `100205` e, em seguida, corresponder à regra filha mais específica `100210`.

Portanto, a ausência de uma linha separada da `100205` no teste final não significa falha da correlação intermediária.

---

## Evidência Tri-Source

Arquivo:

```text
cases/case-100210-tri-source-rdp-correlation.txt
```

O arquivo contém nove registros JSON da janela final de teste.

Documentação detalhada:

```text
docs/tri-source-rdp-correlation.md
```

---

# Custom Detection Rules

Arquivo:

```text
wazuh/rules/local_rules.xml
```

| Rule | Level | Detection | MITRE |
|---|---:|---|---|
| 100100 | 10 | PowerShell Script Block marker | T1059.001 |
| 100110 | 8 | PowerShell spawning cmd.exe | T1059.003 |
| 100120 | 10 | whoami discovery | T1033, T1059.003 |
| 100130 | 12 | Multi-command discovery | T1033, T1016, T1087.001, T1059.003 |
| 100135 | 6 | Wrong password for existing account | Authentication |
| 100140 | 12 | Password guessing | T1110.001 |
| 100145 | 4 | Successful network logon | T1078 |
| 100150 | 14 | Successful logon after password guessing | T1078 |
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
| 100205 | 15 | Reconnaissance followed by successful RDP after guessing | T1046, T1021.001, T1078.003 |
| 100210 | 15 | Tri-source Suricata + Zeek + Windows correlation | T1046, T1110.001, T1021.001, T1078.003 |

---

# Detection Philosophy

O objetivo do laboratório não é apenas criar alertas.

A meta é transformar eventos técnicos isolados em contexto operacional.

Exemplo:

```text
Five failed logons
```

isoladamente podem representar:

- erro de usuário;
- senha desatualizada;
- serviço configurado incorretamente;
- tentativa de ataque.

Por outro lado:

```text
Network reconnaissance
        |
        v
Repeated RDP authentication failures
        |
        v
Successful RDP authentication
```

possui maior relevância analítica.

Com uma fonte adicional:

```text
Suricata reconnaissance
        +
Zeek RDP metadata
        +
Windows authentication events
        |
        v
Tri-source correlated alert
```

a investigação ganha confiança e contexto.

---

# SOC Triage

Durante uma investigação, os principais campos analisados incluem:

```text
timestamp
rule.id
rule.level
rule.description
agent.id
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
id.orig_h
id.orig_p
id.resp_h
id.resp_p
query
MITRE technique
```

Fluxo de triagem:

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
Assess confidence
  |
  v
Classify
```

Classificações utilizadas:

```text
True Positive
Authorized Security Test
```

---

# MITRE ATT&CK Coverage

| Technique | Description | Detection |
|---|---|---|
| T1059.001 | PowerShell | 100100 |
| T1059.003 | Windows Command Shell | 100110, 100120, 100130 |
| T1033 | System Owner/User Discovery | 100120, 100130 |
| T1016 | System Network Configuration Discovery | 100130 |
| T1087.001 | Local Account Discovery | 100130 |
| T1110 | Brute Force | 60204, 60115 |
| T1110.001 | Password Guessing | 100140, 100155, 100165, 100170, 100210 |
| T1531 | Account Access Removal | 100155 |
| T1078 | Valid Accounts | 100145, 100150 |
| T1078.003 | Local Accounts | 100175, 100205, 100210 |
| T1021.001 | Remote Desktop Protocol | 100160, 100165, 100170, 100175, 100180, 100190, 100205, 100210 |
| T1046 | Network Service Discovery | 100185, 100205, 100210 |
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
|   +-- case-100210-tri-source-rdp-correlation.txt
|
+-- docs/
|   +-- process-tree-investigation.md
|   +-- windows-authentication-monitoring.md
|   +-- suricata-network-monitoring.md
|   +-- zeek-network-monitoring.md
|   +-- tri-source-rdp-correlation.md
|
+-- evidence/
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
|   |   +-- node.cfg
|   |   +-- networks.cfg
|   |   +-- local.zeek
|   |
|   +-- systemd/
|       +-- zeek.service
|
+-- wazuh/
    +-- rules/
        +-- local_rules.xml
```

---

# Current Detection Flow

```text
Endpoint Telemetry
Sysmon / PowerShell
        |
        +----------------------+
                               |
Windows Authentication        |
4624 / 4625 / 4740 / RDP      |
        |                      |
        +----------------------+
                               |
Suricata                      |
IDS / EVE JSON                |
        |                      |
        +----------------------+
                               |
Zeek                           |
conn.log / dns.log             |
        |                      |
        +----------------------+
                               |
                               v
                             Wazuh
                               |
                               v
                    Custom Detection Rules
                               |
                  +------------+-------------+
                  |                          |
                  v                          v
           Single-source              Multi-source
             alerts                   correlations
                                             |
                                             v
                                       Rule 100205
                                             |
                                             v
                                       Rule 100210
                                             |
                                             v
                                      SOC Investigation
```

---

# Troubleshooting Realizado

Durante a construção do laboratório foram investigados e resolvidos diversos problemas.

---

## Wazuh Agent

Foram validados:

```text
agent registration
manager connectivity
Windows service
event channel collection
```

---

## Sysmon

A configuração foi ajustada para equilibrar:

```text
visibility
vs.
event volume
```

---

## RDP

Foi identificado que falhas RDP com NLA podem aparecer como:

```text
4625 Logon Type 3
```

e precisam de contexto adicional antes de serem classificadas como falhas RDP.

Também foi validado:

```text
4624 Logon Type 10
```

como evidência endpoint-side de successful RDP logon.

---

## Wazuh Logtest

Durante troubleshooting do Event 261, foi observado que reenviar um `full_log` pelo `wazuh-logtest` pode não representar exatamente o pipeline real de um evento Windows EventChannel.

A validação final foi realizada com eventos reais recebidos dos agentes.

---

## VirtualBox Network Visibility

Inicialmente, a interface de gerenciamento `enp0s8` não recebia tráfego unicast entre as outras VMs.

Foi criada:

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

---

## VirtualBox Host-Only Adapter Reset

Após atualização do VirtualBox, o adaptador Host-Only do host voltou para uma configuração padrão diferente da rede do laboratório.

Sintoma:

```text
host could no longer reach 192.168.100.10
```

A rede de gerenciamento foi restaurada para:

```text
192.168.100.1/24
```

permitindo novamente acesso ao `soc01`.

---

## Suricata Rule Tuning

A regra de port scan inicialmente gerava volume maior após o threshold.

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

Um estado `crashed` após reboot foi investigado.

Os logs mostraram que o processo recebeu sinal de término durante o shutdown completo do sistema.

Não houve evidência de:

```text
OOM
segmentation fault
core dump
```

O problema foi classificado como término normal durante shutdown, não crash interno.

---

## Cross-Agent Wazuh Correlation

A primeira tentativa da Rule `100205` não correlacionou:

```text
Suricata 100185
Agent 000 / soc01
```

com:

```text
Windows 100175
Agent 002 / WINSERVER2022
```

A correlação passou a funcionar após utilização de:

```xml
<global_frequency />
```

Isso permitiu correlação temporal entre eventos processados sob agentes diferentes.

---

# Status Atual

## Endpoint Visibility

```text
Wazuh Agent                   VALIDATED
Sysmon                        VALIDATED
Process Creation              VALIDATED
Network Connect               VALIDATED
DNS Query                     VALIDATED
PowerShell 4104               VALIDATED
Process Tree Investigation    VALIDATED
Discovery Detection           VALIDATED
```

---

## Authentication Visibility

```text
4625 Failed Logon             VALIDATED
4624 Successful Logon         VALIDATED
4740 Account Lockout          VALIDATED
Password Guessing             VALIDATED
Success After Guessing        VALIDATED
Lockout After Guessing        VALIDATED
```

---

## RDP Visibility

```text
RDP Listener Event 261        VALIDATED
Failed RDP correlation        VALIDATED
Repeated RDP failures         VALIDATED
Successful RDP Logon          VALIDATED
Success After RDP Guessing    VALIDATED
```

---

## Suricata Visibility

```text
Passive packet capture        VALIDATED
Promiscuous visibility        VALIDATED
AF_PACKET                     VALIDATED
RDP protocol visibility       VALIDATED
EVE JSON                      VALIDATED
Wazuh ingestion               VALIDATED
RDP custom alert              VALIDATED
TCP port scan alert           VALIDATED
```

---

## Zeek Visibility

```text
Standalone capture            VALIDATED
conn.log                      VALIDATED
dns.log                       VALIDATED
JSON logging                  VALIDATED
Wazuh ingestion               VALIDATED
RDP connection metadata       VALIDATED
Controlled DNS query          VALIDATED
DNS beacon-like correlation   VALIDATED
0.00% capture loss test       VALIDATED
systemd persistence           VALIDATED
```

---

## Multi-Source Correlation

```text
Suricata + Windows            VALIDATED
Rule 100205                   VALIDATED
Cross-agent correlation       VALIDATED

Suricata + Zeek + Windows     VALIDATED
Rule 100210                   VALIDATED
Level 15 tri-source alert     VALIDATED
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
Suricata Network IDS
          +
Zeek Network Security Monitoring
          |
          v
        Wazuh
          |
          v
Detection Engineering
          |
          v
Multi-Source Correlation
          |
          v
SOC Investigation
```

---

# Casos Documentados

```text
cases/case-100130-discovery.txt
cases/case-100140-password-guessing.txt
cases/case-100150-success-after-password-guessing.txt
cases/case-100155-account-lockout-after-password-guessing.txt
cases/case-100175-rdp-success-after-password-guessing.txt
cases/case-100180-suricata-rdp.txt
cases/case-100185-suricata-port-scan.txt
cases/case-100190-zeek-rdp-connection.txt
cases/case-100195-zeek-dns-query.txt
cases/case-100200-zeek-dns-beacon-like.txt
cases/case-100210-tri-source-rdp-correlation.txt
```

---

# Documentação Técnica

```text
docs/process-tree-investigation.md
docs/windows-authentication-monitoring.md
docs/suricata-network-monitoring.md
docs/zeek-network-monitoring.md
docs/tri-source-rdp-correlation.md
```

---

# Próximos Passos

Com a correlação tri-source validada, as próximas evoluções planejadas são:

1. criar hunting queries no Wazuh para reconstrução de timelines;
2. evoluir dashboards para separar endpoint, authentication e network telemetry;
3. expandir detecções Suricata e analisar assinaturas ET Open relevantes;
4. criar novos casos de DNS e network behavior;
5. adicionar cenários de lateral movement além de RDP;
6. criar detecções de persistence e privilege escalation;
7. ampliar investigação com Sysmon após successful remote access;
8. desenvolver novas automações para triagem;
9. avaliar integração adicional com Splunk;
10. documentar cada novo cenário com evidência reproduzível.

---

# Repository

```text
https://github.com/LuucasVerdun/soc-blue-team-homelab
```

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

Todos os testes foram executados em ambiente isolado e autorizado.

Nenhum dos procedimentos descritos deve ser utilizado contra sistemas, contas ou redes sem autorização explícita.
