# Windows Authentication Monitoring

## Objetivo

Implementar e validar detecções de falhas e sucessos de autenticação no Windows utilizando:

- Windows Security Event Log
- Wazuh
- Regras nativas
- Regras customizadas
- Correlação temporal
- MITRE ATT&CK

O objetivo principal foi diferenciar:

1. falha individual de logon;
2. múltiplas falhas originadas do mesmo IP;
3. password guessing direcionado contra a mesma conta;
4. logon bem-sucedido após uma sequência de falhas;
5. bloqueio de conta após password guessing.

---

# Event ID 4625 - Failed Logon

O principal evento utilizado para falhas de autenticação foi:

```text
Event ID 4625
An account failed to log on
```

Campos relevantes:

```text
targetUserName
targetDomainName
logonType
ipAddress
status
subStatus
```

---

## Teste inicial de falha de autenticação

Foi gerada uma tentativa de autenticação inválida via:

```powershell
net use \\127.0.0.1\IPC$ /user:WIN10\SOC-LAB-INVALID "WrongPassword-SOC-LAB"
```

O Windows registrou:

```text
Event ID:    4625
Logon Type:  3
Source IP:   127.0.0.1
Status:      0xC000006D
SubStatus:   0xC0000064
```

Interpretação:

```text
0xC000006D = Logon failure
0xC0000064 = User does not exist
```

No Wazuh, o evento foi classificado pela regra nativa:

```text
Rule ID:      60122
Level:        5
Description:  Logon Failure - Unknown user or bad password
```

---

# Rule 60204 - Multiple Windows Logon Failures

O Wazuh possui uma regra nativa de correlação para múltiplas falhas:

```xml
<rule id="60204" level="10" frequency="$MS_FREQ" timeframe="240">
  <if_matched_group>authentication_failed</if_matched_group>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>Multiple Windows Logon Failures</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

A variável:

```xml
<var name="MS_FREQ">8</var>
```

faz com que a regra seja acionada após:

```text
8 falhas
mesmo IP
até 240 segundos
```

MITRE ATT&CK:

```text
T1110 - Brute Force
Tactic: Credential Access
```

---

## Validação da Rule 60204

Foram geradas 8 tentativas contra usuários diferentes.

Resultado:

```text
Rule ID:      60204
Level:        10
Description:  Multiple Windows Logon Failures
MITRE:        T1110
Technique:    Brute Force
```

---

# Password Guessing Detection

## Rule 100135

Foi criada uma regra intermediária para identificar especificamente senha incorreta em uma conta existente.

```xml
<rule id="100135" level="6">
  <if_sid>60122</if_sid>
  <field name="win.eventdata.subStatus" type="pcre2">(?i)^0xc000006a$</field>
  <description>SOC LAB: Windows logon failure caused by incorrect password for an existing account.</description>
  <group>authentication_failed,password_failure,soc_lab,</group>
</rule>
```

O código:

```text
0xC000006A
```

representa senha incorreta para uma conta existente.

---

## Rule 100140

```xml
<rule id="100140" level="12" frequency="5" timeframe="60">
  <if_matched_sid>100135</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>SOC LAB: Repeated password failures against the same Windows account from the same source IP.</description>
  <group>authentication_failed,brute_force,password_guessing,soc_lab,</group>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

Critérios:

```text
5 falhas
mesmo usuário
mesmo IP
até 60 segundos
senha incorreta
conta existente
```

MITRE ATT&CK:

```text
T1110.001 - Password Guessing
Tactic: Credential Access
```

---

## Validação da Rule 100140

Foram realizadas cinco tentativas de senha incorreta contra:

```text
WIN10\vboxuser
```

Resultado:

```text
1ª falha -> Rule 100135
2ª falha -> Rule 100135
3ª falha -> Rule 100135
4ª falha -> Rule 100135
5ª falha -> Rule 100140
```

Alerta final:

```text
Rule ID:      100140
Level:        12
User:         vboxuser
Source IP:    127.0.0.1
Technique:    Password Guessing
MITRE:        T1110.001
```

---

# Successful Logon Monitoring

## Event ID 4624

Foi validado o evento:

```text
Event ID 4624
An account was successfully logged on
```

Os principais Logon Types analisados foram:

```text
Type 2  - Interactive
Type 3  - Network
Type 10 - RemoteInteractive / RDP
```

Nesta etapa foram validados diretamente os Types 2 e 3.

---

## Logon Type 2 - Interactive

Resultado:

```text
User:        vboxuser
Domain:      WIN10
Logon Type:  2
Source IP:   ::1
AuthPackage: Negotiate
```

No Wazuh:

```text
Rule ID:      60118
Level:        3
Description:  Windows Workstation Logon Success
```

---

## Logon Type 3 - Network

Foi gerado um logon de rede utilizando:

```powershell
net use \\127.0.0.1\IPC$ /user:WIN10\vboxuser *
```

Resultado:

```text
User:        vboxuser
Domain:      WIN10
Logon Type:  3
Source IP:   127.0.0.1
Workstation: WIN10
AuthPackage: NTLM
```

No Wazuh:

```text
Rule ID:      60106
Level:        3
Description:  Windows Logon Success
```

MITRE:

```text
T1078 - Valid Accounts
```

---

# Rule 100145 - Successful Network Logon

Foi criada uma regra intermediária para identificar logons de rede bem-sucedidos:

```xml
<rule id="100145" level="4">
  <if_sid>60106</if_sid>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <description>SOC LAB: Successful Windows network logon.</description>
  <group>authentication_success,network_logon,soc_lab,</group>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
```

Critérios:

```text
Event ID 4624
Logon Type 3
Successful Network Logon
```

---

# Rule 100150 - Successful Logon After Password Guessing

A Rule 100150 correlaciona um logon bem-sucedido com uma ocorrência anterior da Rule 100140.

```xml
<rule id="100150" level="14" timeframe="300">
  <if_sid>100145</if_sid>
  <if_matched_sid>100140</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>SOC LAB: Successful Windows network logon after repeated password guessing attempts.</description>
  <group>authentication_success,possible_account_compromise,password_guessing,soc_lab,</group>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
```

Lógica:

```text
5 falhas
mesmo usuário
mesmo IP
até 60 segundos
↓
100140
Password Guessing
↓
4624 Type 3
mesmo usuário
mesmo IP
até 300 segundos
↓
100150
Successful Logon After Password Guessing
```

Resultado validado:

```text
Rule ID:      100150
Level:        14
User:         vboxuser
Source IP:    127.0.0.1
Logon Type:   3
MITRE:        T1078
Technique:    Valid Accounts
```

---

# Event ID 4740 - Account Lockout

Após a etapa de falhas e sucessos de autenticação, foi validado o bloqueio de conta do Windows.

Política local utilizada:

```text
Lockout threshold:             10
Lockout duration:              10 minutes
Lockout observation window:    10 minutes
Computer role:                 WORKSTATION
```

Para evitar bloquear a conta principal do laboratório, foi criada uma conta dedicada:

```text
SOC-LAB-LOCKOUT
```

Após atingir o limite configurado de tentativas inválidas, o Windows gerou:

```text
Event ID:      4740
User:          SOC-LAB-LOCKOUT
Description:   A user account was locked out
```

---

# Rule 60115 - User Account Locked Out

O Wazuh possui uma regra nativa para Event ID 4740.

Resultado observado:

```text
Rule ID:      60115
Level:        9
Description:  User account locked out (multiple login errors)
User:         SOC-LAB-LOCKOUT
```

Grupos:

```text
windows
windows_security
authentication_failures
```

MITRE ATT&CK:

```text
T1110 - Brute Force
T1531 - Account Access Removal
```

Táticas:

```text
Credential Access
Impact
```

Campos disponíveis no evento incluíram:

```text
targetUserName
targetDomainName
targetSid
subjectUserSid
subjectUserName
subjectDomainName
subjectLogonId
```

Neste cenário, o Event ID 4740 não apresentou `ipAddress`.

Por isso, qualquer correlação envolvendo o bloqueio deveria utilizar o usuário afetado como principal chave de contexto.

---

# Rule 100155 - Account Lockout After Password Guessing

Foi criada uma regra customizada para correlacionar:

```text
Password Guessing
↓
Account Lockout
```

Regra:

```xml
<rule id="100155" level="13" timeframe="300">
  <if_sid>60115</if_sid>
  <if_matched_sid>100140</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>

  <description>SOC LAB: Windows account locked out after repeated password guessing attempts.</description>

  <group>authentication_failed,account_lockout,password_guessing,soc_lab,</group>

  <mitre>
    <id>T1110.001</id>
    <id>T1531</id>
  </mitre>
</rule>
```

Critérios:

```text
Rule 100140 previamente acionada
+
Rule 60115 no evento atual
+
mesmo targetUserName
+
janela de 300 segundos
```

---

## Validação da Rule 100155

Durante o teste, a sequência observada foi:

```text
100135
100135
100135
100135
100140
100135
100135
100135
100135
60115
100140
```

A primeira detecção de Password Guessing ocorreu antes do bloqueio.

Exemplo da sequência temporal:

```text
14:53:21 -> 100140 | Password Guessing
14:53:41 -> 60115  | Account Locked Out
```

A diferença foi de aproximadamente 20 segundos, dentro da janela de 300 segundos.

Após a criação da Rule 100155, um novo teste controlado gerou:

```text
Rule ID:      100155
Level:        13
Description:  SOC LAB: Windows account locked out after repeated password guessing attempts.
User:         SOC-LAB-LOCKOUT
```

MITRE:

```text
T1110.001 - Password Guessing
T1531     - Account Access Removal
```

Táticas:

```text
Credential Access
Impact
```

---

# Account Lockout Detection Chain

```text
4625
↓
60122
↓
100135
Wrong password for existing account
↓
100140
Password Guessing
T1110.001
↓
4740
↓
60115
Account Locked Out
T1110 + T1531
↓
100155
Account Lockout After Password Guessing
T1110.001 + T1531
```

---

# SOC Interpretation

Um bloqueio de conta isolado pode ocorrer por diferentes motivos, incluindo:

- erro legítimo do usuário;
- credenciais antigas;
- serviços configurados com senha desatualizada;
- tarefas agendadas;
- aplicações com credenciais armazenadas;
- ataques automatizados.

Porém, quando o bloqueio ocorre logo após uma detecção de Password Guessing contra a mesma conta, o contexto se torna mais relevante.

A Rule 100155 agrega essa informação e permite que o analista veja que:

```text
houve tentativa repetida de descoberta de senha
↓
a mesma conta atingiu o limite de bloqueio
```

Em produção, esse alerta deve motivar investigação sobre:

- origem das falhas;
- conta afetada;
- volume e frequência das tentativas;
- existência de outras contas atacadas;
- autenticações bem-sucedidas próximas ao evento;
- atividade do endpoint;
- processos e conexões relacionadas;
- possível comprometimento;
- possibilidade de indisponibilidade provocada intencionalmente.

---

# SOC Triage - Rule 100155

Como o cenário foi realizado de maneira controlada:

```text
Classification: True Positive
Disposition: Close - Authorized Security Test
```

O comportamento detectado ocorreu de fato, portanto a detecção foi classificada como True Positive.

Entretanto, não houve incidente malicioso, pois as tentativas foram executadas intencionalmente no SOC Home Lab.

Case:

```text
cases/case-100155-account-lockout-after-password-guessing.txt
```

---

# Authentication Detection Architecture

```text
Windows Security Event Log
        |
        +---------------- Event ID 4625 ----------------+
        |                                               |
        v                                               v
60122                                           authentication_failed
        |                                               |
        v                                               v
100135                                          60204 | Level 10
Wrong password                                  Multiple Logon Failures
existing account                                T1110
        |
        v
100140 | Level 12
Password Guessing
T1110.001
        |
        +-----------------------+
        |                       |
        |                       |
        v                       v
4624 Type 3                  4740
        |                       |
        v                       v
60106                       60115
        |                  Account Locked Out
        v                  T1110 + T1531
100145                        |
        |                     v
        v                   100155 | Level 13
100150 | Level 14           Password Guessing
Successful Logon            + Account Lockout
After Password Guessing     T1110.001 + T1531
T1078
```

---

# Cases

Os principais casos de autenticação documentados são:

```text
cases/case-100140-password-guessing.txt
cases/case-100150-success-after-password-guessing.txt
cases/case-100155-account-lockout-after-password-guessing.txt
```

---

# MITRE ATT&CK Coverage

| Technique | Description | Context |
|---|---|---|
| T1110 | Brute Force | Multiple Windows logon failures |
| T1110.001 | Password Guessing | Repeated wrong passwords against same account |
| T1078 | Valid Accounts | Successful logon after password guessing |
| T1531 | Account Access Removal | Account lockout |

---

# Resultados

A etapa de Windows Authentication Monitoring demonstrou:

- análise de Event ID 4625;
- análise de Event ID 4624;
- análise de Event ID 4740;
- diferenciação entre usuário inexistente e senha incorreta;
- diferenciação de Logon Type 2 e 3;
- detecção de múltiplas falhas;
- detecção de Password Guessing;
- detecção de logon de rede bem-sucedido;
- correlação entre falhas e sucesso;
- detecção de possível comprometimento de conta;
- detecção de Account Lockout;
- correlação entre Password Guessing e Account Lockout;
- uso de `if_sid`;
- uso de `if_matched_sid`;
- uso de `same_field`;
- correlação temporal;
- uso de regras nativas e customizadas;
- troubleshooting de regras Wazuh;
- interpretação de campos do Windows Security Event Log;
- mapeamento MITRE ATT&CK;
- triagem SOC.

---

---

# RDP Authentication Monitoring

## Objetivo

A etapa RDP foi concluída com a implementação e validação de uma cadeia de detecção para autenticação remota em Windows Server 2022.

Fluxo validado:

```text
Event ID 261
RDP listener connection
        ↓
Rule 100160
        ↓
Event ID 4625
wrong password
        ↓
Rule 100165
Failed RDP authentication
        ↓
repeated failures
same user + same IP
        ↓
Rule 100170
RDP Password Guessing
Level 12
        ↓
Event ID 4624
Logon Type 10
        ↓
Rule 100175
Successful RDP Logon After Password Guessing
Level 14
```

## Ambiente

```text
Origem: Windows 10
Source IP: 192.168.100.20

Destino: Windows Server 2022
Destination IP: 192.168.100.30

Wazuh Agent: WINSERVER2022
Agent ID: 002

Conta de teste: SOC-RDP-TEST
```

## Event ID 261

Canal:

```text
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
```

Evento:

```text
Event ID: 261
Message: Listener RDP-Tcp received a connection
```

Durante o troubleshooting foi identificado que esse evento possui:

```text
severityValue = INFORMATION
```

e segue a árvore:

```text
60000
↓
60009
↓
100160
```

## Rule 100160

```xml
<rule id="100160" level="5">
  <if_sid>60009</if_sid>
  <field name="win.system.providerName" type="pcre2">^Microsoft-Windows-TerminalServices-RemoteConnectionManager$</field>
  <field name="win.system.eventID">^261$</field>
  <description>SOC LAB: RDP connection received by Windows Remote Desktop listener.</description>
  <group>rdp,remote_access,soc_lab,</group>
  <mitre>
    <id>T1021.001</id>
  </mitre>
</rule>
```

## Falha RDP com NLA

Durante uma tentativa RDP com senha incorreta:

```text
Event ID: 4625
Logon Type: 3
Authentication Package: NTLM
Status: 0xC000006D
SubStatus: 0xC000006A
Source IP: 192.168.100.20
```

O laboratório confirmou que RDP com NLA pode gerar `4625 / Logon Type 3`, portanto esse evento isolado não foi considerado suficiente para classificar a falha como RDP.

## Rule 100165

```xml
<rule id="100165" level="7" timeframe="10">
  <if_sid>100135</if_sid>
  <if_matched_sid>100160</if_matched_sid>
  <description>SOC LAB: Failed Windows authentication associated with a recent RDP connection.</description>
  <group>authentication_failed,rdp,remote_access,soc_lab,</group>
  <mitre>
    <id>T1021.001</id>
    <id>T1110.001</id>
  </mitre>
</rule>
```

## Rule 100170

```xml
<rule id="100170" level="12" frequency="4" timeframe="60">
  <if_matched_sid>100165</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>SOC LAB: Repeated RDP authentication failures against the same Windows account from the same source IP.</description>
  <group>authentication_failed,rdp,brute_force,password_guessing,remote_access,soc_lab,</group>
  <mitre>
    <id>T1021.001</id>
    <id>T1110.001</id>
  </mitre>
</rule>
```

Validação:

```text
2026-08-27T05:49:28.245+0000
Rule: 100170
Level: 12
User: SOC-RDP-TEST
Source IP: 192.168.100.20
Logon Type: 3
```

## Successful RDP Logon

O login válido foi detectado pela regra nativa:

```text
Rule ID: 92653
Event ID: 4624
Logon Type: 10
```

## Rule 100175

```xml
<rule id="100175" level="14" timeframe="300">
  <if_sid>92653</if_sid>
  <if_matched_sid>100170</if_matched_sid>
  <same_field>win.eventdata.targetUserName</same_field>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>SOC LAB: Successful RDP logon after repeated password guessing from the same source IP.</description>
  <group>authentication_success,rdp,password_guessing,valid_accounts,remote_access,soc_lab,</group>
  <mitre>
    <id>T1021.001</id>
    <id>T1078.003</id>
  </mitre>
</rule>
```

Validação final:

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
6 segundos
```

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
T1110.001 - Password Guessing
T1078.003 - Local Accounts
```

Classificação:

```text
True Positive
Authorized Security Test
```

## Troubleshooting

O Event ID 261 chegava ao manager, mas inicialmente não acionava a regra customizada. A análise mostrou que eventos informacionais desse EventChannel passavam pela Rule 60009; por isso a Rule 100160 foi criada como filha dela.

Durante o replay de eventos de `archives.json` pelo `wazuh-logtest`, o `full_log` foi decodificado como `json`, enquanto em produção os eventos eram processados como `windows_eventchannel`. Por isso a validação definitiva foi feita com eventos reais enviados pelo Wazuh Agent.

O `logall_json` foi habilitado temporariamente durante o troubleshooting e depois restaurado para:

```xml
<logall>no</logall>
<logall_json>no</logall_json>
```

Validação final:

```text
wazuh-analysisd -t: 0
wazuh-manager: active
```

## Evidência

```text
cases/case-100175-rdp-success-after-password-guessing.txt
```

## Resultado

A etapa RDP foi concluída com sucesso:

```text
RDP listener monitoring
Failed RDP authentication
RDP Password Guessing
Successful RDP Logon
Successful RDP Logon After Password Guessing
MITRE ATT&CK correlation
True Positive classification
```
