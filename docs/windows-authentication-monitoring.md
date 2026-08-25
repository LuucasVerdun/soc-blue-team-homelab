# Windows Authentication Monitoring

## Objetivo

Implementar e validar detecções de falhas e sucessos de autenticação no Windows utilizando:

- Windows Security Event Log
- Wazuh
- Regras nativas
- Regras customizadas
- MITRE ATT&CK

O objetivo principal foi diferenciar:

1. falha individual de logon;
2. múltiplas falhas originadas do mesmo IP;
3. password guessing direcionado contra a mesma conta;
4. logon bem-sucedido após uma sequência de falhas de senha.

---

## Evento 4625 - Failed Logon

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

## Regra nativa 60204

O Wazuh possui uma regra de correlação para múltiplas falhas:

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

Foram geradas 8 tentativas contra usuários diferentes:

```text
SOC-SPRAY2-01
SOC-SPRAY2-02
SOC-SPRAY2-03
SOC-SPRAY2-04
SOC-SPRAY2-05
SOC-SPRAY2-06
SOC-SPRAY2-07
SOC-SPRAY2-08
```

Todas partiram de:

```text
127.0.0.1
```

Resultado:

```text
Rule:        60204
Level:       10
Description: Multiple Windows Logon Failures
MITRE:       T1110
Technique:   Brute Force
```

---

## Regra customizada para Password Guessing

### Rule 100135

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

Foram realizadas 5 tentativas de senha incorreta contra:

```text
WIN10\vboxuser
```

O Windows registrou:

```text
Status:     0xC000006D
SubStatus:  0xC000006A
```

No Wazuh:

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

## Problema encontrado durante a implementação

Inicialmente, a Rule 100140 fazia correlação diretamente sobre:

```xml
<if_matched_sid>60122</if_matched_sid>
```

Durante os testes, foi observado que a presença dessa regra interferia no disparo da regra nativa 60204.

Com a Rule 100140 ativa:

```text
8 falhas
mesmo IP
usuários diferentes
-> 60204 não disparou
```

Com a Rule 100140 temporariamente desabilitada:

```text
8 falhas
mesmo IP
usuários diferentes
-> 60204 disparou
```

A arquitetura foi então alterada para utilizar uma regra intermediária:

```text
60122
  |
  v
100135
  |
  v
100140
```

Após essa alteração, as duas lógicas passaram a coexistir corretamente.

---

## Arquitetura de falhas de autenticação

```text
Windows Event ID 4625
        |
        v
60122 | Level 5
Individual Logon Failure
        |
        +-------------------------------+
        |                               |
        v                               v
60204 | Level 10                  100135 | Level 6
8 failures / same IP             Wrong password
240 seconds                      Existing account
T1110                                  |
                                         v
                                   100140 | Level 12
                                   5 failures
                                   same user
                                   same IP
                                   60 seconds
                                   T1110.001
```

---

# Successful Logon Monitoring

Após validar falhas de autenticação, a etapa seguinte foi analisar logons bem-sucedidos utilizando:

```text
Event ID 4624
An account was successfully logged on
```

Campos relevantes:

```text
TargetUserName
TargetDomainName
LogonType
WorkstationName
IpAddress
IpPort
AuthenticationPackageName
ProcessName
```

---

## Logon Type 2 - Interactive

Foi validado um logon interativo para:

```text
User:        vboxuser
Domain:      WIN10
Logon Type:  2
Source IP:   ::1
AuthPackage: Negotiate
```

O Wazuh classificou o evento como:

```text
Rule ID:      60118
Level:        3
Description:  Windows Workstation Logon Success
```

Interpretação:

```text
Logon Type 2 = Interactive
```

---

## Logon Type 3 - Network

Também foi validado um logon de rede utilizando:

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

Interpretação:

```text
Logon Type 3 = Network
```

---

## Comparação de Logon Types

```text
Type 2  = Interactive
Type 3  = Network
Type 10 = RemoteInteractive / RDP
```

Nesta etapa foram validados diretamente os Types 2 e 3.

---

# Successful Logon After Password Guessing

Após validar a detecção de Password Guessing com a Rule 100140, foi implementada uma correlação adicional para identificar um cenário de maior risco:

```text
múltiplas falhas de senha
+
mesmo usuário
+
mesmo IP
↓
logon bem-sucedido logo depois
```

Esse padrão pode indicar comprometimento de credenciais.

---

## Rule 100145

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

MITRE ATT&CK:

```text
T1078 - Valid Accounts
```

---

## Rule 100150

A regra final correlaciona o sucesso de autenticação com uma ocorrência anterior da Rule 100140:

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

A lógica final é:

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

---

## Validation

O cenário foi testado com:

```text
User:        vboxuser
Source IP:   127.0.0.1
```

Primeiro foram geradas cinco falhas de senha:

```text
100135
100135
100135
100135
100140
```

Em seguida foi realizada uma autenticação válida via rede.

Resultado:

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

## Detection Chain

```text
4625
↓
60122
↓
100135
↓
100140
T1110.001 - Password Guessing
↓
4624 Type 3
↓
100145
↓
100150
T1078 - Valid Accounts
```

---

## SOC Interpretation

Esse padrão é mais crítico do que uma sequência de falhas isoladas.

Em um ambiente real, a combinação:

```text
múltiplas falhas
↓
sucesso posterior
```

pode indicar que uma credencial foi descoberta ou comprometida.

Por isso, a Rule 100150 foi configurada com:

```text
Level 14
```

para representar uma prioridade alta de investigação.

---

## Triage

Como o cenário foi executado de forma controlada no laboratório:

```text
Classification: True Positive
Disposition: Close - Authorized Security Test
```

Em produção, a recomendação seria investigar imediatamente:

- usuário afetado;
- origem do acesso;
- histórico de autenticação;
- dispositivo utilizado;
- eventos posteriores ao logon;
- processos iniciados;
- alterações de privilégio;
- movimentação lateral;
- persistência;
- atividade de rede.

---

## Result

A etapa demonstrou:

- coleta de Windows Security Events;
- análise de Event ID 4625;
- análise de Event ID 4624;
- diferenciação de Logon Type 2 e 3;
- interpretação de Status e SubStatus;
- correlação temporal;
- uso de `same_field`;
- uso combinado de `if_sid`;
- uso de `if_matched_sid`;
- regras nativas e customizadas do Wazuh;
- detecção de brute force;
- detecção de password guessing;
- correlação entre falha e sucesso de autenticação;
- detecção de possível comprometimento de conta;
- mapeamento MITRE ATT&CK para T1110, T1110.001 e T1078;
- troubleshooting de conflito entre regras de correlação;
- triagem de alerta de alta severidade.

