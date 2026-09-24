# Case 17 — Windows Event Log Clearing & Defense Evasion Investigation & Detection Engineering

## 1. Objetivo

Investigar e detectar uma cadeia controlada de limpeza de Windows Event Logs em `WINSERVER2022`, começando por um log isolado de laboratório e evoluindo para a limpeza controlada do `Security` log após preservação prévia das evidências.

O cenário foi executado exclusivamente em laboratório próprio e autorizado. O objetivo foi exercitar evidence preservation, Windows Event Log analysis, Sysmon process attribution, Wazuh detection engineering, correlação temporal, tratamento de telemetria recebida fora de ordem e negative testing.

## 2. Escopo

- **Host:** `WIN-30JS3HVHMAB` — Windows Server 2022
- **Wazuh agent:** `002 / WINSERVER2022`
- **SIEM:** Wazuh 4.14.7
- **Endpoint telemetry:** Windows Event Log + Sysmon
- **Usuário executor:** `WIN-30JS3HVHMAB\Administrator`
- **SID:** `S-1-5-21-3382847163-1926424565-132962873-500`
- **Integrity:** High
- **MITRE ATT&CK:** `T1070.001 — Indicator Removal: Clear Windows Event Logs`
- **Classification:** True Positive — Controlled Lab

## 3. Baseline

Antes da primeira ação destrutiva:

- `WazuhSvc`: Running / Automatic
- `Sysmon64`: Running / Automatic
- Wazuh Manager: active
- Agent `002`: Active
- Security log: `8003` registros no baseline inicial
- System log: `10959` registros no baseline inicial
- Sysmon Operational: `38856` registros no baseline inicial
- nenhum Event ID `1102` nos 30 dias anteriores
- nenhum Event ID `104` nos 30 dias anteriores
- Sysmon Event ID `1` ativo

A sessão administrativa apresentava `BUILTIN\Administrators` habilitado e `High Mandatory Level`.

## 4. Primeira etapa — log isolado SOC-Case17

Foi criado o log customizado `SOC-Case17` com a source `SOC-Case17-Lab`.

Três eventos benignos foram gravados: `17001`, `17002` e `17003`, usando o token `20260921-194227`.

Antes da limpeza, o log foi exportado para `SOC-Case17-before-clear-20260921-194227.evtx`.

SHA256:

`945202D7CD8E9FA8206BFED70933E3D1101CD404BF06A40C31DAB31E4BB441B5`

O EVTX exportado foi reaberto e os três eventos foram validados antes da limpeza.

## 5. Event ID 104 — confirmação de log limpo

A execução de `wevtutil cl SOC-Case17` produziu:

- System Event ID: `104`
- Record ID: `10973`
- Provider: `Microsoft-Windows-Eventlog`
- Channel limpo: `SOC-Case17`
- Subject user: `Administrator`
- Domain: `WIN-30JS3HVHMAB`

O Wazuh materializou a regra nativa `63104 / Level 5` — `A Windows log file was cleared`.

## 6. Sysmon process attribution

A mesma ação produziu Sysmon Event ID `1` para `C:\Windows\System32\wevtutil.exe`, command line `cl SOC-Case17`, usuário `Administrator`, `IntegrityLevel=High` e `LogonId=0x60d4a`.

A telemetria demonstrou que o evento de criação de processo ocorreu antes do Event ID `104`, mas o SIEM não necessariamente recebeu os dois canais na mesma ordem.

## 7. Detection Engineering — SOC-Case17

| Rule | Level | Função |
|---|---:|---|
| 100400 | 8 | `wevtutil.exe cl SOC-Case17` via Sysmon Event ID 1 |
| 100405 | 10 | Event ID 104 confirmando que `SOC-Case17` foi limpo |
| 100410 | 13 | ordem normal de ingestão: process clear → Event 104 |
| 100412 | 13 | ordem invertida de ingestão: Event 104 → Sysmon process |

No primeiro teste após criação das regras, o Wazuh materializou `100405` antes de `100400`. Isso impediu a correlação unidirecional `100410`.

Foi então criada a regra simétrica `100412`.

Na validação seguinte:

- Event ID `104`: Record `11058`
- Sysmon Event ID `1`: Record `40597`
- comando: `wevtutil.exe cl SOC-Case17`
- final correlation: `100412 / Level 13`

Esse resultado demonstrou a diferença entre **event time** e **SIEM ingestion time**.

## 8. Preservação do Security log antes da limpeza

Antes de limpar o `Security` log:

- RecordCount: `8072`
- FileSize: `6361088` bytes

O log inteiro foi exportado para `Security-before-clear-20260921-211213.evtx`.

SHA256:

`5857D2210035B3596723C8A163363E0C99B99B339EF5E35175C3AB44343B0139`

A leitura do backup retornou exatamente `8072` registros. Essa preservação foi concluída antes da execução de `wevtutil cl Security`.

## 9. Security Event ID 1102

A primeira limpeza controlada do `Security` log produziu:

- Event ID: `1102`
- Record ID: `8086`
- Subject SID: `S-1-5-21-3382847163-1926424565-132962873-500`
- Subject user: `Administrator`
- Subject domain: `WIN-30JS3HVHMAB`
- Subject Logon ID: `0x60d4a`

O Sysmon correspondente foi:

- Event ID: `1`
- Record ID: `41279`
- Image: `wevtutil.exe`
- Command line: `wevtutil.exe cl Security`
- User: `WIN-30JS3HVHMAB\Administrator`
- Logon ID: `0x60d4a`
- Integrity: High
- Parent: PowerShell

A correlação investigativa foi:

`Sysmon.logonId == 1102.subjectLogonId == 0x60d4a`

O Wazuh materializou nativamente `63103 / Level 5` — `The audit log was cleared`.

Embora o ruleset também contenha a rule `60117` para Event ID `1102`, ela não foi a regra materializada no teste real.

Também não foi observado Event ID `104` no `System` dentro da janela da limpeza do `Security` log. Portanto, o Case 17 não assume que `104` acompanha toda limpeza de `Security`.

## 10. MITRE ATT&CK

O Wazuh 4.14.7 instalado conhece `T1070.001`, então as regras customizadas do Case 17 utilizam diretamente:

**T1070.001 — Indicator Removal: Clear Windows Event Logs**

Foi observada uma inconsistência no ruleset nativo: a rule `60117` contém `T1070.004`, enquanto a rule `63103` materializada utiliza `T1070`. Nenhum desses mapeamentos foi adotado como granular mapping do Case 17.

## 11. Detection Engineering — Security audit log

| Rule | Level | Função |
|---|---:|---|
| 100415 | 10 | Sysmon detecta `wevtutil.exe cl Security` |
| 100420 | 12 | Event ID 1102 confirma Security audit log clearing |
| 100425 | 15 | ordem normal: clear process → 1102 |
| 100427 | 15 | ordem invertida: 1102 → clear process |

As regras finais são temporais. Elas não fazem comparação dinâmica entre `win.eventdata.logonId` e `win.logFileCleared.subjectLogonId`.

A igualdade desses campos foi validada manualmente durante a investigação.

## 12. Validação final Level 15

Antes da segunda validação, o pequeno Security log atual foi novamente preservado em `Security-before-detection-clear-20260921-213605.evtx`.

- eventos: `11`
- SHA256: `DE4D9F0290364BC9BF43FC8AF503E8DE791D496F7E393A320D6D7C9FA7ED306A`

A execução final produziu:

### Security 1102

- Record ID: `8097`
- SystemTime: `2026-09-22T04:36:39.6888454Z`
- Subject user: `Administrator`
- Subject SID: `S-1-5-21-3382847163-1926424565-132962873-500`
- Subject Logon ID: `0x60d4a`
- Custom rule: `100420`
- Level: `12`

### Sysmon Event ID 1

- Record ID: `41784`
- SystemTime: `2026-09-22T04:36:39.6758754Z`
- PID: `1412`
- ProcessGuid: `{34dad77b-05d7-6ab2-8701-000000001d00}`
- Image: `C:\Windows\System32\wevtutil.exe`
- Command line: `"C:\Windows\system32\wevtutil.exe" cl Security`
- User: `WIN-30JS3HVHMAB\Administrator`
- Logon ID: `0x60d4a`
- Integrity: High
- Parent PID: `3112`
- Parent image: PowerShell

O Sysmon ocorreu aproximadamente `12.97 ms` antes do `1102`.

Entretanto, o Wazuh materializou primeiro `100420` e recebeu depois o evento Sysmon. A regra simétrica `100427` correlacionou a sequência e gerou Level `15`.

## 13. Cadeia final

```text
EVENT TIME

Sysmon Event 1 / Record 41784
wevtutil.exe cl Security
LogonId 0x60d4a
        |
        | ~12.97 ms
        v
Security 1102 / Record 8097
SubjectLogonId 0x60d4a


WAZUH INGESTION

100420 / Level 12
1102 materialized first
        |
        v
Sysmon telemetry arrives
matches 100415 conditions
        |
        v
100427 / Level 15
```

## 14. Negative test

Foi executado:

`wevtutil qe Security /c:1 /rd:true /f:text`

Esse comando consulta o log e não o limpa.

Sysmon registrou Event ID `1`, Record `41861`.

O contador de alertas Case 17 Security permaneceu `2 → 2`.

Não houve novo `100415`, `100420`, `100425` ou `100427`.

Isso demonstrou que a lógica não alerta simplesmente pelo uso de `wevtutil.exe`; ela exige a semântica de limpeza `cl Security` e/ou a confirmação por Event ID `1102`.

## 15. Limitações e tuning

- `wevtutil.exe` é uma ferramenta administrativa legítima; contexto é necessário antes de classificar uso como atividade maliciosa.
- A correlação `100425/100427` é temporal e não compara dinamicamente Logon IDs.
- A igualdade `0x60d4a == 0x60d4a` foi validada durante investigação.
- Canais Windows diferentes podem chegar ao SIEM fora de ordem.
- A implementação usa regras simétricas para tolerar essa inversão.
- O teste cobre `wevtutil.exe`; outras técnicas ou APIs capazes de limpar logs exigiriam cobertura adicional.
- Event ID `104` foi observado para o log customizado, mas não para a limpeza de `Security` no ambiente testado.
- Em produção, approved maintenance, troubleshooting e change-management devem ser considerados no tuning.

## 16. Evidências

Arquivos preservados no repositório:

- `wazuh-alerts.jsonl`
- `wazuh-final-chain.jsonl`
- `supporting-events.jsonl`
- `local_rules-active-post-case17.xml`
- `case17-custom-rules.xml`
- `security-8097-event1102.xml`
- `sysmon-41784-wevtutil-cl-security.xml`
- `sysmon-41861-negative-qe-security.xml`
- `summary.md`
- `hashes.sha256`

EVTX preservados localmente durante a execução:

- `SOC-Case17-before-clear-20260921-194227.evtx`
- `SOC-Case17-before-detection-clear-20260921-203527.evtx`
- `SOC-Case17-before-correlation-clear-20260921-204606.evtx`
- `Security-before-clear-20260921-211213.evtx`
- `Security-before-detection-clear-20260921-213605.evtx`

## 17. Conclusão

O Case 17 demonstrou uma investigação completa de Defense Evasion envolvendo Windows Event Log clearing, começando por um canal isolado e evoluindo para o Security audit log após preservação forense.

A investigação correlacionou processo, command line, usuário, Integrity Level, Logon ID, Event ID `104`, Event ID `1102`, Sysmon e Wazuh.

A validação final produziu uma correlação Wazuh Level 15 e também demonstrou um problema operacional real de SIEM: eventos causalmente ordenados podem ser ingeridos em ordem diferente. A detecção foi ajustada para tolerar esse comportamento sem abandonar o negative testing.
