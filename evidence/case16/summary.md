# Case 16 — Evidence Summary

## Identificação

- **Case:** 16
- **Título:** Windows Identity Abuse & Local Administrator Escalation Investigation & Detection Engineering
- **Asset:** `WINSERVER2022` / `WIN-30JS3HVHMAB`
- **Controlled identity:** `WIN-30JS3HVHMAB\soccase16`
- **Historical SID:** `S-1-5-21-3382847163-1926424565-132962873-1003`
- **Live validation SID:** `S-1-5-21-3382847163-1926424565-132962873-1004`
- **Elevated Logon ID:** `0x452c93`
- **Filtered Logon ID:** `0x452cc0`
- **SIEM:** Wazuh 4.14.7
- **Endpoint telemetry:** Windows Security Event Log + Sysmon
- **Classification:** True Positive — Controlled Lab
- **Malware:** None
- **Credential dumping:** None
- **UAC bypass:** None
- **External offensive tooling:** None

## Cadeia final validada

1. Event `4720`, Record `7717`, criou `soccase16`.
2. **100365 / Level 8** detectou a criação.
3. Event `4732`, Record `7723`, adicionou SID `S-1-5-21-3382847163-1926424565-132962873-1004` a
   `BUILTIN\Administrators`.
4. **100375 / Level 13** correlacionou criação seguida de atribuição
   administrativa.
5. Event `4624`, Record `7729`, registrou token elevado para
   `0x452c93`.
6. **100380 / Level 10** detectou o logon elevado.
7. Event `4624`, Record `7730`, registrou o token filtrado
   `0x452cc0`.
8. Event `4672`, Record `7731`, associou privilégios especiais ao
   `0x452c93`.
9. **100385 / Level 12** correlacionou logon elevado com special privileges.
10. Sysmon Event `1`, Record `34532`, registrou PowerShell PID `4120` em
    High Integrity com Logon ID `0x452c93`.
11. **100395 / Level 15** confirmou a cadeia final.
12. Event `4733`, Record `7752`, removeu o SID `S-1-5-21-3382847163-1926424565-132962873-1004` de Administrators.
13. Event `4726`, Record `7754`, excluiu a mesma identidade.

## Correlações de identidade

```text
4720.targetSid
  = S-1-5-21-3382847163-1926424565-132962873-1004

4732.memberSid
  = S-1-5-21-3382847163-1926424565-132962873-1004
```

```text
4624.targetLogonId
  = 0x452c93

4672.subjectLogonId
  = 0x452c93

Sysmon.logonId
  = 0x452c93
```

## Split token

| Contexto | Logon ID | Linked Logon ID | ElevatedToken |
|---|---|---|---|
| Elevated | `0x452c93` | `0x452cc0` | `%%1842` / Yes |
| Filtered | `0x452cc0` | `0x452c93` | `%%1843` / No |

Endpoint validation:

- Medium PowerShell PID `4440`: Administrators deny-only, Integrity
  `S-1-16-8192`.
- High PowerShell PID `4120`: Administrators enabled, Integrity
  `S-1-16-12288`.

## Regras customizadas

| Rule ID | Level | Função |
|---|---:|---|
| 100365 | 8 | account creation |
| 100370 | 12 | local Administrators assignment |
| 100375 | 13 | create → promote correlation |
| 100380 | 10 | elevated-token logon |
| 100385 | 12 | elevated logon → special privileges |
| 100390 | 12 | High Integrity process |
| 100395 | 15 | final identity-escalation correlation |

## Alertas live customizados preservados

A execução final preservou nove alertas com grupo `case16`.

O primeiro processo final de alta confiança foi:

- Rule `100395`
- Level `15`
- Record `34532`
- PID `4120`
- Image `powershell.exe`
- Parent PID `4440`
- Logon ID `0x452c93`
- Integrity `High`

Processos High adicionais observados:

- `conhost.exe` PID `2332`
- `whoami.exe` PID `2000`
- `whoami.exe /groups` PID `4556`
- `whoami.exe /priv` PID `3404`

Todos pertenciam ao mesmo Logon ID elevado.

## Evidências preservadas

- `case16-custom-rules.xml` — regras customizadas `100365–100395`.
- `wazuh-live-alerts.jsonl` — alertas customizados observados na validação live.
- `wazuh-live-chain.jsonl` — cadeia principal de criação, promoção, logon privilegiado e execução High Integrity.
- `wazuh-supporting-events.jsonl` — Event ID 4624 do token filtrado e eventos de cleanup 4733/4726.
- `hashes.sha256` — hashes SHA256 dos artefatos preservados.

## Positive / Negative Testing

Foram validados:

- `4720 → 4732` dispara `100375`;
- ordem inversa `4732 → 4720` não dispara `100375`;
- `4624 ElevatedToken=Yes` dispara `100380`;
- `4624 ElevatedToken=No` não dispara `100380`;
- elevated `4624 → 4672` dispara `100385`;
- filtered `4624 → 4672` não dispara `100385`;
- create/promote → Sysmon High dispara `100395`;
- Sysmon High isolado gera somente `100390`;
- Sysmon High antes de create/promote não gera `100395`.

## MITRE ATT&CK

- **T1136.001 — Create Account: Local Account**
- **T1098 — Account Manipulation** (Wazuh-compatible); current granular
  mapping: **T1098.007 — Additional Local or Domain Groups**
- **T1078 — Valid Accounts** (Wazuh-compatible); current granular mapping:
  **T1078.003 — Local Accounts**

## Cleanup

- identidade removida de `Administrators`;
- Event `4733` preservado;
- identidade excluída;
- Event `4726` preservado;
- `seclogon` restaurado para `Stopped / Manual`;
- local `Administrators` retornou ao baseline.

## Conclusão

O Case 16 demonstrou uma investigação identity-focused completa, com
correlação entre SID, Logon ID, UAC split token, privilégios, integridade de
processo, Windows Security Event Log, Sysmon e Wazuh.

A detecção final não depende de um único evento; ela utiliza contexto temporal
e múltiplas fontes para elevar a confiança analítica.
