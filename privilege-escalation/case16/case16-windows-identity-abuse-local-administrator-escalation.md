# Case 16 — Windows Identity Abuse & Local Administrator Escalation Investigation & Detection Engineering

## 1. Objetivo

Investigar e detectar, em Windows Server 2022, uma cadeia controlada de abuso de
identidade local composta por:

**criação de conta → atribuição ao grupo Administrators → uso de credenciais
válidas → split token do UAC → token elevado → privilégios especiais → execução
de processo em High Integrity**.

O cenário foi executado exclusivamente em laboratório autorizado. Não foram
utilizados malware, credential dumping, exploit de kernel, UAC bypass ou
ferramentas ofensivas externas.

## 2. Escopo

- **Host:** `WIN-30JS3HVHMAB` — Windows Server 2022
- **Conta controlada:** `soccase16`
- **SIEM:** Wazuh 4.14.7
- **Endpoint telemetry:** Sysmon
- **Wazuh agent:** `002 / WINSERVER2022`
- **Final live validation:** `2026-09-21`
- **Classification:** True Positive — Controlled Lab

## 3. Baseline e conceito de identidade

O `Administrator` local possuía RID `500` e a conta `soccase16` ainda não
existia no início da validação final.

Uma execução histórica anterior havia criado `soccase16` com SID:

`S-1-5-21-3382847163-1926424565-132962873-1003`

Após cleanup, a conta foi recriada para a validação live e recebeu:

`S-1-5-21-3382847163-1926424565-132962873-1004`

O nome de usuário permaneceu `soccase16`, mas o SID mudou. Isso demonstrou na
prática que **username reutilizado não representa a mesma identidade de
segurança**.

## 4. Criação da conta — Event ID 4720

A validação live gerou:

- Event ID: `4720`
- Record ID: `7717`
- Actor: `Administrator`
- Actor Logon ID: `0x6ffba`
- Target account: `soccase16`
- Target SID: `S-1-5-21-3382847163-1926424565-132962873-1004`
- Custom rule: `100365`
- Level: `8`

A rule `100365` utiliza `60109` como parent e restringe a detecção ao Event ID
`4720` e à conta controlada.

## 5. Atribuição ao grupo local Administrators — Event ID 4732

A nova identidade foi adicionada ao grupo local `Administrators`.

Evidência live:

- Event ID: `4732`
- Record ID: `7723`
- Actor: `Administrator`
- Actor Logon ID: `0x6ffba`
- Group SID: `S-1-5-32-544`
- Member SID: `S-1-5-21-3382847163-1926424565-132962873-1004`
- Final correlated rule: `100375`
- Level: `13`

A igualdade:

`4720.targetSid == 4732.memberSid == S-1-5-21-3382847163-1926424565-132962873-1004`

comprova, nesta investigação, que a identidade criada foi a mesma identidade
posteriormente adicionada a `BUILTIN\Administrators`.

## 6. Detection Engineering — Create → Promote

Regras relevantes:

| Rule | Level | Função |
|---|---:|---|
| 100365 | 8 | criação controlada de `soccase16` |
| 100370 | 12 | membro adicionado a `Administrators` |
| 100375 | 13 | criação recente seguida de atribuição administrativa |

A `100375` usa correlação temporal e depende de `100365` anterior e `100370`
no evento atual.

Foi realizado negative test com a ordem invertida:

**4732 → 4720**

e a `100375` não disparou. Isso confirmou que a regra é sensível à ordem
temporal **create → promote**.

Limitação documentada: a correlação temporal do Wazuh não compara diretamente
`4720.targetSid` com `4732.memberSid`, pois os nomes dos campos são diferentes.
A igualdade de SID foi validada durante a investigação.

## 7. UAC split token e logon elevado

A conta administrativa local foi utilizada por `runas`, produzindo dois
contextos de logon relacionados.

### Token elevado

- Event ID: `4624`
- Record ID: `7729`
- Target user: `soccase16`
- Target SID: `S-1-5-21-3382847163-1926424565-132962873-1004`
- Logon Type: `2`
- Logon ID: `0x452c93`
- Linked Logon ID: `0x452cc0`
- Elevated Token: `%%1842` / Yes
- Logon Process: `seclogo`
- Rule: `100380`
- Level: `10`

### Token filtrado

- Event ID: `4624`
- Record ID: `7730`
- Logon ID: `0x452cc0`
- Linked Logon ID: `0x452c93`
- Elevated Token: `%%1843` / No
- Native rule: `60118`

O relacionamento bidirecional dos `Linked Logon ID` demonstrou o split token
do UAC.

## 8. Validação de token no endpoint

A PowerShell Medium executada como `soccase16` apresentou:

- PID `4440`
- `BUILTIN\Administrators` como **Group used for deny only**
- `S-1-5-114` como **Group used for deny only**
- `Mandatory Label\Medium Mandatory Level`
- SID de integridade `S-1-16-8192`
- privilégios limitados

Após consentimento UAC, a PowerShell High apresentou:

- PID `4120`
- `BUILTIN\Administrators` habilitado
- grupo marcado também como `Group owner`
- `Mandatory Label\High Mandatory Level`
- SID de integridade `S-1-16-12288`
- privilégios administrativos adicionais, incluindo `SeDebugPrivilege` e
  `SeImpersonatePrivilege`

Isso é **elevação legítima via UAC**, não UAC bypass.

## 9. Special Privileges — Event ID 4672

Evidência live:

- Event ID: `4672`
- Record ID: `7731`
- Subject user: `soccase16`
- Subject Logon ID: `0x452c93`
- Rule: `100385`
- Level: `12`

A correlação investigativa foi:

`4624.targetLogonId == 4672.subjectLogonId == 0x452c93`

O evento incluiu privilégios como `SeSecurityPrivilege`,
`SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`,
`SeDebugPrivilege`, `SeImpersonatePrivilege` e outros.

O Event ID `4672` isoladamente não é tratado como atividade maliciosa; ele
recebe contexto da identidade, do logon elevado e da atividade subsequente.

## 10. Execução High Integrity — Sysmon Event ID 1

O primeiro processo High relevante da validação final foi:

- Record ID: `34532`
- Image: `powershell.exe`
- PID: `4120`
- Parent PID: `4440`
- Parent image: `powershell.exe`
- User: `WIN-30JS3HVHMAB\soccase16`
- Logon ID: `0x452c93`
- Integrity Level: `High`

A rule `100390`, Level 12, detecta processos High Integrity executados pela
conta controlada sem hardcode do Logon ID.

## 11. Correlação final — Rule 100395

A rule `100395`, Level 15, correlaciona:

**100375 — criação + Administrators**

com:

**100390 — execução High Integrity**

dentro da janela configurada.

Na execução live, o primeiro alerta final foi:

- Rule: `100395`
- Level: `15`
- Sysmon Record ID: `34532`
- PID: `4120`
- Logon ID: `0x452c93`
- Integrity: `High`

A cadeia cross-source foi:

```text
4720 / targetSid S-1-5-21-3382847163-1926424565-132962873-1004
         |
         v
4732 / memberSid S-1-5-21-3382847163-1926424565-132962873-1004
         |
         v
100375 / Level 13
         |
         v
4624 elevated / LogonId 0x452c93
         |
         v
4672 / SubjectLogonId 0x452c93
         |
         v
Sysmon Event 1 / LogonId 0x452c93 / High
         |
         v
100395 / Level 15
```

## 12. Processos High observados

Enquanto a janela correlacional permaneceu ativa, processos High adicionais
também satisfizeram a regra final:

| Record | PID | Processo | Parent |
|---|---:|---|---|
| 34532 | 4120 | `powershell.exe -NoExit` | Medium PowerShell PID 4440 |
| 34533 | 2332 | `conhost.exe` | High PowerShell PID 4120 |
| 34548 | 2000 | `whoami.exe` | High PowerShell |
| 34551 | 4556 | `whoami.exe /groups` | High PowerShell |
| 34556 | 3404 | `whoami.exe /priv` | High PowerShell |

Todos compartilharam `LogonId: 0x452c93` e
`IntegrityLevel: High`.

Esse comportamento é correto para a lógica atual, mas demonstra uma
oportunidade de tuning para reduzir alertas repetidos em produção.

## 13. Regras customizadas

| Rule | Level | Detecção |
|---|---:|---|
| 100365 | 8 | criação de `soccase16` |
| 100370 | 12 | adição de membro a `Administrators` |
| 100375 | 13 | create → administrator assignment |
| 100380 | 10 | logon da conta com token elevado |
| 100385 | 12 | elevated logon → special privileges |
| 100390 | 12 | processo High Integrity da conta controlada |
| 100395 | 15 | criação/promoção → execução High Integrity |

## 14. MITRE ATT&CK

- **T1136.001 — Create Account: Local Account**
- **T1098 — Account Manipulation** — mapping compatível com a base MITRE
  embarcada no Wazuh 4.14.7; o comportamento de grupo local corresponde à
  granularidade atual **T1098.007 — Additional Local or Domain Groups**.
- **T1078 — Valid Accounts** — mapping compatível com a regra Wazuh; para a
  conta local utilizada neste caso, a granularidade atual é
  **T1078.003 — Local Accounts**.

A atividade UAC deste caso não é classificada como `T1548.002`, pois não houve
bypass de UAC.

## 15. Tuning e falsos positivos

Eventos como `4720`, `4732`, `4624`, `4672` e processos High Integrity podem
ocorrer legitimamente em administração Windows.

O aumento de confiança vem da sequência:

**new local account → Administrators → valid logon → elevated token →
special privileges → High Integrity execution**

Recomendações para produção:

- manter allowlist de contas administrativas aprovadas;
- excluir contas de provisioning conhecidas quando apropriado;
- correlacionar SID da identidade entre eventos;
- reduzir ou deduplicar múltiplos processos High da mesma sessão;
- ajustar `timeframe` com base no comportamento administrativo real;
- priorizar criação de conta seguida de promoção em curto intervalo;
- enriquecer com ticket/change management quando disponível.

Durante a investigação, uma regra nativa Wazuh atribuiu `T1484` ao Event ID
`4672`. Essa associação nativa não foi adotada como descrição do
comportamento deste caso, pois a telemetria demonstrou privilégios locais de
uma nova sessão, e não modificação de política de domínio.

## 16. Validação do Wazuh

As regras foram testadas em duas etapas:

1. `wazuh-logtest` com eventos históricos para positive/negative testing;
2. validação live end-to-end com o agente `002`.

A validação live comprovou:

`Windows Security / Sysmon → Wazuh Agent → Manager → custom rules →
correlation → Level 15 alert`.

## 17. Cleanup

Após preservação das evidências:

- processos de `soccase16` foram encerrados;
- a conta foi removida de `Administrators`;
- Event ID `4733`, Record `7752`, registrou a remoção do SID `S-1-5-21-3382847163-1926424565-132962873-1004`;
- a conta `soccase16` foi excluída;
- Event ID `4726`, Record `7754`, registrou a exclusão do mesmo SID;
- `Secondary Logon` foi restaurado para `Stopped / Manual`;
- `Administrators` voltou a conter somente o `Administrator`.

A execução anterior, SID `S-1-5-21-3382847163-1926424565-132962873-1003`, também possuía seus próprios eventos
`4733/4726`. Isso reforça novamente a distinção entre username e SID.

## 18. Evidências

Consulte:

- `evidence/case16/summary.md`
- `evidence/case16/case16-custom-rules.xml`
- `evidence/case16/wazuh-live-alerts.jsonl`
- `evidence/case16/wazuh-live-chain.jsonl`
- `evidence/case16/hashes.sha256`
- `evidence/case16/wazuh-supporting-events.jsonl`

## 19. Resultado

**True Positive — Controlled Lab.**

Foi comprovada uma cadeia identity-focused completa, desde a criação e
promoção de uma nova conta local até sua utilização em contexto elevado e a
execução real de processos High Integrity, com correlação entre Windows
Security Events, Sysmon e Wazuh.
