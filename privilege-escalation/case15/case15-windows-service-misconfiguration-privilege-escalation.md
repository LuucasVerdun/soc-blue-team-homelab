# Case 15 — Windows Service Misconfiguration Privilege Escalation Investigation & Detection Engineering

## 1. Objetivo

Investigar e detectar uma condição controlada de **weak service permissions**
em Windows Server 2022, demonstrando como um usuário padrão pode alterar a
configuração de um serviço executado como `LocalSystem` e provocar uma execução
privilegiada benignamente observável.

O cenário foi construído exclusivamente para laboratório. Não foram utilizados
malware, credential dumping, kernel exploits ou ferramentas ofensivas externas.

## 2. Escopo

- **Host:** `WIN-30JS3HVHMAB` — Windows Server 2022
- **Usuário padrão controlado:** `soccase15`
- **Serviço controlado:** `SOC_CASE15`
- **Conta do serviço:** `LocalSystem`
- **Sensor endpoint:** Sysmon 15.21
- **SIEM:** Wazuh 4.14.7
- **Validação final:** `20260916-220147`

## 3. Baseline do usuário

Antes da alteração do serviço, o usuário `soccase15` foi validado como usuário
padrão:

- `whoami`: `win-30js3hvhmab\\soccase15`
- grupo local relevante: `BUILTIN\\Users`
- ausência do grupo `Administrators`
- `Mandatory Label\\Medium Mandatory Level`
- privilégios observados:
  - `SeChangeNotifyPrivilege`
  - `SeIncreaseWorkingSetPrivilege`

O serviço apresentava:

- `TYPE: WIN32_OWN_PROCESS`
- `START_TYPE: DEMAND_START`
- `SERVICE_START_NAME: LocalSystem`
- estado inicial `STOPPED`

## 4. Condição vulnerável deliberada

O SDDL original foi preservado antes da alteração:

`D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`

Uma ACE específica foi adicionada deliberadamente ao usuário de laboratório
para permitir alteração da configuração e inicialização do serviço. Essa
condição foi utilizada apenas durante o teste e removida no cleanup.

## 5. Teste inicial da vulnerabilidade

Executando sob `soccase15`, a alteração do `ImagePath` retornou:

`[SC] ChangeServiceConfig SUCCESS`

O serviço permaneceu configurado para executar como `LocalSystem`.

Antes da inicialização do serviço, o marker privilegiado não existia. Isso
separou a etapa de **modificação** da etapa de **execução privilegiada**.

## 6. Telemetria da alteração

A sequência observada foi:

1. Sysmon Event 1 — `sc.exe config SOC_CASE15 ...`
   - User: `WIN-30JS3HVHMAB\\soccase15`
   - IntegrityLevel: `Medium`
2. Sysmon Event 13
   - Image: `services.exe`
   - User: `NT AUTHORITY\\SYSTEM`
   - TargetObject: `...\\Services\\SOC_CASE15\\ImagePath`
   - Details: `cmd.exe /c ...case15-marker-<token>.cmd`

Esse comportamento é esperado: `sc.exe` representa a ação do usuário, enquanto
o Service Control Manager (`services.exe`) efetiva a alteração no Registry.

## 7. Execução privilegiada controlada

Na validação final `20260916-220147`:

- `soccase15` executou `sc.exe start SOC_CASE15` em Medium Integrity;
- o SCM iniciou o comando configurado no serviço;
- `cmd.exe` executou como `NT AUTHORITY\\SYSTEM`;
- Sysmon Event 11 registrou a criação de
  `case15-system-marker-20260916-220147.txt` por `cmd.exe` como SYSTEM;
- `whoami.exe` foi executado como:
  - User: `NT AUTHORITY\\SYSTEM`
  - IntegrityLevel: `System`.

O marker continha `CASE15_PRIVESC_SUCCESS`. A prova da identidade SYSTEM é a
telemetria Sysmon/Wazuh, e não somente o texto do arquivo.

## 8. Sobre o erro 1053

`sc.exe start SOC_CASE15` retornou `StartService FAILED 1053`.

Isso não representa falha da execução do comando. O binário configurado para o
teste era `cmd.exe`, que não implementa a interface de controle esperada de um
serviço Windows. O processo e o marker foram efetivamente criados, fato
confirmado por Sysmon.

## 9. Detection Engineering no Wazuh

Foram implementadas as seguintes regras:

| Rule | Level | Detecção |
|---|---:|---|
| 100325 | 8 | usuário padrão executando `sc.exe config SOC_CASE15` |
| 100330 | 10 | alteração controlada de `SOC_CASE15\\ImagePath` |
| 100335 | 10 | usuário padrão executando `sc.exe start SOC_CASE15` |
| 100340 | 12 | processo controlado executado como SYSTEM |
| 100345 | 12 | marker criado por SYSTEM |
| 100350 | 13 | correlação configuração → alteração do Registry |
| 100352 | 13 | correlação simétrica para ordem inversa de ingestão |
| 100355 | 14 | configuração seguida de inicialização |
| 100360 | 15 | cadeia final standard user → SYSTEM |

Na execução final foram materializados em `alerts.json`:

`100325 → 100350 → 100355 → 100345 → 100360`

Regras intermediárias como `100330` e `100340` atuaram como pré-requisitos de
regras filhas/correlacionadas e, por isso, não necessariamente aparecem como
alertas separados na cadeia final.

## 10. Cadeia final

```text
soccase15 / Medium Integrity
        |
        v
sc.exe config SOC_CASE15
        |
        v
100325 / Level 8
        |
        v
services.exe altera ImagePath
        |
        v
100350 / Level 13
        |
        v
sc.exe start SOC_CASE15
        |
        v
100355 / Level 14
        |
        v
cmd.exe / SYSTEM cria marker
        |
        v
100345 / Level 12
        |
        v
whoami.exe / SYSTEM / System Integrity
        |
        v
100360 / Level 15
```

## 11. MITRE ATT&CK

- **T1543.003 — Create or Modify System Process: Windows Service**
- **T1569.002 — System Services: Service Execution**
- **T1059.003 — Command and Scripting Interpreter: Windows Command Shell**

A documentação evita classificar o cenário como credential access ou como
exploração de kernel. O comportamento demonstrado foi uma elevação local
controlada baseada em permissão inadequada no objeto de serviço.

## 12. Evidências

Consulte:

- `evidence/case15/summary.md`
- `evidence/case15/case15-custom-rules.xml`
- `evidence/case15/wazuh-final-chain.jsonl`
- `evidence/case15/wazuh-final-telemetry.jsonl`
- `evidence/case15/hashes.sha256`

Hash do arquivo endpoint `case15-final-sysmon-events.txt`:

`466C805410B0F604B276371F16245C4066BFE08B72978CAF79B349A2179AA909`

## 13. Cleanup e remediação

O laboratório foi retornado a um estado seguro:

1. `ImagePath` restaurado para o valor benigno.
2. SDDL original restaurado.
3. Serviço `SOC_CASE15` removido.
4. `sc query SOC_CASE15` confirmou erro 1060.
5. Usuário `soccase15` removido.
6. `Secondary Logon` restaurado para `Stopped`.
7. Artefatos temporários em `C:\\Users\\Public\\case15-*` removidos.
8. Sysmon restaurado para `sysmon-case14.xml`.

Hash da configuração Sysmon ativa após cleanup:

`DC597C27033797D9F5C9F9BD57D7E21BDB7A35679CC198605DC7760D24F598B3`

## 14. Resultado

**True Positive — Controlled Lab.**

Foi comprovada a cadeia:

**standard user → service configuration modification → service start →
LocalSystem process execution**

A regra final `100360`, Level 15, forneceu uma detecção correlacionada de alta
fidelidade para a atividade reproduzida no laboratório.
