# Case 15 — Evidence Summary

## Identificação

- **Case:** 15
- **Título:** Windows Service Misconfiguration Privilege Escalation Investigation & Detection Engineering
- **Final validation token:** `20260916-220147`
- **Asset:** `WINSERVER2022` / `WIN-30JS3HVHMAB`
- **Standard user:** `WIN-30JS3HVHMAB\\soccase15`
- **Service:** `SOC_CASE15`
- **Service account:** `LocalSystem`
- **SIEM:** Wazuh 4.14.7
- **Endpoint telemetry:** Sysmon 15.21
- **Classification:** True Positive — Controlled Lab
- **Impact demonstrated:** Standard-user service modification followed by controlled LocalSystem execution
- **Malware:** None
- **Credential access:** None
- **External offensive tooling:** None

## Condição vulnerável controlada

O objeto de serviço `SOC_CASE15` recebeu deliberadamente uma ACE específica para
o usuário padrão `soccase15`, permitindo a alteração da configuração do serviço
e sua inicialização. O serviço continuou configurado para executar como
`LocalSystem`.

A validação inicial demonstrou que `soccase15`:

- estava em **Medium Integrity**;
- pertencia a `BUILTIN\\Users`;
- não pertencia a `Administrators`;
- possuía privilégios de token limitados;
- conseguia consultar o serviço;
- conseguia executar `ChangeServiceConfig` devido à ACL deliberadamente fraca.

## Cadeia final validada

1. `soccase15` executou `sc.exe config SOC_CASE15 ...` em Medium Integrity.
2. **100325 / Level 8** detectou a alteração de configuração pelo usuário padrão.
3. Sysmon Event 13 mostrou `services.exe` gravando `SOC_CASE15\\ImagePath`.
4. **100350 / Level 13** correlacionou a ação do usuário com a alteração no Registry.
5. `soccase15` executou `sc.exe start SOC_CASE15`.
6. **100355 / Level 14** correlacionou alteração seguida de inicialização.
7. Sysmon Event 11 mostrou `cmd.exe`, como `NT AUTHORITY\\SYSTEM`, criando o marker.
8. **100345 / Level 12** detectou o marker criado no contexto SYSTEM.
9. `whoami.exe` foi executado como `NT AUTHORITY\\SYSTEM`, `IntegrityLevel: System`.
10. **100360 / Level 15** confirmou a cadeia controlada de elevação de privilégio.

> O retorno `StartService FAILED 1053` é compatível com o payload controlado:
> `cmd.exe` executou o comando, porém não implementa a interface de um serviço
> Windows convencional e, portanto, não responde ao Service Control Manager
> como um serviço normal.

## Regras customizadas

| Rule ID | Level | Função |
|---|---:|---|
| 100325 | 8 | `sc.exe config SOC_CASE15` por `soccase15` em Medium Integrity |
| 100330 | 10 | alteração do `SOC_CASE15\\ImagePath` |
| 100335 | 10 | `sc.exe start SOC_CASE15` por `soccase15` |
| 100340 | 12 | execução controlada como SYSTEM |
| 100345 | 12 | criação do marker por SYSTEM |
| 100350 | 13 | correlação configuração → Registry |
| 100352 | 13 | correlação simétrica Registry → configuração |
| 100355 | 14 | correlação configuração → inicialização |
| 100360 | 15 | correlação final: standard user → LocalSystem execution |

Na execução final, regras filhas/correlacionadas substituíram alguns alertas
intermediários na saída de alertas. O arquivo `wazuh-final-chain.jsonl` preserva
os cinco alertas finais observados: `100325`, `100350`, `100355`, `100345` e
`100360`.

## Evidências do repositório

| Arquivo | SHA256 |
|---|---|
| `case15-custom-rules.xml` | `3d77695313477750e176fdc32948600656c15e9468fe629eaa21a2bc2b156d92` |
| `wazuh-final-chain.jsonl` | `ee33234fef161a003b434a4d18386ab5a6c76fb3f3cd7eee1b996408bed5eb4e` |
| `wazuh-final-telemetry.jsonl` | `6b677c512754c8547823dde0cf37aa09c906c5d55e97c43802d57d962ba45a63` |

## Evidências preservadas no endpoint

| Artefato | SHA256 |
|---|---|
| `case15-final-sysmon-events.txt` | `466C805410B0F604B276371F16245C4066BFE08B72978CAF79B349A2179AA909` |
| `case15-marker-20260916-220147.cmd` | `CBF97A8B7DD28B35F6950116F024A4C73695BD008BF89101B520307A74F8DDBB` |
| `case15-user-actions-20260916-220147.cmd` | `B38C264BD94C6DC69B7B863DEA8A7E089B0F51D5329D045F8FB135E3B2F207DA` |
| `case15-system-marker-20260916-220147.txt` | `A980C560CEC290EEA40D499D5742C8EACC80C3FBABAA14C11C569E9B0C2792B0` |
| `sysmon-case15.xml` | `B990081D1B3114E0429A4B781C24B8D4CA175A035646D0F0A38ED967DC371901` |

O marker continha `CASE15_PRIVESC_SUCCESS`. A identidade privilegiada não é
inferida apenas pelo conteúdo do marker: ela é comprovada pela telemetria
Sysmon/Wazuh, que registrou `whoami.exe` e seu processo pai no contexto
`NT AUTHORITY\\SYSTEM`.

## MITRE ATT&CK

- **T1543.003 — Create or Modify System Process: Windows Service**
- **T1569.002 — System Services: Service Execution**
- **T1059.003 — Command and Scripting Interpreter: Windows Command Shell**
  (telemetria específica do processo controlado)

## Cleanup / Remediação do laboratório

Após preservar a evidência:

- o `ImagePath` foi restaurado para o comando benigno original;
- o SDDL original do serviço foi restaurado;
- a ACE específica de `soccase15` deixou de existir;
- `SOC_CASE15` foi removido e `sc query` retornou erro 1060;
- o usuário local `soccase15` foi removido;
- `Secondary Logon` voltou ao estado `Stopped`;
- os artefatos temporários `C:\\Users\\Public\\case15-*` foram removidos;
- Sysmon foi restaurado para `sysmon-case14.xml`;
- hash da configuração Sysmon ativa após cleanup:
  `DC597C27033797D9F5C9F9BD57D7E21BDB7A35679CC198605DC7760D24F598B3`.

## Conclusão

O Case 15 demonstrou, de forma controlada e sem malware, que uma permissão
inadequada sobre um serviço que roda como `LocalSystem` pode permitir que um
usuário padrão altere sua configuração e provoque execução privilegiada.

A detecção final não depende de um único indicador. Ela correlaciona:

**standard-user service modification → Registry confirmation → service start →
SYSTEM-owned file creation → SYSTEM process execution**.
