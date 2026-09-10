# Case 13 — Investigação de Movimento Lateral e Detection Engineering

## Visão geral

Este caso documenta uma simulação **controlada e benigna** de movimento lateral de `WIN10` (`192.168.100.20`) para `WINSERVER2022` (`192.168.100.30`) utilizando SMB administrative shares e o Windows Service Control Manager.

O objetivo foi reconstruir a cadeia completa sob a ótica de um SOC e desenvolver detecções Wazuh capazes de correlacionar Windows Security, System, Sysmon, Zeek e Suricata.

Nenhum malware foi utilizado. O payload apenas criou um marker.

## Execução oficial

- Token: `20260910-030053`
- Serviço: `SOC_CASE13_20260910030053`
- Script: `case13-remote-20260910-030053.cmd`
- Marker: `case13-marker-20260910-030053.txt`
- Fluxo SMB: `192.168.100.20:50227 -> 192.168.100.30:445`
- SHA256 observado pelo Zeek e confirmado no servidor: `59E00E12FCC3249FCF9B0B4E71AE2B232AF38AC3E8967A58E531CDF53367409D`

## 1. Contexto de autenticação

Um Event ID 4624 anterior estabeleceu a sessão SMB:

- Logon Type `3`
- Workstation `WIN10`
- Source Address `192.168.100.20`
- Source Port `50227`
- Authentication Package `NTLM`
- NTLM V2
- Account `Administrator`
- Logon ID `0x2C5437`

A sessão permaneceu aberta e foi reutilizada na execução final. Por isso, a execução oficial não precisou gerar um novo 4624.

### Validação de alerta nativo

A regra Wazuh `92657` descreveu o logon como possível Pass-the-Hash / possível RDP. A evidência, porém, mostrava SMB/445 com Logon Type 3 e NTLM V2.

**Conclusão:** não classificar como Pass-the-Hash nem RDP. A descrição do alerta foi tratada como pista de investigação, não como verdade absoluta.

## 2. Transferência via ADMIN$

O script foi copiado para:

`\\192.168.100.30\ADMIN$\Temp\case13-remote-20260910-030053.cmd`

No servidor isso corresponde a:

`C:\Windows\Temp\case13-remote-20260910-030053.cmd`

O Security Event ID 5145 mostrou:

- origem `192.168.100.20:50227`;
- share `ADMIN$`;
- target `Temp\case13-remote-20260910-030053.cmd`;
- Access Mask `0x2`;
- `WriteData (or AddFile)`;
- conta `Administrator`;
- Logon ID `0x2C5437`.

A custom rule `100260` elevou esse write para Level 8 e mapeou `T1021.002`.

## 3. Zeek observa o arquivo SMB

Zeek registrou o mesmo objeto em `smb_files.log` e `files.log`:

- UID `C2mN2qTkFJzCj9PTj`
- FUID `FTs14p1ZkYJbJpWOr9`
- `192.168.100.20:50227 -> 192.168.100.30:445`
- `ADMIN$`
- tamanho final `108 bytes`
- MIME `text/x-msdos-batch`
- `missing_bytes: 0`
- SHA256 `59e00e12fcc3249fcf9b0b4e71ae2b232af38ac3e8967a58e531cdf53367409d`

O arquivo armazenado no WINSERVER2022 apresentou o mesmo SHA256.

## 4. Criação de serviço remoto

O serviço foi criado com:

- Name `SOC_CASE13_20260910030053`
- Binary Path `cmd.exe /c C:\Windows\Temp\case13-remote-20260910-030053.cmd`
- Start Type `demand`
- Account `LocalSystem`

O Windows System Event ID 7045 registrou a instalação. A regra nativa Wazuh `61138` detectou `New Windows Service Created` e mapeou `T1543.003`.

## 5. Zeek DCE/RPC

No mesmo UID SMB, o `dce_rpc.log` registrou:

- `OpenSCManager2`
- `CreateServiceW`
- `OpenSCManager2`
- `OpenServiceW`
- `StartServiceW`

Endpoint: `svcctl`

Named pipe: `\pipe\ntsvcs`

Isso forneceu evidência de rede independente para criação e inicialização de serviço remoto.

## 6. Suricata

Suricata observou o mesmo par de endpoints e disparou:

`ET INFO Command Shell Activity Over SMB - Possible Lateral Movement`

Signature ID `2027175`, categoria `Potentially Bad Traffic`.

O alerta IDS foi usado como **evidência corroborativa**, não como prova isolada.

## 7. Erro 1053 e execução real

`sc.exe start` retornou erro 1053 porque `cmd.exe` não implementa o protocolo normal de um Windows Service.

Os eventos 7009 e 7000 registraram timeout/falha do serviço, mas isso não significou que o comando não executou.

## 8. Sysmon prova a execução

Sysmon Event ID 1:

- PID `2476`
- ProcessGuid `{34dad77b-47e5-6aa2-6d02-000000001700}`
- Image `C:\Windows\System32\cmd.exe`
- CommandLine `cmd.exe /c C:\Windows\Temp\case13-remote-20260910-030053.cmd`
- User `NT AUTHORITY\SYSTEM`
- Integrity `System`
- ParentProcessId `612`

`ParentImage` não foi preenchido pelo evento. Uma consulta posterior identificou PID 612 como `services.exe`; esse dado é tratado apenas como validação complementar.

## 9. Sysmon prova o efeito

Sysmon Event ID 11 registrou o mesmo PID e ProcessGuid criando:

`C:\Users\Public\case13-marker-20260910-030053.txt`

O conteúdo do marker confirmou a execução controlada.

## 10. Detection Engineering no Wazuh

| Regra | Nível | Função |
|---|---:|---|
| `100260` | 8 | escrita do script via ADMIN$ |
| `100265` | 10 | serviço Case13 criado como LocalSystem |
| `100270` | 12 | cmd.exe executa script como SYSTEM |
| `100275` | 8 | marker criado |
| `100280` | 10 | Suricata indica command shell over SMB |
| `100285` | 13 | ADMIN$ transfer + service creation |
| `100290` | 15 | cadeia Windows até SYSTEM execution |
| `100295` | 15 | branch cross-agent endpoint-first |
| `100300` | 15 | branch cross-agent network-first |

Na execução oficial disparou `100300 — Level 15`.

A duplicidade `100295/100300` existe para tolerar variação na ordem de ingestão entre o agente `000/soc01` (Suricata) e o agente `002/WINSERVER2022` (Windows/Sysmon).

## 11. MITRE ATT&CK

### T1021.002 — SMB/Windows Admin Shares

Sustentado por TCP/445, ADMIN$, 5140/5145, Zeek SMB, 100260 e 100280.

### T1543.003 — Windows Service

Sustentado por Event ID 7045, criação do serviço e regras 61138/100265/100285.

### T1569.002 — Service Execution

Sustentado pela combinação de `CreateServiceW`, `StartServiceW`, execução posterior de `cmd.exe` como SYSTEM e correlação 100290/100300.

### T1059.003 — Windows Command Shell

Sustentado pelo Sysmon Event ID 1, `cmd.exe /c`, contexto SYSTEM e 100270/100300.

## 12. Timeline resumida

- `06:00:59Z` — script criado no WIN10.
- `06:01:16Z` — script chega ao servidor; Sysmon 11, 92200, 5145 e 100260.
- `06:01:47Z` — Zeek observa SCM/DCE-RPC; Suricata alerta; 7045.
- `06:01:48Z` — Wazuh 100285 Level 13.
- `06:02:13Z` — Zeek StartServiceW; Sysmon 1 mostra cmd.exe como SYSTEM; Sysmon 11 mostra marker.
- `06:02:14Z` — Wazuh 100300 Level 15 e 100275 Level 8.

## 13. Avaliação SOC

**Verdict: TRUE POSITIVE — CONTROLLED LAB SIMULATION**

Em produção, a combinação de ADMIN$ write, remote service creation, StartServiceW, SYSTEM cmd.exe e IDS corroboration justificaria investigação de alta prioridade.

## 14. Limitações

1. A sessão SMB foi reutilizada.
2. Não houve novo 4624 na execução final.
3. Sysmon não preencheu ParentImage.
4. PID 612 -> services.exe foi validado posteriormente.
5. Suricata sozinho indica apenas possibilidade.
6. O hash final do arquivo-fonte WIN10 não foi independentemente preservado no output fornecido.
7. O cenário foi autorizado e controlado.

## 15. Cleanup

WINSERVER2022:
- quatro serviços `SOC_CASE13_*` removidos;
- scripts remotos removidos;
- markers removidos;
- validação sem artefatos restantes.

WIN10:
- scripts locais removidos;
- sessão `IPC$` encerrada;
- `net use` sem entradas.

Foram mantidos Sysmon, auditoria de shares, ingestão 5145 e as regras `100260–100300`.

## Conclusão

O Case 13 validou uma cadeia de movimento lateral em múltiplas camadas:

**Windows Security + System + Sysmon + Zeek + Suricata + Wazuh**

O resultado principal foi uma detecção Level 15 baseada em correlação, e não em um único indicador.
