# Windows Authentication Monitoring

## Objetivo

Implementar e validar detecções de falhas de autenticação no Windows utilizando:

- Windows Security Event Log
- Wazuh
- Regras nativas
- Regras customizadas
- MITRE ATT&CK

O objetivo principal foi diferenciar:

1. falha individual de logon;
2. múltiplas falhas originadas do mesmo IP;
3. password guessing direcionado contra a mesma conta.

---

## Evento principal

O evento utilizado foi:

```text
Event ID 4625
An account failed to log on
