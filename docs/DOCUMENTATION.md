# linux-audit-json

Agente de auditoria Linux que coleta eventos do `auditd` em tempo real,
correlaciona registros, converte para JSON estruturado e encaminha para
múltiplos destinos simultaneamente.

**Versão atual:** 1.1.0

---

## Índice

1. [Visão geral](#1-visão-geral)
2. [Arquitetura](#2-arquitetura)
3. [Estrutura do projeto](#3-estrutura-do-projeto)
4. [Requisitos](#4-requisitos)
5. [Instalação](#5-instalação)
6. [Desinstalação](#6-desinstalação)
7. [Gerenciamento e operação](#7-gerenciamento-e-operação)
8. [Configuração](#8-configuração)
9. [Filtros](#9-filtros)
10. [Roteamento](#10-roteamento)
11. [Destinos de saída](#11-destinos-de-saída)
12. [Fila persistente em disco (spool)](#12-fila-persistente-em-disco-spool)
13. [Formato de saída JSON](#13-formato-de-saída-json)
14. [Segurança e hardening](#14-segurança-e-hardening)
15. [Política de descarte de eventos (lossy vs lossless)](#15-política-de-descarte-de-eventos-lossy-vs-lossless)
16. [Rotação de logs (logrotate)](#16-rotação-de-logs-logrotate)
17. [Modos de operação](#17-modos-de-operação)
18. [Diagnóstico e troubleshooting](#18-diagnóstico-e-troubleshooting)
19. [Testes](#19-testes)
20. [Roadmap](#20-roadmap)

---

## 1. Visão geral

O Linux Audit subsystem (`auditd`) gera eventos de segurança em baixo nível —
execuções de processos, acessos a arquivos, mudanças de credenciais, chamadas
de sistema. Esses eventos chegam em formato texto bruto, fragmentados em
múltiplos registros por evento, e são difíceis de consumir diretamente por
SIEMs e ferramentas de análise.

O **linux-audit-json** resolve isso atuando como um pipeline configurável:

```
Kernel
  └─ auditd
       └─ audispd (dispatcher interno do auditd)
            └─ linux-audit-json-plugin        ← processo filho, gerenciado pelo auditd
                    │
                    ▼
         [coleta → parse → correlação → filtros → roteamento]
                    │
          ┌─────────┼──────────┐
          ▼         ▼          ▼
      arquivo      TCP        UDP
      (NDJSON)   (SIEM)   (secundário)
                   │
              [spool em disco quando SIEM offline]
```

**Pipeline de processamento, em ordem:**

1. **Coleta** — recebe linhas brutas do auditd via stdin (plugin do audispd)
2. **Parse** — extrai campos estruturados, decodifica hex e campos enriquecidos
3. **Correlação** — agrupa registros do mesmo evento lógico pelo `event_id`
4. **Normalização** — produz um objeto JSON único por evento correlacionado
5. **Filtros** — aplica regras de drop/allow/tag configuráveis
6. **Roteamento** — despacha para um ou mais destinos conforme as rotas
7. **Envio** — grava em arquivo, envia por TCP (com spool) ou UDP

---

## 2. Arquitetura

### 2.1 Fluxo de dados

```
stdin (audispd)
      │
      ▼
  parser.py ──────────────────────────── AuditRecord
      │                                  (record_type, event_id,
      ▼                                   timestamp, fields, raw)
  correlator.py ──────────────────────── AuditEvent
      │           [RLock — thread-safe]   (event_id, host, records[],
      │                                   summary, config_hash, agent_id)
      ▼
  router.py
      │
      ├── FilterEngine (filters.py)
      │       ├── drop  → descartado para esta rota
      │       ├── allow → aceito
      │       └── tag   → tag adicionada, continua
      │
      └── outputs/
              ├── FileOutput   → NDJSON (640, fsync opcional, O_NOFOLLOW)
              ├── TcpOutput    → TCP assíncrono + spool em disco
              ├── UdpOutput    → UDP sem conexão
              └── (stdout bloqueado em produção)
```

### 2.2 Correlação de eventos

O Linux Audit emite múltiplos registros para um mesmo evento lógico.
Por exemplo, a execução de um comando gera:

```
type=SYSCALL   msg=audit(1700000000.123:4567): syscall=59 exe="/usr/bin/ls" ...
type=EXECVE    msg=audit(1700000000.123:4567): argc=2 a0="ls" a1="-la"
type=CWD       msg=audit(1700000000.123:4567): cwd="/home/usuario"
type=PATH      msg=audit(1700000000.123:4567): name="/usr/bin/ls"
type=PROCTITLE msg=audit(1700000000.123:4567): proctitle=6C73002D6C61
type=EOE       msg=audit(1700000000.123:4567):
```

O correlator agrupa todos pelo `event_id` (`4567`) e emite um único
`AuditEvent` ao receber `EOE`. Eventos sem `EOE` são emitidos por
timeout configurável (`event_timeout`). O correlator é thread-safe
(protegido por `RLock`) para uso simultâneo pelo loop principal e
pela thread de flush periódico.

### 2.3 Responsabilidade de cada módulo

| Módulo | Responsabilidade |
|--------|-----------------|
| `plugin.py` | Entrypoint do processo filho do audispd. Coordena módulos, gerencia sinais, injeta metadados de integridade em cada evento. |
| `main.py` | CLI administrativo: `validate`, `test`, `run` (modo file). |
| `parser.py` | Linhas brutas → `AuditRecord`. Decodifica hex, trata separador `0x1D`. |
| `correlator.py` | `AuditRecord` por `event_id` → `AuditEvent`. Thread-safe com `RLock`. |
| `filters.py` | Avalia filtros sobre `AuditEvent`. Retorna ação e nome do filtro. |
| `router.py` | Por rota: avalia filtros e despacha para destinos. Isola falhas. |
| `config_loader.py` | Lê, valida, computa SHA-256 e loga auditoria de filtros. |
| `models.py` | `AuditRecord`, `AuditEvent` com `config_hash` e `agent_id`. |
| `internal_logging.py` | Logger interno separado dos eventos coletados. |
| `outputs/file_output.py` | NDJSON com `640`, `O_NOFOLLOW`, `fsync` opcional. |
| `outputs/tcp_output.py` | TCP assíncrono com spool em disco e shutdown correto. |
| `outputs/udp_output.py` | UDP síncrono sem conexão. |

### 2.4 Threading

| Thread | Função |
|--------|--------|
| Principal | Lê stdin linha a linha (bloqueante por design) |
| `flush-loop` | Daemon — verifica eventos expirados por timeout periodicamente |
| `tcp-output-*` | Uma por destino TCP — fila assíncrona com spool em disco |

Falha em qualquer thread de output não afeta a thread principal nem outros outputs.

---

## 3. Estrutura do projeto

```
linux-audit-json/
│
├── agent/
│   ├── main.py                CLI: validate / test / run (modo file)
│   ├── plugin.py              Entrypoint do plugin audispd
│   ├── config_loader.py       Parse, validação, hash e auditoria de filtros
│   ├── parser.py              Parse de linhas brutas do auditd
│   ├── correlator.py          Correlação thread-safe por event_id
│   ├── filters.py             Motor de filtros (drop / allow / tag)
│   ├── router.py              Roteamento eventos → destinos
│   ├── models.py              AuditRecord, AuditEvent (com config_hash, agent_id)
│   ├── internal_logging.py    Log interno do agente
│   └── outputs/
│       ├── __init__.py
│       ├── file_output.py     NDJSON (640, O_NOFOLLOW, fsync)
│       ├── tcp_output.py      TCP + spool em disco + shutdown correto
│       ├── udp_output.py      UDP
│       └── stdout_output.py   Stdout (bloqueado em produção)
│
├── conf/
│   ├── agent.conf                        Configuração ativa (copiada para /etc)
│   ├── agent.conf.example                Referência imutável sempre atualizada
│   ├── linux-audit-json.conf.audispd     Plugin do audispd
│   └── linux-audit-json.logrotate        Configuração do logrotate
│
├── systemd/
│   └── linux-audit-json.service          Unit file (modo file — ver seção 17)
│
├── tests/
│   ├── test_parser.py
│   ├── test_correlator.py
│   ├── test_filters.py
│   └── test_security.py                  Concorrência, permissões, config maliciosa
│
├── install.sh                  Instalação completa
├── uninstall.sh                Remoção completa
├── cleanup-old-install.sh      Correção de instalação anterior
├── fix-auditd-queue.sh         Correção isolada do q_depth
├── CHANGELOG.md                Histórico de mudanças
├── requirements.txt
└── README.md
```

---

## 4. Requisitos

| Requisito | Versão mínima |
|-----------|--------------|
| Python | 3.11+ |
| Linux | qualquer distribuição com auditd |
| auditd | qualquer versão com suporte a plugins |
| systemd | qualquer versão (apenas para modo file) |
| acl | recomendado (para ACL em /var/log/audit) |

**Dependências Python:** nenhuma. Usa exclusivamente stdlib.

Distribuições testadas: Ubuntu 22.04+, Debian 12+, Rocky Linux 9+.

---

## 5. Instalação

### 5.1 Instalação limpa

```bash
git clone https://github.com/seu-org/linux-audit-json
cd linux-audit-json
sudo bash install.sh
```

**O que o `install.sh` faz:**

1. Verifica Python 3.11+
2. Cria usuário e grupo `audit-agent` (sistema, sem shell, sem home)
3. Configura ACL em `/var/log/audit` via `setfacl` (sem adicionar ao grupo `adm`)
4. Cria diretórios com permissões corretas:
   - `/opt/linux-audit-json/` — `755 root:root`
   - `/etc/linux-audit-json/` — `750 root:audit-agent`
   - `/var/log/linux-audit-json/` — `750 audit-agent:audit-agent`
5. Copia arquivos do agente para `/opt/linux-audit-json/`
6. Instala `/etc/linux-audit-json/agent.conf` (`640`) — apenas se não existir
7. Instala `/etc/linux-audit-json/agent.conf.example` (`640`) — sempre atualizado
8. Instala o `.service` systemd (desabilitado)
9. Cria os wrappers CLI:
   - `/usr/local/bin/linux-audit-json` — CLI administrativo
   - `/usr/local/bin/linux-audit-json-plugin` — processo filho do audispd
10. Instala `/etc/audit/plugins.d/linux-audit-json.conf`
11. Ajusta `q_depth = 10500` no `auditd.conf` e remove `disp_qos` deprecated
12. Instala logrotate em `/etc/logrotate.d/linux-audit-json`
13. Reinicia o auditd e confirma que o plugin subiu

### 5.2 Após a instalação

```bash
# 1. Edite a configuração
sudo nano /etc/linux-audit-json/agent.conf

# 2. Valide antes de aplicar
linux-audit-json validate

# 3. Aplique reiniciando o auditd
sudo systemctl restart auditd
```

### 5.3 Verificando

```bash
# Plugin deve aparecer como processo filho do auditd
sudo systemctl status auditd
# Esperado no CGroup:
#   ├─XXXXX /sbin/auditd
#   └─XXXXX python3.11 /opt/linux-audit-json/agent/plugin.py ...

# Verificar eventos chegando
sudo tail -f /var/log/linux-audit-json/events.ndjson

# Verificar log interno
sudo tail -f /var/log/linux-audit-json/agent.log
```

---

## 6. Desinstalação

```bash
sudo bash uninstall.sh
```

Pergunta individualmente antes de remover:
- Configuração em `/etc/linux-audit-json/`
- Logs em `/var/log/linux-audit-json/`
- Usuário e grupo `audit-agent`

Remove sem perguntar:
- Plugin do audispd
- Arquivos em `/opt/linux-audit-json/`
- Serviço systemd
- Wrappers CLI
- Linhas adicionadas ao `auditd.conf`
- Configuração do logrotate

O auditd continua rodando normalmente após a remoção.

---

## 7. Gerenciamento e operação

### 7.1 Modelo de processo

```
systemd
  └─ auditd.service     ← você gerencia este
       └─ plugin.py     ← o auditd gerencia automaticamente
```

O `linux-audit-json.service` está instalado mas **desabilitado** — é usado
apenas no modo `source=file`. Ver [seção 17](#17-modos-de-operação).

### 7.2 Comandos do dia a dia

```bash
# Status (plugin aparece no CGroup do auditd)
sudo systemctl status auditd

# Reiniciar plugin (após mudança de configuração)
sudo systemctl restart auditd

# Parar coleta completamente
sudo systemctl stop auditd

# Ver eventos em tempo real
sudo tail -f /var/log/linux-audit-json/events.ndjson

# Ver log interno do agente
sudo tail -f /var/log/linux-audit-json/agent.log

# Ver logs do auditd + plugin
sudo journalctl -u auditd -f

# Validar configuração (sem sudo)
linux-audit-json validate

# Desativar plugin sem parar auditd
sudo nano /etc/audit/plugins.d/linux-audit-json.conf
# active = no
sudo systemctl restart auditd
```

### 7.3 Aplicar mudanças na configuração

O agente não suporta reload em runtime (SIGHUP completo está no roadmap).

```bash
# 1. Valide
linux-audit-json validate

# 2. Reinicie (relança o plugin com nova config)
sudo systemctl restart auditd
```

O novo `config_hash` aparece no `agent.log` confirmando qual configuração está ativa.

### 7.4 Testar pipeline manualmente

```bash
cat << 'EOF' | linux-audit-json --conf /etc/linux-audit-json/agent.conf test
type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e syscall=59 success=yes exit=0 pid=2001 uid=0 auid=1001 comm="ls" exe="/usr/bin/ls"
type=PATH msg=audit(1700000000.123:4567): item=0 name="/usr/bin/ls" nametype=NORMAL
type=CWD msg=audit(1700000000.123:4567): cwd="/home/usuario"
type=PROCTITLE msg=audit(1700000000.123:4567): proctitle=6C73002D6C61
type=EOE msg=audit(1700000000.123:4567):
EOF
```

---

## 8. Configuração

O arquivo `/etc/linux-audit-json/agent.conf` usa formato INI estendido.

- Comentários: `#` ou `;`
- Seções com múltiplas instâncias: `[tipo:nome]`
- Restaurar padrão: `sudo cp /etc/linux-audit-json/agent.conf.example /etc/linux-audit-json/agent.conf`

### 8.1 `[options]`

```ini
[options]
flush_interval  = 1.0     # segundos entre verificações de timeout
queue_size      = 10000   # tamanho máximo das filas internas
retry_interval  = 5.0     # intervalo de retry para destinos remotos
worker_threads  = 2       # threads de worker (uso futuro)
hostname        = srv01   # override do hostname (padrão: nome real)
event_timeout   = 2.0     # timeout de correlação em segundos
```

### 8.2 `[source:nome]`

```ini
[source:default]
type = dispatcher   # dispatcher (stdin via audispd) ou file
# path = /var/log/audit/audit.log   # apenas quando type = file
```

### 8.3 `[parser]`

```ini
[parser]
preserve_raw     = yes   # inclui linha bruta no JSON
include_metadata = yes   # inclui host, versão, rota, config_hash
```

### 8.4 `[filter:nome]`

Ver [seção 9](#9-filtros).

### 8.5 `[destination:nome]`

Ver [seção 11](#11-destinos-de-saída).

### 8.6 `[route:nome]`

Ver [seção 10](#10-roteamento).

### 8.7 `[logging]`

```ini
[logging]
level        = INFO    # DEBUG | INFO | WARNING | ERROR
file         = /var/log/linux-audit-json/agent.log
use_journald = yes
```

O log interno registra: startup, shutdown, hash da config, auditoria de filtros,
erros de envio, reconexões, estatísticas finais. **Separado dos eventos coletados.**

### 8.8 `[security]`

```ini
[security]
user  = audit-agent
group = audit-agent
```

---

## 9. Filtros

Filtros são avaliados em ordem crescente de `priority`. Cada filtro define
**condições** (AND lógico) e uma **ação**.

### 9.1 Sintaxe

```ini
[filter:nome]
action       = drop        # drop | allow | tag
priority     = 10          # menor = avaliado primeiro
tag          = minha-tag   # obrigatório quando action = tag

record_types = SYSCALL, PATH
executables  = /usr/bin/ls
uids         = 0, 1000
auids        = 1001
paths        = /tmp, /proc
commands     = ls, cat
keywords     = passwd, shadow
regex        = \d+\.\d+\.\d+\.\d+
syscalls     = 59, 62
success      = yes          # yes | no
```

### 9.2 Ações

| Ação | Comportamento |
|------|--------------|
| `drop` | Descarta para a rota atual. Outras rotas não são afetadas. |
| `allow` | Aceita explicitamente. Útil para exceções antes de um `drop` mais amplo. |
| `tag` | Adiciona tag ao evento e continua. Não descarta. |

### 9.3 Auditoria de filtros

**Toda alteração de filtros é registrada.** No startup, o agente loga:
- Quais filtros estão ativos
- Priority, action e condições de cada filtro
- SHA-256 do `agent.conf` ativo

Isso permite detectar mudanças não autorizadas na configuração de filtragem.
Cada evento JSON carrega o `config_hash` do momento da coleta.

> ⚠️ **Atenção:** Filtros `drop` reduzem o volume enviado ao SIEM.
> Um filtro `drop` em `record_types = SYSCALL` oculta execução de processos.
> Use com critério e documente a justificativa operacional de cada filtro.

### 9.4 Exemplos

```ini
# Ignora o próprio agente
[filter:ignore-agent]
action      = drop
priority    = 10
executables = /usr/bin/python3.11

# Ignora CWD isolado
[filter:ignore-cwd]
action       = drop
priority     = 20
record_types = CWD

# Exceção: aceita root mesmo em /tmp
[filter:allow-root-tmp]
action   = allow
priority = 25
uids     = 0
paths    = /tmp

# Descarta operações ok em /tmp para todos os outros
[filter:drop-tmp-ok]
action   = drop
priority = 30
paths    = /tmp
success  = yes

# Tag autenticação
[filter:tag-auth]
action       = tag
priority     = 50
tag          = auth
record_types = USER_AUTH USER_LOGIN USER_LOGOUT
```

---

## 10. Roteamento

Uma rota associa filtros a destinos. Um evento pode passar por múltiplas rotas.

```ini
[route:nome]
source       = default
filters      = filtro1, filtro2
destinations = destino1, destino2
```

**Isolamento de falhas:** falha em um destino não impede envio para os demais.

### Exemplos

```ini
# Tudo (exceto ruído) → arquivo local
[route:all-to-file]
source       = default
filters      = ignore-agent, ignore-cwd, drop-tmp-ok
destinations = local-file

# Críticos e auth → SIEM TCP
[route:security-to-siem]
source       = default
filters      = tag-critical, tag-auth
destinations = siem-tcp
```

---

## 11. Destinos de saída

### 11.1 Arquivo local (NDJSON)

```ini
[destination:local-file]
type  = file
path  = /var/log/linux-audit-json/events.ndjson
fsync = no    # yes = fsync após cada evento (durabilidade vs performance)
```

**Detalhes de implementação:**
- Arquivo criado com permissão `640` (audit-agent:audit-agent)
- Abertura com `O_NOFOLLOW` — rejeita symlinks no caminho final
- `fsync = yes` garante que nenhum evento seja perdido em crash do processo.
  Tem custo de I/O por evento — recomendado em ambientes críticos de baixo volume.
  Para alto volume, use `fsync = no` e confie no buffer do SO.
- Compatível com logrotate (reabre o arquivo automaticamente após rotação)

### 11.2 TCP

```ini
[destination:siem-tcp]
type           = tcp
host           = 10.10.10.50
port           = 5140
timeout        = 5.0
retries        = 3
retry_interval = 5.0
spool_dir      = /var/log/linux-audit-json/spool   # opcional
spool_max_mb   = 100
```

Ver [seção 12](#12-fila-persistente-em-disco-spool) para detalhes do spool.

### 11.3 UDP

```ini
[destination:secondary-udp]
type    = udp
host    = 192.168.1.20
port    = 5514
timeout = 2.0
```

UDP não garante entrega. Adequado para ambientes de alta performance onde
perda eventual é aceitável. Sem fila — falhou, evento descartado.

### 11.4 Stdout (bloqueado em produção)

O tipo `stdout` com `enabled = yes` é **rejeitado** pelo validador de
configuração. Impede vazamento de dados de auditoria para terminal, pipe
ou journald sem controle.

Para testes manuais, use o modo CLI:
```bash
echo "tipo=SYSCALL ..." | linux-audit-json test
```

---

## 12. Fila persistente em disco (spool)

O spool resolve o problema de perda de eventos quando o SIEM está offline.

### Sem spool (comportamento padrão)

```
SIEM offline → fila em memória enche (5000 eventos) → eventos descartados
processo reinicia → fila zera → todos os eventos do período perdidos
```

### Com spool habilitado

```
SIEM offline → fila em memória → spool em disco (append-only)
SIEM volta   → replay automático do spool → spool limpo após confirmação
processo reinicia → lê spool do disco → nenhum evento perdido
```

### Configuração

```ini
[destination:siem-tcp]
type         = tcp
host         = 10.10.10.50
port         = 5140
spool_dir    = /var/log/linux-audit-json/spool
spool_max_mb = 100    # limite de tamanho (padrão: 100MB)
```

### Comportamento detalhado

- O spool é um arquivo binário append-only por destino TCP
- Permissão `640`, diretório `750`
- Quando o TCP volta, a thread de envio tenta replay antes de processar novos eventos
- Replay parcial: apenas eventos que falharem no reenvio permanecem no spool
- Quando o spool atinge `spool_max_mb`, novos eventos são descartados com log de erro
- O spool não é comprimido — monitore o tamanho se o SIEM ficar offline por longos períodos

### Monitoramento do spool

```bash
# Ver tamanho do spool
ls -lh /var/log/linux-audit-json/spool/

# Ver log de replay
grep "replay\|spool" /var/log/linux-audit-json/agent.log
```

---

## 13. Formato de saída JSON

Cada evento é emitido como uma linha JSON (NDJSON).

### Estrutura completa

```json
{
  "event_id": "4567",
  "timestamp": 1700000000.123,
  "host": "meu-servidor",
  "record_types": ["SYSCALL", "PATH", "CWD", "PROCTITLE"],
  "summary": {
    "syscall": "59",
    "success": "yes",
    "pid": "2001",
    "uid": "0",
    "auid": "1001",
    "comm": "ls",
    "exe": "/usr/bin/ls",
    "filepath": "/usr/bin/ls",
    "cwd": "/home/usuario",
    "proctitle": "ls -la",
    "cmdline": "ls -la"
  },
  "records": [
    {
      "type": "SYSCALL",
      "fields": { "arch": "c000003e", "syscall": "59", "success": "yes", "..." : "..." },
      "raw": "type=SYSCALL msg=audit(1700000000.123:4567): ..."
    }
  ],
  "tags": ["critical"],
  "route_name": "all-to-file",
  "filter_name": "",
  "collector_version": "1.1.0",
  "config_hash": "a3f1b2c4d5e6...",
  "agent_id": "meu-servidor@1.1.0"
}
```

### Campos do objeto raiz

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `event_id` | string | ID do evento no auditd |
| `timestamp` | float | Unix timestamp do primeiro registro |
| `host` | string | Hostname do sistema |
| `record_types` | array | Tipos de registro presentes |
| `summary` | object | Campos de alto valor extraídos automaticamente |
| `records` | array | Todos os registros correlacionados |
| `tags` | array | Tags aplicadas pelos filtros |
| `route_name` | string | Última rota que processou o evento |
| `filter_name` | string | Filtro que casou (se aplicável) |
| `collector_version` | string | Versão do agente |
| `config_hash` | string | SHA-256 do `agent.conf` ativo na coleta |
| `agent_id` | string | `hostname@versão` do coletor |

### Decodificações automáticas

| Situação | Antes | Depois |
|----------|-------|--------|
| Campos hex | `proctitle=6C73002D6C61` | `"proctitle": "ls -la"` |
| Null bytes (argv) | `ls\x00-la` | `"ls -la"` |
| Campos enriquecidos `0x1D` | `res=success\x1dUID="osboxes"` | `"UID": "osboxes"` |

---

## 14. Segurança e hardening

### 14.1 Princípio do menor privilégio

O plugin roda como `audit-agent`:
- Usuário de sistema (sem shell `/usr/sbin/nologin`, sem home)
- Não adicionado ao grupo `adm` — ACL específica em `/var/log/audit`
- Acesso de escrita apenas em `/var/log/linux-audit-json/`
- Leitura em `/etc/linux-audit-json/` e `/opt/linux-audit-json/`

### 14.2 Permissões de arquivos

| Caminho | Permissão | Dono |
|---------|-----------|------|
| `/etc/linux-audit-json/` | `750` | `root:audit-agent` |
| `/etc/linux-audit-json/agent.conf` | `640` | `root:audit-agent` |
| `/etc/linux-audit-json/agent.conf.example` | `640` | `root:audit-agent` |
| `/var/log/linux-audit-json/` | `750` | `audit-agent:audit-agent` |
| `/var/log/linux-audit-json/events.ndjson` | `640` | `audit-agent:audit-agent` |
| `/var/log/linux-audit-json/spool/` | `750` | `audit-agent:audit-agent` |
| `/opt/linux-audit-json/` | `755` | `root:root` |
| `/opt/linux-audit-json/agent/*.py` | `644` | `root:root` |
| `/usr/local/bin/linux-audit-json*` | `755` | `root:root` |

O diretório `/etc/linux-audit-json/` usa `750` (não `755`) — usuários sem
privilégio não podem listar nem ler a configuração, que contém IPs de SIEM,
estrutura de filtros e rotas.

### 14.3 Validação de configuração

O `config_loader` rejeita:
- Destino `stdout` com `enabled = yes`
- Caminhos de saída fora de `/var/log/`, `/tmp/`, `/opt/linux-audit-json/`
- Caminhos de log fora de `/var/log/`, `/tmp/`
- Actions de filtro inválidas
- Destinos TCP/UDP sem host ou com porta inválida
- Rotas referenciando filtros ou destinos não definidos

### 14.4 Proteções no FileOutput

- Abertura com `O_NOFOLLOW` — rejeita symlinks no arquivo final
- Arquivo criado com `O_CREAT | O_APPEND` — sem truncamento
- Permissão `640` forçada via `os.chmod` mesmo em arquivos preexistentes
- `fsync` opcional para durabilidade em crash

### 14.5 Integridade da configuração

A cada startup o agente:
1. Computa SHA-256 do `agent.conf`
2. Loga o hash no `agent.log`
3. Inclui o hash em cada evento JSON (`config_hash`)
4. Loga todos os filtros ativos com condições

Isso permite:
- Detectar quando a configuração foi alterada (hash muda)
- Correlacionar eventos com a configuração vigente na época
- Auditar filtros ativos em qualquer momento histórico via os logs

### 14.6 Hardening do unit systemd (modo file)

```ini
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
```

### 14.7 Proteções no código

- Sem `eval`, `exec` ou `shell=True`
- Entradas tratadas como não confiáveis (parsing defensivo com regex)
- Exceções capturadas por destino — erro em um não propaga para outros
- Logs internos não expõem dados sensíveis dos eventos coletados

---

## 15. Política de descarte de eventos (lossy vs lossless)

Esta seção documenta uma decisão arquitetural importante sobre o comportamento
do sistema quando a fila entre o auditd e o plugin está cheia.

### O parâmetro `disp_qos`

O parâmetro `disp_qos` do `auditd.conf` controlava o comportamento de descarte.
**Ele foi removido nas versões recentes do auditd** e não deve ser usado —
o instalador remove automaticamente qualquer ocorrência desse parâmetro para
evitar o aviso `"disp_qos option is deprecated"`.

O comportamento atual do auditd é equivalente ao modo **lossy**: se a fila
para o plugin estiver cheia, eventos são descartados pelo auditd.

### Lossy (comportamento atual)

```
Fila cheia → auditd descarta o evento → kernel não é bloqueado
```

**Vantagens:**
- O sistema operacional nunca trava esperando o plugin processar
- Performance previsível sob qualquer carga
- Recomendado pela Red Hat para produção

**Desvantagens:**
- Perda de eventos em picos de volume (especialmente no boot)
- Em ambiente de segurança crítico, evento perdido = evidência perdida

**Mitigação implementada:**
- `q_depth = 10500` (padrão do auditd é 2000) — aumentado pelo instalador
- Spool em disco no TCP — recupera eventos após queda do SIEM
- `fsync = yes` no arquivo local — garante durabilidade dos eventos gravados

### Lossless (alternativa não recomendada para produção)

```
Fila cheia → auditd bloqueia → kernel aguarda o plugin processar
```

**Vantagem:** nenhum evento perdido.

**Desvantagem crítica:** se o plugin Python travar ou ficar lento, o kernel
inteiro fica bloqueado aguardando. Em produção, isso pode derrubar o sistema.
Por isso o modo lossless **não é recomendado** para uso geral.

### Referências

- `man auditd.conf` — documentação oficial dos parâmetros
- [Red Hat Security Hardening Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) — recomenda lossy para produção
- [linux-audit documentation](https://github.com/linux-audit/audit-documentation) — documentação do projeto

### Recomendação

Para ambientes de segurança onde perda zero é obrigatória:
1. Aumente `q_depth` conforme o volume do ambiente (ex: `q_depth = 50000`)
2. Habilite o spool em disco para todos os destinos TCP
3. Use `fsync = yes` no destino de arquivo local
4. Monitore ativamente `grep "dropping event" /var/log/audit/audit.log`

---

## 16. Rotação de logs (logrotate)

O instalador configura logrotate automaticamente em `/etc/logrotate.d/linux-audit-json`.

### Política padrão

| Arquivo | Frequência | Retenção | Compressão |
|---------|-----------|----------|------------|
| `events.ndjson` | Diária | 7 dias | gzip (com delay de 1 dia) |
| `agent.log` | Semanal | 4 semanas | gzip (com delay de 1 dia) |

Novos arquivos são criados com permissão `640 audit-agent:audit-agent`.

### Testando a configuração

```bash
# Simula rotação sem executar
sudo logrotate -d /etc/logrotate.d/linux-audit-json

# Força rotação imediata
sudo logrotate -f /etc/logrotate.d/linux-audit-json

# Verifica arquivos rotacionados
ls -lh /var/log/linux-audit-json/
```

### Compatibilidade com o agente

No modo `source=file`, o agente detecta rotação automaticamente monitorando
o inode do arquivo. Quando o inode muda (logrotate criou novo arquivo),
o agente reabre o arquivo sem intervenção manual.

No modo `source=dispatcher` (plugin), o logrotate atua apenas no arquivo de
saída `events.ndjson`. O `FileOutput` reabre o arquivo na próxima escrita
após a rotação.

---

## 17. Modos de operação

### 17.1 Modo plugin (padrão, recomendado)

**Configuração:** `source.type = dispatcher`

O plugin roda como processo filho do audispd. O auditd gerencia o ciclo
de vida — lança na inicialização, relança se morrer.

**Gerenciamento:** `sudo systemctl restart auditd`

**Quando usar:** sempre que possível. Mais eficiente e com menor latência.

### 17.2 Modo file (alternativo)

**Configuração:** `source.type = file` + `path = /var/log/audit/audit.log`

O agente lê o arquivo em modo tail contínuo com detecção de rotação.

**Gerenciamento:** `sudo systemctl start/stop/restart linux-audit-json`

**Quando usar:** quando não é possível configurar plugins no audispd.

**Para ativar:**
```bash
# 1. Edite agent.conf: type = file
# 2. Desative o plugin: active = no em /etc/audit/plugins.d/linux-audit-json.conf
sudo systemctl restart auditd
# 3. Habilite o serviço
sudo systemctl enable --now linux-audit-json
```

**Nota:** ao iniciar, o agente posiciona no fim do arquivo (não reprocessa histórico).

---

## 18. Diagnóstico e troubleshooting

### Plugin não aparece no status do auditd

```bash
# Verifica o arquivo de plugin
sudo cat /etc/audit/plugins.d/linux-audit-json.conf
# active deve ser "yes"

# Testa o wrapper diretamente
echo "" | sudo /usr/local/bin/linux-audit-json-plugin \
    --conf /etc/linux-audit-json/agent.conf 2>&1 | head -5

# Verifica se há erro de Python
sudo journalctl -u auditd --no-pager | grep -i "python\|plugin\|error"
```

### "queue to plugins is full - dropping event"

```bash
# Aumenta q_depth
sudo bash fix-auditd-queue.sh

# Ou manualmente
sudo nano /etc/audit/auditd.conf
# q_depth = 50000
sudo systemctl restart auditd
```

### Nenhum evento no arquivo de saída

```bash
# Verifica permissões
sudo ls -la /var/log/linux-audit-json/

# Verifica erros no log
sudo tail -50 /var/log/linux-audit-json/agent.log

# Gera evento e aguarda
ls /tmp
sudo tail -f /var/log/linux-audit-json/events.ndjson
```

### Verificar config_hash ativo

```bash
# No log do agente
grep "config_hash\|SHA-256\|Configuração carregada" \
    /var/log/linux-audit-json/agent.log | tail -5

# Em eventos recentes
sudo tail -1 /var/log/linux-audit-json/events.ndjson \
    | python3.11 -c "import json,sys; e=json.load(sys.stdin); print(e['config_hash'])"
```

### Verificar filtros ativos

```bash
grep "Filtros carregados\|\[0" /var/log/linux-audit-json/agent.log | tail -20
```

### Spool TCP acumulando

```bash
# Ver tamanho
ls -lh /var/log/linux-audit-json/spool/

# Ver log de erros de conexão
grep "TcpOutput\|spool\|replay\|conectar" \
    /var/log/linux-audit-json/agent.log | tail -20

# Testar conectividade com o SIEM
nc -zv 10.10.10.50 5140
```

### Erro de permissão ao rodar validate

```bash
# Verifica permissão do diretório
ls -la /etc/ | grep linux-audit
# Deve ser drwxr-x--- (750)

# O usuário deve ser membro do grupo audit-agent para acesso
# Ou usar sudo para acessar como root
sudo linux-audit-json validate
```

### Estatísticas do agente

```bash
# Últimas estatísticas registradas no log
grep "Estatísticas\|encerrado" /var/log/linux-audit-json/agent.log | tail -5
# Exemplo: recebidos=1423 enviados=1187 descartados=236 erros=0

# Via journald
sudo journalctl -u auditd | grep "Estatísticas"
```

---

## 19. Testes

```bash
# Testes funcionais
python3.11 tests/test_parser.py
python3.11 tests/test_correlator.py
python3.11 tests/test_filters.py

# Testes de segurança e concorrência
python3.11 tests/test_security.py

# Com pytest
pip install pytest
pytest tests/ -v
```

### Cobertura dos testes de segurança

| Teste | O que verifica |
|-------|---------------|
| `test_correlator_thread_safety` | 100 eventos em 3 threads simultâneas sem erros |
| `test_correlator_no_duplicate_flush` | Evento não emitido duas vezes (EOE + timeout) |
| `test_stdout_blocked_in_production` | `stdout` ativo rejeitado pelo validador |
| `test_dangerous_path_rejected` | Caminhos fora dos prefixos permitidos rejeitados |
| `test_safe_path_allowed` | Caminhos em `/var/log/` aceitos |
| `test_invalid_filter_action_rejected` | Action inválida em filtro rejeitada |
| `test_config_hash_computed` | SHA-256 do conf computado e com 64 chars |
| `test_file_output_permissions` | Arquivo criado com permissão `640` |
| `test_file_output_concurrent_writes` | 200 eventos em 4 threads sem corrupção |

---

## 20. Roadmap

### [1.2.0] — previsto

- [ ] TLS para saída TCP (validação de CA, mTLS opcional)
- [ ] Reload de configuração sem restart (SIGHUP com staging e rollback)
- [ ] Output HTTP/HTTPS (webhooks, Elasticsearch)
- [ ] Métricas Prometheus

### [1.3.0] — previsto

- [ ] Compressão do spool e do envio TCP
- [ ] Templates de output (formatos alternativos)
- [ ] Suporte a formato syslog (RFC 5424)
- [ ] CLI de diagnóstico em tempo real (`linux-audit-json status`)
- [ ] Pacotes `.deb` e `.rpm`
