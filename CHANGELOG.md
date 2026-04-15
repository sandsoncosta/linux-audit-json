# Changelog — linux-audit-json

Todas as mudanças significativas são documentadas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).

---
## [1.1.0] — 2026-03-25

### Segurança

- **Lock no correlator (crítico):** `Correlator` era explicitamente não thread-safe,
  mas era acessado simultaneamente pelo loop principal e pela thread de flush periódico.
  Adicionado `threading.RLock` em `feed()`, `flush_expired()`, `pending_count()` e
  `_flush()`. Elimina race condition, perda de eventos e estado inconsistente sob carga.

- **stdout bloqueado em produção:** Destino `type = stdout` com `enabled = yes` agora
  é rejeitado pelo `config_loader` na validação. Impede vazamento de dados de auditoria
  para terminal, pipe ou journald sem controle. Para testes: `linux-audit-json test`.

- **Permissões endurecidas:**
  - `/etc/linux-audit-json/` alterado de `755` para `750` (root:audit-agent)
  - `agent.conf` e `agent.conf.example` alterados de `644` para `640`
  - Arquivos de saída `events.ndjson` criados com permissão `640` (audit-agent:audit-agent)
  - Spool TCP criado com permissão `640` e diretório `750`

- **Grupo adm removido:** O usuário `audit-agent` não é mais adicionado ao grupo `adm`.
  Substituído por ACL específica via `setfacl` em `/var/log/audit` quando disponível.
  Reduz superfície de acesso do processo a arquivos do sistema.

- **Validação de caminhos:** `config_loader` agora valida que caminhos de saída
  (`destination.path`, `spool_dir`) e de log (`logging.file`) estão dentro de
  prefixos permitidos (`/var/log/`, `/tmp/`, `/opt/linux-audit-json/`).
  Impede que config maliciosa aponte saídas para `/etc/shadow`, `/proc` etc.

- **Proteção contra symlink no FileOutput:** Abertura de arquivo usa `O_NOFOLLOW`
  (onde disponível) para rejeitar symlinks no caminho final do arquivo de saída.

### Confiabilidade

- **Fila persistente em disco (TCP spool):** `TcpOutput` agora suporta spool
  append-only em disco quando `spool_dir` está configurado no destino.
  - Eventos que não podem ser enviados (SIEM offline, fila em memória cheia)
    são gravados no spool em vez de descartados
  - Replay automático quando a conexão TCP é restaurada
  - Replay parcial: apenas eventos com falha de reenvio permanecem no spool
  - Limite de tamanho configurável (`spool_max_mb`, padrão 100MB)
  - Spool é arquivo binário append-only com permissão `640`

- **Shutdown correto do TcpOutput:** `close()` usava `put_nowait(_SENTINEL)` que
  lançava `queue.Full` silenciosamente se a fila estivesse cheia, travando o
  `thread.join()` indefinidamente. Substituído por `put(_SENTINEL, timeout=5.0)`
  com log de aviso em caso de timeout.

- **fsync configurável no FileOutput:** Novo parâmetro `fsync = yes/no` por destino.
  Quando ativo, força escrita imediata em disco após cada evento via `os.fsync()`.
  Garante que nenhum evento seja perdido em crash do processo. Padrão: `no`
  (balance entre performance e durabilidade — configure `yes` em ambientes críticos).

### Observabilidade

- **Hash da configuração:** `config_loader` computa SHA-256 do `agent.conf` no
  startup e registra no log interno. Hash muda se o arquivo for alterado,
  permitindo detectar mudanças de configuração em produção.

- **Auditoria de filtros:** No startup, todos os filtros carregados são registrados
  no log interno com nome, priority, action e condições. Cria rastreabilidade de
  quais regras de filtragem estavam ativas em cada momento.

- **Metadados de integridade em cada evento:** Cada evento JSON agora inclui:
  - `config_hash`: SHA-256 do `agent.conf` ativo no momento da coleta
  - `agent_id`: `hostname@versão` do coletor
  - `collector_version`: atualizado para `1.1.0`

### Correções

- **Bug no build_summary (EXECVE):** `f["a{i}"]` (string literal) substituído
  por `f[f"a{i}"]` (f-string). Campos `a0`, `a1`, `a2`... agora são corretamente
  extraídos para o `summary.cmdline`.

- **disp_qos deprecated:** O instalador adicionava `disp_qos = lossy` no
  `auditd.conf`, causando o aviso `"disp_qos option is deprecated"` em versões
  recentes do auditd. O instalador agora remove essa linha se presente.

### Infraestrutura

- **Logrotate:** Adicionado arquivo de configuração do logrotate
  (`conf/linux-audit-json.logrotate`) instalado em `/etc/logrotate.d/`:
  - `events.ndjson`: rotação diária, 7 dias de retenção, compressão gzip
  - `agent.log`: rotação semanal, 4 semanas de retenção, compressão gzip
  - Permissão `640` preservada nos novos arquivos após rotação

- **Testes de segurança:** Nova suíte `tests/test_security.py` cobrindo:
  - Concorrência no correlator (100 eventos em 3 threads simultâneas)
  - Ausência de flush duplicado (EOE + timeout para o mesmo evento)
  - Rejeição de stdout em produção
  - Rejeição de caminhos perigosos
  - Validação de caminhos seguros
  - Rejeição de action inválida em filtro
  - Cálculo e presença do config_hash
  - Permissão 640 no arquivo de saída
  - Escrita concorrente sem corrupção (200 eventos, 4 threads)

---

## [1.0.0] — 2026-03-25 (versão inicial)

### Funcionalidades implementadas

- **Coleta via plugin do audispd:** Processo filho do auditd, lê stdin.
  Gerenciado automaticamente pelo auditd — sem necessidade de serviço systemd separado.

- **Parser de linhas do auditd:**
  - Extrai tipo, timestamp, event_id e campos chave=valor
  - Decodifica campos hex (`proctitle`, `comm`, `exe`, `cwd`, `name`, `a0`–`a3`)
  - Trata separador GS (`0x1D`) de campos enriquecidos (`UID=`, `AUID=`)
  - Substitui null bytes em `proctitle` por espaços (reconstrução do argv)

- **Correlação de eventos:** Agrupa registros pelo `event_id`. Emite evento
  completo ao receber `EOE` ou por timeout configurável (`event_timeout`).
  Extrai `summary` com campos de alto valor por tipo de registro.

- **Filtros configuráveis:** Motor de filtros com suporte a condições AND,
  ações drop/allow/tag, prioridade e encadeamento. Avaliado por rota.

- **Roteamento:** Associação filtros → destinos. Um evento pode passar por
  múltiplas rotas. Falha em um destino não afeta os demais.

- **Destinos de saída:**
  - `file`: NDJSON local com escrita thread-safe e lock interno
  - `tcp`: envio assíncrono com thread dedicada, fila em memória, reconexão automática
  - `udp`: envio síncrono sem conexão
  - `stdout`: disponível apenas para testes (bloqueado em produção na v1.1.0)

- **Modo file (alternativo):** Leitura de `/var/log/audit/audit.log` em modo
  tail contínuo com detecção de rotação por inode.

- **Configuração via agent.conf:** Formato INI estendido com seções nomeadas.
  Validação completa antes da inicialização. Suporte a múltiplos filtros,
  destinos e rotas.

- **Log interno:** Logger separado dos eventos coletados. Nível configurável,
  saída para arquivo e/ou journald.

- **Serviço systemd (modo file):** Unit file com hardening completo
  (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`
  e outros). Instalado desabilitado — não necessário no modo plugin.

- **Scripts de instalação:**
  - `install.sh`: instalação completa em sistema limpo
  - `uninstall.sh`: remoção completa com confirmações interativas
  - `cleanup-old-install.sh`: correção de instalação anterior problemática
  - `fix-auditd-queue.sh`: correção isolada do q_depth

- **Testes unitários:** `test_parser.py`, `test_correlator.py`, `test_filters.py`

---

## Roadmap

### [1.2.0] — previsto

- [ ] TLS para saída TCP (validação de CA, mTLS opcional)
- [ ] Reload de configuração sem restart (SIGHUP completo com rollback)
- [ ] Output HTTP/HTTPS
- [ ] Métricas Prometheus

### [1.3.0] — previsto

- [ ] Compressão de eventos no spool e no envio TCP
- [ ] Templates de output (formatos alternativos)
- [ ] Suporte a formato syslog (RFC 5424)
- [ ] CLI de diagnóstico em tempo real (`linux-audit-json status`)
- [ ] Pacotes `.deb` e `.rpm`
