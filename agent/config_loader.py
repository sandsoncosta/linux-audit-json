"""
config_loader.py — Carrega, valida e computa hash do arquivo agent.conf.

Formato: INI estendido com seções nomeadas.
Sintaxe de seção: [tipo:nome]  ou  [tipo]
Comentários: linhas iniciadas com # ou ;
"""

import configparser
import hashlib
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from internal_logging import log


# ---------------------------------------------------------------------------
# Diretórios permitidos para caminhos de saída e log
# Impede que config maliciosa aponte para /etc/shadow, /proc etc.
# ---------------------------------------------------------------------------
_ALLOWED_OUTPUT_PREFIXES = (
    "/var/log/",
    "/tmp/",          # apenas para dev/test
    "/opt/linux-audit-json/",
)

_ALLOWED_LOG_PREFIXES = (
    "/var/log/",
    "/tmp/",
)


# ---------------------------------------------------------------------------
# Estruturas de configuração
# ---------------------------------------------------------------------------

@dataclass
class OptionsConfig:
    flush_interval: float = 1.0
    queue_size:     int   = 10000
    retry_interval: float = 5.0
    worker_threads: int   = 2
    hostname:       str   = field(default_factory=socket.gethostname)
    event_timeout:  float = 2.0


@dataclass
class SourceConfig:
    name: str = "default"
    type: str = "dispatcher"
    path: str = "/var/run/audispd_events"


@dataclass
class ParserConfig:
    preserve_raw:     bool = True
    include_metadata: bool = True


@dataclass
class FilterConfig:
    name:         str       = ""
    action:       str       = "drop"
    priority:     int       = 100
    record_types: list[str] = field(default_factory=list)
    executables:  list[str] = field(default_factory=list)
    uids:         list[str] = field(default_factory=list)
    auids:        list[str] = field(default_factory=list)
    paths:        list[str] = field(default_factory=list)
    commands:     list[str] = field(default_factory=list)
    keywords:     list[str] = field(default_factory=list)
    regex:        list[str] = field(default_factory=list)
    syscalls:     list[str] = field(default_factory=list)
    success:      str | None = None
    tag:          str        = ""


@dataclass
class DestinationConfig:
    name:           str   = ""
    type:           str   = "file"
    enabled:        bool  = True
    path:           str   = "/var/log/linux-audit-json/events.ndjson"
    host:           str   = ""
    port:           int   = 0
    timeout:        float = 5.0
    retries:        int   = 3
    retry_interval: float = 5.0
    fsync:          bool  = False   # força fsync após cada escrita (file)
    # fila persistente em disco para TCP
    spool_dir:      str   = ""      # diretório do spool; vazio = desabilitado
    spool_max_mb:   int   = 100     # tamanho máximo do spool em MB


@dataclass
class RouteConfig:
    name:         str       = ""
    source:       str       = "default"
    filters:      list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)


@dataclass
class LoggingConfig:
    level:        str  = "INFO"
    file:         str  = "/var/log/linux-audit-json/agent.log"
    use_journald: bool = False


@dataclass
class SecurityConfig:
    user:  str = "audit-agent"
    group: str = "audit-agent"


@dataclass
class AgentConfig:
    options:      OptionsConfig                  = field(default_factory=OptionsConfig)
    source:       SourceConfig                   = field(default_factory=SourceConfig)
    parser:       ParserConfig                   = field(default_factory=ParserConfig)
    filters:      dict[str, FilterConfig]        = field(default_factory=dict)
    destinations: dict[str, DestinationConfig]   = field(default_factory=dict)
    routes:       list[RouteConfig]              = field(default_factory=list)
    logging:      LoggingConfig                  = field(default_factory=LoggingConfig)
    security:     SecurityConfig                 = field(default_factory=SecurityConfig)
    config_hash:  str                            = ""   # preenchido pelo loader


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_list(value: str) -> list[str]:
    items = re.split(r"[,\s]+", value.strip())
    return [i for i in items if i]


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("yes", "true", "1", "on")


def _compute_file_hash(path: Path) -> str:
    """Retorna SHA-256 hex do conteúdo do arquivo."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_safe_path(path_str: str, allowed_prefixes: tuple) -> bool:
    """Verifica se o caminho está dentro dos prefixos permitidos."""
    try:
        p = Path(path_str).resolve()
        return any(str(p).startswith(prefix) for prefix in allowed_prefixes)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ConfigLoader
# ---------------------------------------------------------------------------

class ConfigLoader:
    """Carrega, valida e computa hash do agent.conf."""

    def __init__(self, conf_path: str):
        self.conf_path = Path(conf_path)
        self._raw: dict[str, dict] = {}

    def load(self) -> AgentConfig:
        """Lê, valida e retorna AgentConfig. Lança ValueError em erros."""
        if not self.conf_path.exists():
            raise FileNotFoundError(
                f"Arquivo de configuração não encontrado: {self.conf_path}"
            )

        self._read_raw()
        cfg = self._build_config()
        self._validate(cfg)

        # Computa e registra o hash da configuração ativa
        cfg.config_hash = _compute_file_hash(self.conf_path)
        log.info(
            "Configuração carregada. SHA-256: %s  arquivo: %s",
            cfg.config_hash[:16] + "...",
            self.conf_path,
        )
        self._log_filter_summary(cfg)
        return cfg

    # ------------------------------------------------------------------
    # Leitura
    # ------------------------------------------------------------------

    def _read_raw(self) -> None:
        parser = configparser.RawConfigParser(
            comment_prefixes=("#", ";"),
            inline_comment_prefixes=("#",),
            strict=False,
        )
        parser.read(str(self.conf_path), encoding="utf-8")
        for section in parser.sections():
            self._raw[section] = dict(parser[section])

    # ------------------------------------------------------------------
    # Construção
    # ------------------------------------------------------------------

    def _build_config(self) -> AgentConfig:
        cfg = AgentConfig()
        for section, values in self._raw.items():
            sec_lower = section.lower()
            if sec_lower == "options":
                cfg.options = self._build_options(values)
            elif sec_lower.startswith("source"):
                cfg.source = self._build_source(section, values)
            elif sec_lower == "parser":
                cfg.parser = self._build_parser(values)
            elif sec_lower.startswith("filter:"):
                name = section.split(":", 1)[1].strip()
                cfg.filters[name] = self._build_filter(name, values)
            elif sec_lower.startswith("destination:"):
                name = section.split(":", 1)[1].strip()
                cfg.destinations[name] = self._build_destination(name, values)
            elif sec_lower.startswith("route"):
                name = section.split(":", 1)[1].strip() if ":" in section else section
                cfg.routes.append(self._build_route(name, values))
            elif sec_lower == "logging":
                cfg.logging = self._build_logging(values)
            elif sec_lower == "security":
                cfg.security = self._build_security(values)
        return cfg

    def _build_options(self, v: dict) -> OptionsConfig:
        o = OptionsConfig()
        if "flush_interval"  in v: o.flush_interval  = float(v["flush_interval"])
        if "queue_size"      in v: o.queue_size       = int(v["queue_size"])
        if "retry_interval"  in v: o.retry_interval   = float(v["retry_interval"])
        if "worker_threads"  in v: o.worker_threads   = int(v["worker_threads"])
        if "hostname"        in v: o.hostname         = v["hostname"]
        if "event_timeout"   in v: o.event_timeout    = float(v["event_timeout"])
        return o

    def _build_source(self, section: str, v: dict) -> SourceConfig:
        name = section.split(":", 1)[1].strip() if ":" in section else "default"
        s = SourceConfig(name=name)
        if "type" in v: s.type = v["type"].strip()
        if "path" in v: s.path = v["path"].strip()
        return s

    def _build_parser(self, v: dict) -> ParserConfig:
        p = ParserConfig()
        if "preserve_raw"     in v: p.preserve_raw     = _parse_bool(v["preserve_raw"])
        if "include_metadata" in v: p.include_metadata = _parse_bool(v["include_metadata"])
        return p

    def _build_filter(self, name: str, v: dict) -> FilterConfig:
        f = FilterConfig(name=name)
        if "action"       in v: f.action       = v["action"].strip().lower()
        if "priority"     in v: f.priority     = int(v["priority"])
        if "record_types" in v: f.record_types = _parse_list(v["record_types"])
        if "executables"  in v: f.executables  = _parse_list(v["executables"])
        if "uids"         in v: f.uids         = _parse_list(v["uids"])
        if "auids"        in v: f.auids        = _parse_list(v["auids"])
        if "paths"        in v: f.paths        = _parse_list(v["paths"])
        if "commands"     in v: f.commands     = _parse_list(v["commands"])
        if "keywords"     in v: f.keywords     = _parse_list(v["keywords"])
        if "regex"        in v: f.regex        = _parse_list(v["regex"])
        if "syscalls"     in v: f.syscalls     = _parse_list(v["syscalls"])
        if "success"      in v: f.success      = v["success"].strip().lower()
        if "tag"          in v: f.tag          = v["tag"].strip()
        return f

    def _build_destination(self, name: str, v: dict) -> DestinationConfig:
        d = DestinationConfig(name=name)
        if "type"           in v: d.type           = v["type"].strip().lower()
        if "enabled"        in v: d.enabled        = _parse_bool(v["enabled"])
        if "path"           in v: d.path           = v["path"].strip()
        if "host"           in v: d.host           = v["host"].strip()
        if "port"           in v: d.port           = int(v["port"])
        if "timeout"        in v: d.timeout        = float(v["timeout"])
        if "retries"        in v: d.retries        = int(v["retries"])
        if "retry_interval" in v: d.retry_interval = float(v["retry_interval"])
        if "fsync"          in v: d.fsync          = _parse_bool(v["fsync"])
        if "spool_dir"      in v: d.spool_dir      = v["spool_dir"].strip()
        if "spool_max_mb"   in v: d.spool_max_mb   = int(v["spool_max_mb"])
        return d

    def _build_route(self, name: str, v: dict) -> RouteConfig:
        r = RouteConfig(name=name)
        if "source"       in v: r.source       = v["source"].strip()
        if "filters"      in v: r.filters      = _parse_list(v["filters"])
        if "destinations" in v: r.destinations = _parse_list(v["destinations"])
        return r

    def _build_logging(self, v: dict) -> LoggingConfig:
        l = LoggingConfig()
        if "level"        in v: l.level        = v["level"].strip().upper()
        if "file"         in v: l.file         = v["file"].strip()
        if "use_journald" in v: l.use_journald = _parse_bool(v["use_journald"])
        return l

    def _build_security(self, v: dict) -> SecurityConfig:
        s = SecurityConfig()
        if "user"  in v: s.user  = v["user"].strip()
        if "group" in v: s.group = v["group"].strip()
        return s

    # ------------------------------------------------------------------
    # Validação
    # ------------------------------------------------------------------

    def _validate(self, cfg: AgentConfig) -> None:
        errors: list[str] = []

        # Destinos
        valid_dest_types = {"file", "tcp", "udp", "stdout"}
        for name, dest in cfg.destinations.items():
            if dest.type not in valid_dest_types:
                errors.append(f"Destination '{name}': tipo inválido '{dest.type}'")

            # stdout bloqueado — apenas para dev/test explícito
            if dest.type == "stdout" and dest.enabled:
                errors.append(
                    f"Destination '{name}': tipo 'stdout' não é permitido em produção. "
                    "Use para testes locais apenas com enabled = no, ou redirecione "
                    "para um destino file/tcp/udp."
                )

            if dest.type in ("tcp", "udp"):
                if not dest.host:
                    errors.append(f"Destination '{name}': 'host' obrigatório para tipo {dest.type}")
                if dest.port <= 0 or dest.port > 65535:
                    errors.append(f"Destination '{name}': porta inválida {dest.port}")

            if dest.type == "file" and dest.path:
                if not _is_safe_path(dest.path, _ALLOWED_OUTPUT_PREFIXES):
                    errors.append(
                        f"Destination '{name}': caminho '{dest.path}' fora dos "
                        f"diretórios permitidos: {_ALLOWED_OUTPUT_PREFIXES}"
                    )

            if dest.spool_dir and not _is_safe_path(dest.spool_dir, _ALLOWED_OUTPUT_PREFIXES):
                errors.append(
                    f"Destination '{name}': spool_dir '{dest.spool_dir}' fora dos "
                    f"diretórios permitidos."
                )

        # Filtros
        valid_actions = {"drop", "allow", "tag"}
        for name, flt in cfg.filters.items():
            if flt.action not in valid_actions:
                errors.append(f"Filter '{name}': action inválida '{flt.action}'")
            if flt.action == "tag" and not flt.tag:
                errors.append(f"Filter '{name}': action=tag requer campo 'tag'")

        # Rotas
        for route in cfg.routes:
            for fname in route.filters:
                if fname not in cfg.filters:
                    errors.append(f"Route '{route.name}': filtro '{fname}' não definido")
            for dname in route.destinations:
                if dname not in cfg.destinations:
                    errors.append(f"Route '{route.name}': destino '{dname}' não definido")

        # Source
        if cfg.source.type not in ("dispatcher", "file"):
            errors.append(f"Source type inválido: '{cfg.source.type}'")

        # Log file path
        if cfg.logging.file and not _is_safe_path(cfg.logging.file, _ALLOWED_LOG_PREFIXES):
            errors.append(
                f"Logging file '{cfg.logging.file}' fora dos diretórios permitidos: "
                f"{_ALLOWED_LOG_PREFIXES}"
            )

        # Nível de log
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR"}
        if cfg.logging.level not in valid_levels:
            errors.append(f"Logging level inválido: '{cfg.logging.level}'")

        if errors:
            msg = "Erros de configuração:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ValueError(msg)

        log.debug("Configuração validada com sucesso.")

    # ------------------------------------------------------------------
    # Auditoria de filtros carregados
    # ------------------------------------------------------------------

    def _log_filter_summary(self, cfg: AgentConfig) -> None:
        """Loga todos os filtros carregados — rastreabilidade de configuração."""
        if not cfg.filters:
            log.info("Nenhum filtro configurado.")
            return
        log.info("Filtros carregados (%d):", len(cfg.filters))
        for name, f in sorted(cfg.filters.items(), key=lambda x: x[1].priority):
            conditions = []
            if f.record_types: conditions.append(f"record_types={f.record_types}")
            if f.executables:  conditions.append(f"executables={f.executables}")
            if f.uids:         conditions.append(f"uids={f.uids}")
            if f.paths:        conditions.append(f"paths={f.paths}")
            if f.commands:     conditions.append(f"commands={f.commands}")
            if f.success:      conditions.append(f"success={f.success}")
            if f.syscalls:     conditions.append(f"syscalls={f.syscalls}")
            cond_str = ", ".join(conditions) if conditions else "(sem condições — casa tudo)"
            log.info(
                "  [%03d] %-30s action=%-6s  %s",
                f.priority, name, f.action, cond_str,
            )
