"""
correlator.py — Correlaciona registros pertencentes ao mesmo evento de auditoria.

O Linux Audit emite múltiplos registros para um mesmo evento lógico
(SYSCALL + PATH + CWD + PROCTITLE, por exemplo). O correlator agrupa
esses registros pelo event_id e emite um AuditEvent completo quando
recebe o marcador de fim (EOE — End Of Event) ou após timeout.

Thread-safety: esta classe é thread-safe. Todos os acessos ao estado
interno são protegidos por RLock, permitindo uso simultâneo pelo loop
principal e pela thread de flush periódico.
"""

import threading
import time
from collections import defaultdict

from config_loader import OptionsConfig
from internal_logging import log
from models import AuditEvent, AuditRecord


class Correlator:
    """
    Mantém um buffer de registros em andamento por event_id.

    Thread-safe: usa RLock interno em feed(), flush_expired() e _flush().
    """

    def __init__(self, options: OptionsConfig):
        self._options  = options
        self._hostname = options.hostname
        self._timeout  = options.event_timeout
        self._lock     = threading.RLock()

        # event_id -> {"records": [...], "last_seen": float}
        self._pending: dict[str, dict] = defaultdict(
            lambda: {"records": [], "last_seen": time.monotonic()}
        )

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def feed(self, record: AuditRecord) -> AuditEvent | None:
        """
        Recebe um registro. Retorna AuditEvent se o evento está completo
        (marcador EOE recebido), ou None caso contrário.
        """
        with self._lock:
            eid = record.event_id

            if record.record_type == "EOE":
                return self._flush(eid)

            bucket = self._pending[eid]
            bucket["records"].append(record)
            bucket["last_seen"] = time.monotonic()
            return None

    def flush_expired(self) -> list[AuditEvent]:
        """
        Verifica todos os eventos pendentes e retorna os que ultrapassaram
        o timeout de correlação. Deve ser chamado periodicamente.
        """
        with self._lock:
            now = time.monotonic()
            expired = [
                eid for eid, bucket in self._pending.items()
                if now - bucket["last_seen"] >= self._timeout
            ]
            events = []
            for eid in expired:
                event = self._flush(eid)
                if event:
                    log.debug("Evento %s encerrado por timeout.", eid)
                    events.append(event)
            return events

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    # ------------------------------------------------------------------
    # Interno (deve ser chamado com self._lock adquirido)
    # ------------------------------------------------------------------

    def _flush(self, event_id: str) -> AuditEvent | None:
        bucket = self._pending.pop(event_id, None)
        if not bucket or not bucket["records"]:
            return None

        records: list[AuditRecord] = bucket["records"]
        timestamp    = records[0].timestamp
        record_types = list(dict.fromkeys(r.record_type for r in records))
        summary      = self._build_summary(records)

        return AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            host=self._hostname,
            records=records,
            record_types=record_types,
            summary=summary,
        )

    def _build_summary(self, records: list[AuditRecord]) -> dict:
        """Extrai campos de alto valor para o resumo do evento."""
        summary: dict = {}

        for r in records:
            f     = r.fields
            rtype = r.record_type

            if rtype == "SYSCALL":
                for key in ("syscall", "success", "pid", "uid", "auid", "comm", "exe", "key"):
                    if key in f:
                        summary[key] = f[key]

            elif rtype == "EXECVE":
                args = []
                i = 0
                while f"a{i}" in f:
                    args.append(f[f"a{i}"])
                    i += 1
                if args:
                    summary["cmdline"] = " ".join(args)

            elif rtype == "PATH":
                if "name" in f and "filepath" not in summary:
                    summary["filepath"] = f["name"]

            elif rtype == "CWD":
                if "cwd" in f:
                    summary["cwd"] = f["cwd"]

            elif rtype == "PROCTITLE":
                if "proctitle" in f:
                    summary["proctitle"] = f["proctitle"]

            elif rtype in ("USER_AUTH", "USER_LOGIN", "USER_LOGOUT",
                           "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP"):
                for key in ("acct", "exe", "hostname", "addr", "res"):
                    if key in f:
                        summary[key] = f[key]

        return summary
