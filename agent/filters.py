"""
filters.py — Avalia filtros definidos na configuração sobre AuditEvents.

Suporta condições: record_types, executables, uids, auids, paths,
commands, keywords, regex, syscalls, success.

Ação resultante: drop | allow | tag.
"""

import json
import re as re_module
from typing import Optional

from config_loader import FilterConfig
from internal_logging import log
from models import AuditEvent


class FilterEngine:
    """Compila e avalia filtros sobre eventos de auditoria."""

    def __init__(self, filter_configs: dict[str, FilterConfig]):
        self._filters: list[FilterConfig] = sorted(
            filter_configs.values(), key=lambda f: f.priority
        )
        # Pré-compila regex para desempenho
        self._compiled_regex: dict[str, list[re_module.Pattern]] = {}
        for name, fc in filter_configs.items():
            self._compiled_regex[name] = [
                re_module.compile(pat) for pat in fc.regex
            ]
        log.debug("FilterEngine inicializado com %d filtros.", len(self._filters))

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def evaluate(self, event: AuditEvent) -> tuple[str, str]:
        """
        Avalia todos os filtros sobre o evento na ordem de prioridade.

        Retorna: (ação, nome_do_filtro)
          ação: "drop" | "allow" | "tag" | "pass"  (pass = nenhum filtro casou)
        """
        for fc in self._filters:
            if self._matches(fc, event):
                log.debug(
                    "Evento %s casou filtro '%s' → %s",
                    event.event_id, fc.name, fc.action,
                )
                return fc.action, fc.name
        return "pass", ""

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def _matches(self, fc: FilterConfig, event: AuditEvent) -> bool:
        """Retorna True se TODAS as condições definidas casarem (AND lógico)."""

        # Coleta todos os campos de todos os registros para busca
        all_fields = {}
        all_raw = ""
        for r in event.records:
            all_fields.update(r.fields)
            all_raw += r.raw + "\n"

        # record_types — qualquer tipo do evento casa com qualquer da lista
        if fc.record_types:
            if not any(rt in event.record_types for rt in fc.record_types):
                return False

        # executables
        if fc.executables:
            exe = all_fields.get("exe", "") or event.summary.get("exe", "")
            if not any(e in exe for e in fc.executables):
                return False

        # uids
        if fc.uids:
            uid = str(all_fields.get("uid", ""))
            if uid not in fc.uids:
                return False

        # auids
        if fc.auids:
            auid = str(all_fields.get("auid", ""))
            if auid not in fc.auids:
                return False

        # paths — verifica em todos os campos "name" dos registros PATH
        if fc.paths:
            path_values = [
                r.fields.get("name", "")
                for r in event.records
                if r.record_type == "PATH"
            ]
            all_paths = " ".join(path_values)
            if not any(p in all_paths for p in fc.paths):
                return False

        # commands
        if fc.commands:
            comm = all_fields.get("comm", "") or event.summary.get("comm", "")
            if not any(c in comm for c in fc.commands):
                return False

        # keywords — busca simples no JSON completo do evento
        if fc.keywords:
            event_str = json.dumps(event.to_dict())
            if not any(kw in event_str for kw in fc.keywords):
                return False

        # regex — aplicado ao raw concatenado
        if fc.regex:
            compiled = self._compiled_regex.get(fc.name, [])
            if not any(pat.search(all_raw) for pat in compiled):
                return False

        # syscalls
        if fc.syscalls:
            syscall = all_fields.get("syscall", "")
            if syscall not in fc.syscalls:
                return False

        # success
        if fc.success is not None:
            success_val = all_fields.get("success", "")
            if success_val.lower() != fc.success:
                return False

        return True
