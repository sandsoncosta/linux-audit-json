"""
models.py — Estruturas de dados centrais do agente.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuditRecord:
    """Representa um registro individual do Linux Audit."""
    record_type: str
    timestamp:   float
    event_id:    str
    fields:      dict[str, Any] = field(default_factory=dict)
    raw:         str = ""


@dataclass
class AuditEvent:
    """Representa um evento correlacionado (pode ter N registros)."""
    event_id:          str
    timestamp:         float
    host:              str
    records:           list[AuditRecord]    = field(default_factory=list)
    record_types:      list[str]            = field(default_factory=list)
    summary:           dict[str, Any]       = field(default_factory=dict)
    tags:              list[str]            = field(default_factory=list)
    route_name:        str  = ""
    filter_name:       str  = ""
    collector_version: str  = "1.1.0"
    config_hash:       str  = ""   # SHA-256 do agent.conf ativo
    agent_id:          str  = ""   # hostname + versão

    def to_dict(self) -> dict:
        return {
            "event_id":          self.event_id,
            "timestamp":         self.timestamp,
            "host":              self.host,
            "record_types":      self.record_types,
            "summary":           self.summary,
            "records": [
                {
                    # "type":   r.record_type,
                    # "fields": r.fields,
                    "raw":    r.raw,
                }
                for r in self.records
            ],
            "tags":              self.tags,
            "route_name":        self.route_name,
            "filter_name":       self.filter_name,
            "collector_version": self.collector_version,
            "config_hash":       self.config_hash,
            "agent_id":          self.agent_id,
        }
