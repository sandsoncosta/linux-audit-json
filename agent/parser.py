"""
parser.py — Faz parse das linhas brutas do Linux Audit.

Formato típico de uma linha:
  type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e syscall=59 ...
  type=PATH msg=audit(1700000000.123:4567): item=0 name="/usr/bin/ls" ...

O auditd moderno pode acrescentar campos enriquecidos após um separador GS (0x1D):
  type=USER_END msg=audit(...): ... res=success\x1dUID="osboxes" AUID="osboxes"
Esses campos são extraídos normalmente.
"""

import re
from typing import Optional

from models import AuditRecord


# ---------------------------------------------------------------------------
# Regex principal
# ---------------------------------------------------------------------------

# Captura: type=TIPO msg=audit(TIMESTAMP:EVENT_ID): CAMPOS
# O separador GS (0x1D) pode aparecer no meio dos campos — tratado abaixo.
_LINE_RE = re.compile(
    r"^type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$",
    re.DOTALL,
)

# Captura pares chave=valor (suporta aspas e valores simples)
_KV_RE = re.compile(
    r'(\w+)=(?:"([^"]*)"|((?:[^\s"\x1d\\]|\\.)*))'
)


def parse_line(raw_line: str) -> Optional[AuditRecord]:
    """
    Faz parse de uma linha bruta do auditd.

    Retorna AuditRecord ou None se a linha não for reconhecida.
    """
    # Remove newline mas preserva o conteúdo interno
    raw_line = raw_line.rstrip("\n\r")
    if not raw_line:
        return None

    m = _LINE_RE.match(raw_line)
    if not m:
        return None

    record_type = m.group(1)
    timestamp   = float(m.group(2))
    event_id    = m.group(3)
    fields_str  = m.group(4)

    # O auditd separa campos enriquecidos com GS (0x1D / \x1d)
    # Substituímos por espaço para que o KV parser os trate uniformemente.
    fields_str = fields_str.replace("\x1d", " ")

    fields = _parse_fields(fields_str)
    fields["_record_type"] = record_type

    return AuditRecord(
        record_type=record_type,
        timestamp=timestamp,
        event_id=event_id,
        fields=fields,
        raw=raw_line,
    )


def _parse_fields(fields_str: str) -> dict:
    """
    Extrai pares chave=valor de uma string de campos do auditd.

    Suporta:
    - chave=valor simples
    - chave="valor com espaços"
    - chave=0A1B2C (hex encoding — decodificado para campos conhecidos)
    """
    result = {}
    for m in _KV_RE.finditer(fields_str):
        key   = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = _maybe_decode_hex(key, value)
    return result


# Campos que o auditd costuma hex-encodar
_HEX_FIELDS = {"proctitle", "comm", "exe", "cwd", "name", "a0", "a1", "a2", "a3"}


def _maybe_decode_hex(key: str, value: str) -> str:
    """Tenta decodificar valor hex de campos conhecidos do auditd."""
    if key.lower() not in _HEX_FIELDS:
        return value
    try:
        if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0 and len(value) > 0:
            decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
            decoded = decoded.replace("\x00", " ").strip()
            return decoded
    except Exception:
        pass
    return value
