"""
outputs/stdout_output.py — Saída para stdout (útil para debug/testes).
"""

import json
import sys

from config_loader import DestinationConfig
from internal_logging import log
from models import AuditEvent


class StdoutOutput:
    def __init__(self, config: DestinationConfig):
        self._config = config
        log.info("StdoutOutput '%s': ativo.", config.name)

    def send(self, event: AuditEvent) -> bool:
        try:
            line = json.dumps(event.to_dict(), ensure_ascii=False)
            print(line, flush=True)
            return True
        except Exception as e:
            log.error("StdoutOutput: erro — %s", e)
            return False

    def close(self) -> None:
        pass
