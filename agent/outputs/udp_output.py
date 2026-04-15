"""
outputs/udp_output.py — Saída UDP (sem garantia de entrega).
"""

import json
import socket

from config_loader import DestinationConfig
from internal_logging import log
from models import AuditEvent


class UdpOutput:
    """
    Envia eventos via UDP.

    UDP não garante entrega. Adequado para ambientes de alta performance
    onde perda eventual é aceitável.
    """

    def __init__(self, config: DestinationConfig):
        self._config = config
        self._host = config.host
        self._port = config.port
        self._sock: socket.socket | None = None
        self._open()

    def _open(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(self._config.timeout)
            log.info("UdpOutput '%s': socket criado para %s:%d", self._config.name, self._host, self._port)
        except OSError as e:
            log.error("UdpOutput '%s': falha ao criar socket — %s", self._config.name, e)
            self._sock = None

    def send(self, event: AuditEvent) -> bool:
        if self._sock is None:
            self._open()
            if self._sock is None:
                return False
        try:
            data = (json.dumps(event.to_dict(), ensure_ascii=False) + "\n").encode("utf-8")
            self._sock.sendto(data, (self._host, self._port))
            return True
        except OSError as e:
            log.warning("UdpOutput '%s': falha ao enviar — %s", self._config.name, e)
            return False

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        log.info("UdpOutput '%s': fechado.", self._config.name)
