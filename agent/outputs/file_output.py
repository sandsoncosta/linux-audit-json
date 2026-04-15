"""
outputs/file_output.py — Saída para arquivo local em formato NDJSON.

Melhorias de segurança e resiliência:
  - Permissão 640 no arquivo de saída (dono + grupo, não world-readable)
  - fsync configurável (garante persistência em disco após cada escrita)
  - Proteção contra symlink attack (O_NOFOLLOW via flags)
  - Reabertura automática após falha (suporte a logrotate)
"""

import json
import os
import threading
from pathlib import Path

from config_loader import DestinationConfig
from internal_logging import log
from models import AuditEvent


class FileOutput:
    """Grava eventos em arquivo NDJSON com escrita thread-safe."""

    def __init__(self, config: DestinationConfig):
        self._config  = config
        self._path    = Path(config.path)
        self._fsync   = config.fsync
        self._lock    = threading.Lock()
        self._fd: int | None = None
        self._file    = None
        self._open()

    def _open(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)

            # Abre com O_NOFOLLOW para rejeitar symlinks no caminho final
            # O_APPEND garante escrita atômica em múltiplos processos
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(str(self._path), flags, mode=0o640)
            self._fd   = fd
            self._file = os.fdopen(fd, "a", encoding="utf-8", buffering=1)

            # Garante permissão 640 mesmo se o arquivo já existia
            os.chmod(str(self._path), 0o640)

            log.info(
                "FileOutput '%s': arquivo aberto em %s (fsync=%s)",
                self._config.name, self._path, self._fsync,
            )
        except OSError as e:
            log.error(
                "FileOutput '%s': não foi possível abrir %s — %s",
                self._config.name, self._path, e,
            )
            self._file = None
            self._fd   = None

    def send(self, event: AuditEvent) -> bool:
        if self._file is None:
            self._open()
            if self._file is None:
                return False
        try:
            line = json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
            with self._lock:
                self._file.write(line)
                if self._fsync:
                    self._file.flush()
                    os.fsync(self._file.fileno())
            return True
        except OSError as e:
            log.error("FileOutput '%s': erro ao gravar — %s", self._config.name, e)
            self._file = None
            self._fd   = None
            return False

    def close(self) -> None:
        if self._file:
            try:
                self._file.flush()
                if self._fsync:
                    os.fsync(self._file.fileno())
                self._file.close()
            except OSError:
                pass
            self._file = None
            self._fd   = None
        log.info("FileOutput '%s': fechado.", self._config.name)
