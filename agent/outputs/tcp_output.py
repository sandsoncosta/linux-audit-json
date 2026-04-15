"""
outputs/tcp_output.py — Saída TCP com reconexão automática, fila em memória
e fila persistente em disco (spool) para sobreviver a quedas do SIEM.

Fluxo de dados:
  send() → fila em memória → _sender_loop → TCP
                           ↓ (se TCP cair)
                        spool em disco → replay quando TCP voltar

Shutdown correto:
  close() injeta sentinel com put() bloqueante (timeout 5s) para garantir
  que o sentinel entre mesmo com fila cheia.
"""

import json
import os
import queue
import socket
import threading
import time
from pathlib import Path

from config_loader import DestinationConfig
from internal_logging import log
from models import AuditEvent

_SENTINEL = object()


class TcpOutput:
    """
    Envia eventos via TCP com reconexão automática.

    Fila persistente em disco (spool):
      - Habilitada quando spool_dir está configurado no destino.
      - Eventos são gravados no spool quando o TCP está indisponível.
      - Replay automático quando a conexão é restaurada.
      - Spool é append-only; limpeza ocorre após confirmação de envio.
    """

    def __init__(self, config: DestinationConfig, queue_maxsize: int = 5000):
        self._config         = config
        self._host           = config.host
        self._port           = config.port
        self._timeout        = config.timeout
        self._retries        = config.retries
        self._retry_interval = config.retry_interval

        self._queue: queue.Queue = queue.Queue(maxsize=queue_maxsize)
        self._sock: socket.socket | None = None
        self._conn_lock  = threading.Lock()
        self._stop_event = threading.Event()

        # Fila persistente em disco
        self._spool_dir  = Path(config.spool_dir) if config.spool_dir else None
        self._spool_max  = config.spool_max_mb * 1024 * 1024
        self._spool_lock = threading.Lock()
        if self._spool_dir:
            self._spool_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(str(self._spool_dir), 0o750)
            log.info(
                "TcpOutput '%s': spool em disco habilitado em %s (max %dMB)",
                config.name, self._spool_dir, config.spool_max_mb,
            )

        self._thread = threading.Thread(
            target=self._sender_loop,
            name=f"tcp-output-{config.name}",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "TcpOutput '%s': iniciado para %s:%d",
            config.name, self._host, self._port,
        )

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def send(self, event: AuditEvent) -> bool:
        """Enfileira o evento para envio assíncrono. Não bloqueia."""
        try:
            line = json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
            data = line.encode("utf-8")
            self._queue.put_nowait(data)
            return True
        except queue.Full:
            log.warning(
                "TcpOutput '%s': fila em memória cheia — gravando no spool (evento %s)",
                self._config.name, event.event_id,
            )
            return self._spool_write(data)

    def close(self) -> None:
        """Encerra a thread de envio de forma limpa."""
        log.info("TcpOutput '%s': encerrando...", self._config.name)
        self._stop_event.set()

        # Usa put com timeout para garantir que o sentinel entre mesmo com fila cheia.
        try:
            self._queue.put(_SENTINEL, timeout=5.0)
        except queue.Full:
            log.warning(
                "TcpOutput '%s': fila cheia no shutdown — forçando parada.",
                self._config.name,
            )

        self._thread.join(timeout=15)
        self._disconnect()
        log.info("TcpOutput '%s': encerrado.", self._config.name)

    # ------------------------------------------------------------------
    # Thread de envio
    # ------------------------------------------------------------------

    def _sender_loop(self) -> None:
        # Ao iniciar, tenta fazer replay do spool se houver dados pendentes
        if self._spool_dir:
            self._spool_replay()

        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                # Verifica spool periodicamente
                if self._spool_dir:
                    self._spool_replay()
                continue

            if item is _SENTINEL:
                break

            success = self._send_with_retry(item)
            if not success and self._spool_dir:
                self._spool_write(item)

    def _send_with_retry(self, data: bytes) -> bool:
        for attempt in range(1, self._retries + 1):
            try:
                sock = self._get_connection()
                if sock is None:
                    raise ConnectionError("Sem conexão disponível")
                sock.sendall(data)
                return True
            except (OSError, ConnectionError) as e:
                log.warning(
                    "TcpOutput '%s': falha no envio (tentativa %d/%d) — %s",
                    self._config.name, attempt, self._retries, e,
                )
                self._disconnect()
                if attempt < self._retries:
                    time.sleep(self._retry_interval)
        log.error(
            "TcpOutput '%s': falha após %d tentativas.",
            self._config.name, self._retries,
        )
        return False

    # ------------------------------------------------------------------
    # Gerenciamento de conexão
    # ------------------------------------------------------------------

    def _get_connection(self) -> socket.socket | None:
        with self._conn_lock:
            if self._sock is not None:
                return self._sock
            return self._connect()

    def _connect(self) -> socket.socket | None:
        try:
            sock = socket.create_connection(
                (self._host, self._port), timeout=self._timeout
            )
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock = sock
            log.info(
                "TcpOutput '%s': conectado a %s:%d",
                self._config.name, self._host, self._port,
            )
            return sock
        except OSError as e:
            log.error(
                "TcpOutput '%s': não foi possível conectar — %s",
                self._config.name, e,
            )
            return None

    def _disconnect(self) -> None:
        with self._conn_lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    # ------------------------------------------------------------------
    # Spool em disco
    # ------------------------------------------------------------------

    def _spool_path(self) -> Path:
        return self._spool_dir / f"{self._config.name}.spool"

    def _spool_write(self, data: bytes) -> bool:
        """Grava dados no spool append-only. Respeita limite de tamanho."""
        if not self._spool_dir:
            return False
        with self._spool_lock:
            try:
                spool = self._spool_path()
                # Verifica limite de tamanho
                current_size = spool.stat().st_size if spool.exists() else 0
                if current_size + len(data) > self._spool_max:
                    log.error(
                        "TcpOutput '%s': spool em disco cheio (%dMB) — "
                        "evento descartado. Verifique conectividade com %s:%d.",
                        self._config.name,
                        self._config.spool_max_mb,
                        self._host,
                        self._port,
                    )
                    return False
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                fd = os.open(str(spool), flags, mode=0o640)
                with os.fdopen(fd, "ab") as f:
                    f.write(data)
                return True
            except OSError as e:
                log.error(
                    "TcpOutput '%s': erro ao gravar spool — %s",
                    self._config.name, e,
                )
                return False

    def _spool_replay(self) -> None:
        """Tenta reenviar eventos do spool quando TCP está disponível."""
        if not self._spool_dir:
            return
        spool = self._spool_path()
        with self._spool_lock:
            if not spool.exists() or spool.stat().st_size == 0:
                return

        log.info(
            "TcpOutput '%s': iniciando replay do spool (%d bytes)...",
            self._config.name,
            spool.stat().st_size,
        )

        replayed = 0
        failed   = []

        with self._spool_lock:
            try:
                with open(spool, "rb") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if self._send_with_retry(line + b"\n"):
                            replayed += 1
                        else:
                            failed.append(line)
            except OSError as e:
                log.error("TcpOutput '%s': erro ao ler spool — %s", self._config.name, e)
                return

            # Reescreve spool apenas com os eventos que falharam
            try:
                if failed:
                    with open(spool, "wb") as f:
                        for line in failed:
                            f.write(line + b"\n")
                    log.warning(
                        "TcpOutput '%s': replay parcial — %d enviados, %d pendentes no spool.",
                        self._config.name, replayed, len(failed),
                    )
                else:
                    spool.unlink()
                    log.info(
                        "TcpOutput '%s': replay completo — %d evento(s) enviados.",
                        self._config.name, replayed,
                    )
            except OSError as e:
                log.error(
                    "TcpOutput '%s': erro ao limpar spool após replay — %s",
                    self._config.name, e,
                )
