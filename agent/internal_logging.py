"""
internal_logging.py — Logging operacional interno do agente.

Registra eventos do próprio sistema (inicialização, erros, reconexões etc.)
separado dos eventos de auditoria coletados.
"""

import logging
import logging.handlers
import sys
from pathlib import Path


def setup_internal_logger(
    level: str = "INFO",
    log_file: str | None = None,
    use_journald: bool = False,
) -> logging.Logger:
    """
    Configura e retorna o logger interno do agente.

    Args:
        level: Nível de log (DEBUG, INFO, WARNING, ERROR).
        log_file: Caminho para arquivo de log. None = só stdout.
        use_journald: Se True, adiciona handler para journald via stderr
                      (systemd captura automaticamente stderr).
    """
    logger = logging.getLogger("audit-agent")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Handler para stdout/stderr
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    # Handler para arquivo com rotação
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(path),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger


# Logger global — configurado em main.py antes do uso
log = logging.getLogger("audit-agent")
