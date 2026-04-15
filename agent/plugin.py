"""
plugin.py — Entrypoint dedicado para uso como plugin do audispd.

O audispd chama este script como processo filho e encaminha eventos
pelo stdin. Lê stdin até EOF e encerra com estatísticas.

Metadados de integridade injetados em cada evento:
  - config_hash: SHA-256 do agent.conf ativo
  - agent_id:    hostname + versão do coletor
"""

import argparse
import hashlib
import os
import signal
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config_loader import ConfigLoader
from correlator import Correlator
from filters import FilterEngine
from internal_logging import log, setup_internal_logger
from models import AuditEvent
from parser import parse_line
from router import Router
from outputs.file_output import FileOutput
from outputs.tcp_output import TcpOutput
from outputs.udp_output import UdpOutput

VERSION  = "1.1.0"
DEFAULT_CONF = "/etc/linux-audit-json/agent.conf"


def build_outputs(config):
    outputs = {}
    for name, dest in config.destinations.items():
        if not dest.enabled:
            continue
        if dest.type == "file":
            outputs[name] = FileOutput(dest)
        elif dest.type == "tcp":
            outputs[name] = TcpOutput(dest)
        elif dest.type == "udp":
            from outputs.udp_output import UdpOutput
            outputs[name] = UdpOutput(dest)
        # stdout bloqueado em produção pelo config_loader
    return outputs


def main():
    parser = argparse.ArgumentParser(prog="linux-audit-json-plugin")
    parser.add_argument(
        "--conf", "-c",
        default=os.environ.get("AUDIT_AGENT_CONF", DEFAULT_CONF),
    )
    args = parser.parse_args()

    try:
        cfg = ConfigLoader(args.conf).load()
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)

    setup_internal_logger(
        level=cfg.logging.level,
        log_file=cfg.logging.file,
        use_journald=cfg.logging.use_journald,
    )

    log.info("linux-audit-json plugin v%s iniciando (pid=%d).", VERSION, os.getpid())
    log.info("config_hash: %s", cfg.config_hash)

    # Identificador do agente — incluído em cada evento
    agent_id = f"{cfg.options.hostname}@{VERSION}"

    outputs       = build_outputs(cfg)
    filter_engine = FilterEngine(cfg.filters)
    router        = Router(cfg, outputs, filter_engine)
    correlator    = Correlator(cfg.options)

    running = True

    def handle_term(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT,  handle_term)

    stop_event = threading.Event()

    def flush_loop():
        while not stop_event.wait(cfg.options.flush_interval):
            try:
                for event in correlator.flush_expired():
                    _enrich(event, cfg.config_hash, agent_id)
                    router.dispatch(event)
            except Exception as e:
                log.error("flush_loop: %s", e)

    flush_thread = threading.Thread(target=flush_loop, daemon=True)
    flush_thread.start()

    try:
        for raw_line in sys.stdin:
            if not running:
                break
            record = parse_line(raw_line)
            if record is None:
                continue
            event = correlator.feed(record)
            if event:
                _enrich(event, cfg.config_hash, agent_id)
                router.dispatch(event)
    except Exception as e:
        log.error("Erro no loop principal: %s", e, exc_info=True)
    finally:
        stop_event.set()
        for event in correlator.flush_expired():
            _enrich(event, cfg.config_hash, agent_id)
            router.dispatch(event)
        for out in outputs.values():
            try:
                out.close()
            except Exception:
                pass
        s = router.stats
        log.info(
            "Plugin encerrado. recebidos=%d enviados=%d descartados=%d erros=%d",
            s["received"], s["sent"], s["dropped"], s["send_errors"],
        )


def _enrich(event: AuditEvent, config_hash: str, agent_id: str) -> None:
    """Injeta metadados de integridade no evento."""
    event.config_hash = config_hash
    event.agent_id    = agent_id


if __name__ == "__main__":
    main()
