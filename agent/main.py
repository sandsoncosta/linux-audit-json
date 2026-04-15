"""
main.py — Entrypoint do linux-audit-json agent.

Modos de operação:
  run      — executa o agente (padrão)
  validate — valida o arquivo .conf e sai
  test     — processa entrada de exemplo do stdin
"""

import argparse
import json
import os
import signal
import sys
import time
import threading
from pathlib import Path

# Garante que o diretório do agente está no path
sys.path.insert(0, str(Path(__file__).parent))

from config_loader import AgentConfig, ConfigLoader
from correlator import Correlator
from filters import FilterEngine
from internal_logging import log, setup_internal_logger
from models import AuditEvent
from parser import parse_line
from router import Router
from outputs.file_output import FileOutput
from outputs.tcp_output import TcpOutput
from outputs.udp_output import UdpOutput
from outputs.stdout_output import StdoutOutput


VERSION = "1.0.0"
DEFAULT_CONF = "/etc/linux-audit-json/agent.conf"


# ---------------------------------------------------------------------------
# Construção de outputs
# ---------------------------------------------------------------------------

def build_outputs(config: AgentConfig) -> dict:
    outputs = {}
    for name, dest in config.destinations.items():
        if not dest.enabled:
            log.info("Destino '%s' desabilitado — ignorando.", name)
            continue
        dtype = dest.type
        if dtype == "file":
            outputs[name] = FileOutput(dest)
        elif dtype == "tcp":
            outputs[name] = TcpOutput(dest)
        elif dtype == "udp":
            outputs[name] = UdpOutput(dest)
        elif dtype == "stdout":
            outputs[name] = StdoutOutput(dest)
        else:
            log.warning("Tipo de destino desconhecido: '%s' — ignorando.", dtype)
    return outputs


def close_outputs(outputs: dict) -> None:
    for name, out in outputs.items():
        try:
            out.close()
        except Exception as e:
            log.warning("Erro ao fechar destino '%s': %s", name, e)


# ---------------------------------------------------------------------------
# Fonte: dispatcher (stdin via audispd plugin) ou arquivo
# ---------------------------------------------------------------------------

def iter_lines_stdin():
    """Lê linhas do stdin (modo dispatcher)."""
    for line in sys.stdin:
        yield line


def iter_lines_file(path: str):
    """
    Lê linhas de um arquivo local em modo tail contínuo.

    Lê até o fim do arquivo e então faz polling por novas linhas,
    semelhante a 'tail -F'. Suporta rotação de arquivo (reabre se
    o inode mudar).
    """
    import time as _time
    import os as _os

    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
        f.seek(0, 2)  # posiciona no fim — ignora histórico ao iniciar
        log.info("Source file '%s' aberto em modo tail.", path)
    except OSError as e:
        log.error("Não foi possível abrir source file '%s': %s", path, e)
        return

    current_inode = _os.fstat(f.fileno()).st_ino

    try:
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                # Verifica rotação
                try:
                    new_inode = _os.stat(path).st_ino
                    if new_inode != current_inode:
                        log.info("Rotação detectada em '%s' — reabrindo.", path)
                        f.close()
                        f = open(path, "r", encoding="utf-8", errors="replace")
                        current_inode = new_inode
                except OSError:
                    pass
                _time.sleep(0.1)
    except GeneratorExit:
        pass
    finally:
        try:
            f.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Loop principal
# ---------------------------------------------------------------------------

class Agent:
    def __init__(self, config: AgentConfig):
        self._config = config
        self._running = False

        self._correlator = Correlator(config.options)
        self._filter_engine = FilterEngine(config.filters)
        self._outputs = build_outputs(config)
        self._router = Router(config, self._outputs, self._filter_engine)

        # Thread para flush de eventos expirados
        self._flush_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        log.info("linux-audit-json v%s iniciando.", VERSION)
        log.info(
            "Destinos ativos: %s",
            ", ".join(self._outputs.keys()) or "(nenhum)",
        )
        log.info(
            "Rotas: %s",
            ", ".join(r.name for r in self._config.routes) or "(nenhuma)",
        )

        self._running = True

        # Instala handlers de sinal
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGHUP, self._handle_sighup)

        # Inicia thread de flush de eventos expirados
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="flush-loop",
            daemon=True,
        )
        self._flush_thread.start()

        # Loop de leitura
        src = self._config.source
        if src.type == "dispatcher":
            lines = iter_lines_stdin()
        else:
            lines = iter_lines_file(src.path)

        try:
            self._process_lines(lines)
        except Exception as e:
            log.error("Erro inesperado no loop principal: %s", e, exc_info=True)
        finally:
            self._shutdown()

    def _process_lines(self, lines) -> None:
        for raw_line in lines:
            if not self._running:
                break
            record = parse_line(raw_line)
            if record is None:
                continue
            event = self._correlator.feed(record)
            if event:
                self._dispatch(event)

    def _dispatch(self, event: AuditEvent) -> None:
        try:
            self._router.dispatch(event)
        except Exception as e:
            log.error("Erro ao despachar evento %s: %s", event.event_id, e, exc_info=True)

    def _flush_loop(self) -> None:
        """Periodicamente verifica e flushea eventos expirados."""
        interval = self._config.options.flush_interval
        while not self._stop_event.wait(interval):
            try:
                expired = self._correlator.flush_expired()
                for event in expired:
                    self._dispatch(event)
                if expired:
                    log.debug("%d evento(s) expirado(s) despachados.", len(expired))
            except Exception as e:
                log.error("Erro no flush_loop: %s", e)

    def _shutdown(self) -> None:
        log.info("Encerrando agente...")
        self._stop_event.set()

        # Flush final de pendentes
        remaining = self._correlator.flush_expired()
        for event in remaining:
            self._dispatch(event)
        log.info("Flush final: %d evento(s) pendentes despachados.", len(remaining))

        close_outputs(self._outputs)

        stats = self._router.stats
        log.info(
            "Estatísticas: recebidos=%d despachados=%d descartados=%d erros=%d",
            stats["received"], stats["sent"], stats["dropped"], stats["send_errors"],
        )
        log.info("Agente encerrado.")

    def _handle_signal(self, signum, frame) -> None:
        log.info("Sinal %d recebido — encerrando.", signum)
        self._running = False

    def _handle_sighup(self, signum, frame) -> None:
        log.info("SIGHUP recebido — reload não implementado em runtime; reinicie o serviço.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_run(args) -> None:
    cfg = load_config(args.conf)
    setup_internal_logger(
        level=cfg.logging.level,
        log_file=cfg.logging.file,
        use_journald=cfg.logging.use_journald,
    )
    agent = Agent(cfg)
    agent.start()


def cmd_validate(args) -> None:
    setup_internal_logger(level="INFO")
    try:
        cfg = load_config(args.conf)
        print(f"✓ Configuração válida: {args.conf}")
        print(f"  Destinos  : {list(cfg.destinations.keys())}")
        print(f"  Filtros   : {list(cfg.filters.keys())}")
        print(f"  Rotas     : {[r.name for r in cfg.routes]}")
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ Erro: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_test(args) -> None:
    """Processa linhas do stdin e imprime JSON resultante."""
    cfg = load_config(args.conf)
    setup_internal_logger(level="WARNING")  # silencia logs no modo teste

    correlator = Correlator(cfg.options)

    print("# Modo teste — cole linhas do auditd (Ctrl+D para encerrar):")
    for raw_line in sys.stdin:
        record = parse_line(raw_line)
        if record is None:
            continue
        event = correlator.feed(record)
        if event:
            print(json.dumps(event.to_dict(), ensure_ascii=False, indent=2))

    # Flush final
    for event in correlator.flush_expired():
        print(json.dumps(event.to_dict(), ensure_ascii=False, indent=2))


def load_config(conf_path: str) -> AgentConfig:
    loader = ConfigLoader(conf_path)
    return loader.load()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="linux-audit-json",
        description=f"Agente de auditoria Linux → JSON  (v{VERSION})",
    )
    parser.add_argument(
        "--conf", "-c",
        default=os.environ.get("AUDIT_AGENT_CONF", DEFAULT_CONF),
        help=f"Caminho para o arquivo .conf (padrão: {DEFAULT_CONF})",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("run", help="Executa o agente (padrão se omitido)")
    sub.add_parser("validate", help="Valida o arquivo .conf e sai")
    sub.add_parser("test", help="Processa linhas do stdin e exibe JSON")

    args = parser.parse_args()

    if args.command == "validate":
        cmd_validate(args)
    elif args.command == "test":
        cmd_test(args)
    else:
        cmd_run(args)


if __name__ == "__main__":
    main()
