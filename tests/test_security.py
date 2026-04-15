"""
tests/test_security.py — Testes de segurança, concorrência e resiliência.
"""

import sys
import threading
import time
import json
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from config_loader import ConfigLoader, _is_safe_path, _ALLOWED_OUTPUT_PREFIXES
from correlator import Correlator
from models import AuditRecord, AuditEvent
from outputs.file_output import FileOutput


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_record(rtype, event_id, ts=1700000000.0, **fields):
    return AuditRecord(
        record_type=rtype, timestamp=ts, event_id=event_id,
        fields={"_record_type": rtype, **fields},
        raw=f"type={rtype} msg=audit({ts}:{event_id}):",
    )

def make_options():
    from config_loader import OptionsConfig
    o = OptionsConfig()
    o.event_timeout = 0.05
    o.hostname = "testhost"
    return o


def write_conf(content: str) -> str:
    """Grava conteúdo em arquivo temporário e retorna o caminho."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    f.write(content)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Testes de concorrência no correlator
# ---------------------------------------------------------------------------

def test_correlator_thread_safety():
    """
    Múltiplas threads alimentando o correlator simultaneamente não devem
    causar exceção, perda de eventos ou estado inconsistente.
    """
    corr    = Correlator(make_options())
    errors  = []
    results = []
    lock    = threading.Lock()

    def feeder(start_id, count):
        for i in range(count):
            eid = str(start_id + i)
            corr.feed(make_record("SYSCALL", eid))
            event = corr.feed(make_record("EOE", eid))
            if event:
                with lock:
                    results.append(event.event_id)

    def flusher():
        for _ in range(20):
            try:
                corr.flush_expired()
            except Exception as e:
                with lock:
                    errors.append(str(e))
            time.sleep(0.01)

    threads = [
        threading.Thread(target=feeder, args=(0, 50)),
        threading.Thread(target=feeder, args=(100, 50)),
        threading.Thread(target=flusher),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"Erros de concorrência: {errors}"
    print(f"  thread_safety: {len(results)} eventos processados sem erros.")


def test_correlator_no_duplicate_flush():
    """Um evento não deve ser emitido duas vezes (EOE + timeout)."""
    corr = Correlator(make_options())
    corr.feed(make_record("SYSCALL", "777"))
    e1 = corr.feed(make_record("EOE", "777"))
    assert e1 is not None

    time.sleep(0.1)
    expired = corr.flush_expired()
    assert not any(e.event_id == "777" for e in expired), \
        "Evento 777 foi emitido duas vezes!"
    print("  no_duplicate_flush: OK")


# ---------------------------------------------------------------------------
# Testes de validação de configuração
# ---------------------------------------------------------------------------

def test_stdout_blocked_in_production():
    """Destino stdout ativo deve ser rejeitado pelo config_loader."""
    conf = write_conf("""
[source:default]
type = dispatcher

[destination:debug]
type    = stdout
enabled = yes

[route:r]
source       = default
destinations = debug
""")
    try:
        loader = ConfigLoader(conf)
        try:
            loader.load()
            assert False, "Deveria ter levantado ValueError"
        except ValueError as e:
            assert "stdout" in str(e).lower()
            print("  stdout_blocked: OK —", str(e)[:60])
    finally:
        os.unlink(conf)


def test_dangerous_path_rejected():
    """Caminhos fora dos prefixos permitidos devem ser rejeitados."""
    conf = write_conf("""
[source:default]
type = dispatcher

[destination:bad]
type = file
path = /etc/shadow_copy

[route:r]
source       = default
destinations = bad
""")
    try:
        loader = ConfigLoader(conf)
        try:
            loader.load()
            assert False, "Deveria ter rejeitado o caminho /etc/shadow_copy"
        except ValueError as e:
            assert "permitidos" in str(e) or "prefixos" in str(e) or "fora" in str(e)
            print("  dangerous_path_rejected: OK —", str(e)[:80])
    finally:
        os.unlink(conf)


def test_safe_path_allowed():
    """Caminhos em /var/log/ devem ser aceitos."""
    assert _is_safe_path("/var/log/linux-audit-json/events.ndjson", _ALLOWED_OUTPUT_PREFIXES)
    assert not _is_safe_path("/etc/passwd", _ALLOWED_OUTPUT_PREFIXES)
    assert not _is_safe_path("/proc/1/mem", _ALLOWED_OUTPUT_PREFIXES)
    print("  safe_path_allowed: OK")


def test_invalid_filter_action_rejected():
    """Action inválida em filtro deve ser rejeitada."""
    conf = write_conf("""
[source:default]
type = dispatcher

[filter:bad]
action = execute_something
""")
    try:
        loader = ConfigLoader(conf)
        try:
            loader.load()
            assert False, "Deveria ter rejeitado action inválida"
        except ValueError as e:
            assert "action" in str(e).lower()
            print("  invalid_filter_action: OK")
    finally:
        os.unlink(conf)


def test_config_hash_computed():
    """O hash do agent.conf deve ser computado e incluído na config."""
    conf = write_conf("""
[source:default]
type = dispatcher
""")
    try:
        loader = ConfigLoader(conf)
        cfg = loader.load()
        assert cfg.config_hash
        assert len(cfg.config_hash) == 64  # SHA-256 hex
        print(f"  config_hash_computed: OK — {cfg.config_hash[:16]}...")
    finally:
        os.unlink(conf)


# ---------------------------------------------------------------------------
# Testes de FileOutput
# ---------------------------------------------------------------------------

def test_file_output_permissions():
    """O arquivo de saída deve ter permissão 640."""
    with tempfile.TemporaryDirectory() as tmpdir:
        from config_loader import DestinationConfig
        dest = DestinationConfig(
            name="test",
            type="file",
            path=os.path.join(tmpdir, "events.ndjson"),
            fsync=False,
        )
        out = FileOutput(dest)
        # Grava um evento fake
        event = AuditEvent(
            event_id="1", timestamp=1700000000.0, host="test",
            record_types=["SYSCALL"],
        )
        out.send(event)
        out.close()

        stat = os.stat(dest.path)
        perm = oct(stat.st_mode & 0o777)
        assert perm == "0o640", f"Permissão esperada 640, obtida {perm}"
        print(f"  file_permissions: OK — {perm}")


def test_file_output_concurrent_writes():
    """Múltiplas threads escrevendo no FileOutput não devem corromper o arquivo."""
    with tempfile.TemporaryDirectory() as tmpdir:
        from config_loader import DestinationConfig
        dest = DestinationConfig(
            name="test",
            type="file",
            path=os.path.join(tmpdir, "events.ndjson"),
            fsync=False,
        )
        out   = FileOutput(dest)
        count = 200

        def writer(start):
            for i in range(start, start + count // 4):
                event = AuditEvent(
                    event_id=str(i), timestamp=float(i), host="test",
                    record_types=["SYSCALL"],
                )
                out.send(event)

        threads = [threading.Thread(target=writer, args=(i * count // 4,))
                   for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        out.close()

        # Verifica que todas as linhas são JSON válido
        with open(dest.path) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) == count, f"Esperado {count} linhas, obtido {len(lines)}"
        for line in lines:
            json.loads(line)  # lança se inválido
        print(f"  concurrent_writes: OK — {len(lines)} linhas válidas")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Testes de segurança e concorrência ===")
    print()

    print("[concorrência]")
    test_correlator_thread_safety()
    test_correlator_no_duplicate_flush()

    print()
    print("[validação de config]")
    test_stdout_blocked_in_production()
    test_dangerous_path_rejected()
    test_safe_path_allowed()
    test_invalid_filter_action_rejected()
    test_config_hash_computed()

    print()
    print("[file output]")
    test_file_output_permissions()
    test_file_output_concurrent_writes()

    print()
    print("Todos os testes de segurança passaram.")
