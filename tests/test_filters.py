"""
tests/test_filters.py — Testes do motor de filtros.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from config_loader import FilterConfig
from filters import FilterEngine
from models import AuditEvent, AuditRecord


def make_event(
    event_id="1",
    record_types=None,
    exe="",
    uid="0",
    auid="0",
    success="yes",
    syscall="",
    paths=None,
    comm="",
) -> AuditEvent:
    fields = {
        "exe": exe,
        "uid": uid,
        "auid": auid,
        "success": success,
        "syscall": syscall,
        "comm": comm,
    }
    records = [
        AuditRecord(
            record_type=rt,
            timestamp=1700000000.0,
            event_id=event_id,
            fields=dict(fields, name=paths[0] if paths else ""),
            raw="",
        )
        for rt in (record_types or ["SYSCALL"])
    ]
    return AuditEvent(
        event_id=event_id,
        timestamp=1700000000.0,
        host="testhost",
        records=records,
        record_types=record_types or ["SYSCALL"],
        summary={"exe": exe, "comm": comm},
    )


def test_drop_by_executable():
    fc = FilterConfig(name="drop-ls", action="drop", executables=["/usr/bin/ls"])
    engine = FilterEngine({"drop-ls": fc})
    action, name = engine.evaluate(make_event(exe="/usr/bin/ls"))
    assert action == "drop"
    assert name == "drop-ls"


def test_no_match_returns_pass():
    fc = FilterConfig(name="drop-ls", action="drop", executables=["/usr/bin/ls"])
    engine = FilterEngine({"drop-ls": fc})
    action, name = engine.evaluate(make_event(exe="/usr/bin/cat"))
    assert action == "pass"


def test_drop_by_success():
    fc = FilterConfig(name="drop-success", action="drop", success="yes")
    engine = FilterEngine({"drop-success": fc})
    assert engine.evaluate(make_event(success="yes"))[0] == "drop"
    assert engine.evaluate(make_event(success="no"))[0] == "pass"


def test_drop_by_record_type():
    fc = FilterConfig(name="drop-cwd", action="drop", record_types=["CWD"])
    engine = FilterEngine({"drop-cwd": fc})
    assert engine.evaluate(make_event(record_types=["CWD"]))[0] == "drop"
    assert engine.evaluate(make_event(record_types=["SYSCALL"]))[0] == "pass"


def test_tag_action():
    fc = FilterConfig(name="tag-auth", action="tag", tag="auth",
                      record_types=["USER_AUTH"])
    engine = FilterEngine({"tag-auth": fc})
    event = make_event(record_types=["USER_AUTH"])
    action, name = engine.evaluate(event)
    assert action == "tag"


def test_priority_order():
    """Filtro de menor priority (10) deve ser avaliado antes do de priority 20."""
    fc1 = FilterConfig(name="allow-root", action="allow", priority=10, uids=["0"])
    fc2 = FilterConfig(name="drop-all", action="drop", priority=20)
    engine = FilterEngine({"allow-root": fc1, "drop-all": fc2})
    # uid=0 casa com allow-root (priority 10) → retorna allow
    action, name = engine.evaluate(make_event(uid="0"))
    assert action == "allow"
    assert name == "allow-root"


if __name__ == "__main__":
    test_drop_by_executable()
    test_no_match_returns_pass()
    test_drop_by_success()
    test_drop_by_record_type()
    test_tag_action()
    test_priority_order()
    print("Todos os testes passaram.")
