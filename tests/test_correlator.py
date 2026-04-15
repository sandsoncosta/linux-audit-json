"""
tests/test_correlator.py — Testes do correlator de eventos.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from config_loader import OptionsConfig
from correlator import Correlator
from models import AuditRecord


def make_record(rtype: str, event_id: str, ts: float = 1700000000.0, **fields) -> AuditRecord:
    return AuditRecord(
        record_type=rtype,
        timestamp=ts,
        event_id=event_id,
        fields={"_record_type": rtype, **fields},
        raw=f"type={rtype} msg=audit({ts}:{event_id}):",
    )


def make_options(timeout: float = 0.1) -> OptionsConfig:
    opts = OptionsConfig()
    opts.event_timeout = timeout
    opts.hostname = "testhost"
    return opts


def test_correlate_with_eoe():
    """Evento deve ser emitido ao receber EOE."""
    corr = Correlator(make_options())
    assert corr.feed(make_record("SYSCALL", "100")) is None
    assert corr.feed(make_record("PATH", "100")) is None
    assert corr.feed(make_record("CWD", "100")) is None
    event = corr.feed(make_record("EOE", "100"))
    assert event is not None
    assert event.event_id == "100"
    assert len(event.records) == 3
    assert set(event.record_types) == {"SYSCALL", "PATH", "CWD"}


def test_correlate_multiple_events():
    """Dois eventos distintos não se misturam."""
    corr = Correlator(make_options())
    corr.feed(make_record("SYSCALL", "1"))
    corr.feed(make_record("SYSCALL", "2"))

    e1 = corr.feed(make_record("EOE", "1"))
    e2 = corr.feed(make_record("EOE", "2"))

    assert e1.event_id == "1"
    assert e2.event_id == "2"
    assert len(e1.records) == 1
    assert len(e2.records) == 1


def test_timeout_flush():
    """Eventos sem EOE devem ser emitidos por timeout."""
    corr = Correlator(make_options(timeout=0.05))
    corr.feed(make_record("SYSCALL", "999"))
    assert corr.pending_count() == 1

    time.sleep(0.1)
    expired = corr.flush_expired()
    assert len(expired) == 1
    assert expired[0].event_id == "999"
    assert corr.pending_count() == 0


def test_host_in_event():
    corr = Correlator(make_options())
    corr.feed(make_record("SYSCALL", "42"))
    event = corr.feed(make_record("EOE", "42"))
    assert event.host == "testhost"


if __name__ == "__main__":
    test_correlate_with_eoe()
    test_correlate_multiple_events()
    test_timeout_flush()
    test_host_in_event()
    print("Todos os testes passaram.")
