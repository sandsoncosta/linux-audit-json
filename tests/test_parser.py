"""
tests/test_parser.py — Testes unitários do parser de linhas do auditd.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from parser import parse_line, _parse_fields


def test_parse_syscall_line():
    raw = (
        'type=SYSCALL msg=audit(1700000000.123:4567): arch=c000003e '
        'syscall=59 success=yes exit=0 a0=7f1234 a1=0 a2=0 a3=0 '
        'items=2 ppid=1000 pid=2000 auid=1001 uid=0 gid=0 '
        'euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 '
        'ses=1 comm="ls" exe="/usr/bin/ls" key=(null)'
    )
    record = parse_line(raw)
    assert record is not None
    assert record.record_type == "SYSCALL"
    assert record.event_id == "4567"
    assert record.timestamp == 1700000000.123
    assert record.fields["syscall"] == "59"
    assert record.fields["comm"] == "ls"
    assert record.fields["exe"] == "/usr/bin/ls"
    assert record.fields["success"] == "yes"


def test_parse_path_line():
    raw = (
        'type=PATH msg=audit(1700000000.123:4567): item=0 '
        'name="/usr/bin/ls" inode=123456 dev=fd:01 mode=0100755 '
        'ouid=0 ogid=0 rdev=00:00 nametype=NORMAL'
    )
    record = parse_line(raw)
    assert record is not None
    assert record.record_type == "PATH"
    assert record.fields["name"] == "/usr/bin/ls"


def test_parse_proctitle_hex():
    raw = (
        'type=PROCTITLE msg=audit(1700000000.123:4567): '
        'proctitle=6C73002D6C61'  # "ls\x00-la" hex encoded
    )
    record = parse_line(raw)
    assert record is not None
    # Deve decodificar o hex e substituir \x00 por espaço
    assert "ls" in record.fields.get("proctitle", "")


def test_parse_eoe_line():
    raw = "type=EOE msg=audit(1700000000.123:4567):"
    record = parse_line(raw)
    assert record is not None
    assert record.record_type == "EOE"
    assert record.event_id == "4567"


def test_parse_invalid_line_returns_none():
    assert parse_line("") is None
    assert parse_line("# comentário") is None
    assert parse_line("garbage line without format") is None


def test_parse_kv_with_spaces():
    raw = (
        'type=USER_AUTH msg=audit(1700000000.000:100): '
        'pid=500 uid=0 auid=1000 ses=5 '
        'msg=\'op=PAM:authentication acct="joao" exe="/usr/sbin/sshd" '
        'hostname=192.168.1.10 addr=192.168.1.10 terminal=ssh res=success\''
    )
    record = parse_line(raw)
    # Mesmo sem parsear o msg aninhado completamente, deve retornar um record
    assert record is not None
    assert record.record_type == "USER_AUTH"


if __name__ == "__main__":
    test_parse_syscall_line()
    test_parse_path_line()
    test_parse_proctitle_hex()
    test_parse_eoe_line()
    test_parse_invalid_line_returns_none()
    test_parse_kv_with_spaces()
    print("Todos os testes passaram.")
