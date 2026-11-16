"""Synthetic cases demonstrating the rule and its boundaries."""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from detector import MAX_EVENTS, MAX_FILE_BYTES, detect_brute_force, load_events, parse_events


def record(seconds: int = 0, ip: str = "192.0.2.10", outcome: str = "failure") -> dict[str, str]:
    return {
        "timestamp": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)).isoformat(),
        "source_ip": ip,
        "outcome": outcome,
    }


def test_threshold_and_alert_contents() -> None:
    alerts = detect_brute_force(parse_events([record(i) for i in range(5)]))
    assert len(alerts) == 1
    assert alerts[0].to_dict() == {
        "rule": "repeated_failed_logins",
        "severity": "medium",
        "source_ip": "192.0.2.10",
        "timestamp": "2026-01-01T00:00:04+00:00",
        "window_start": "2026-01-01T00:00:00+00:00",
        "failed_attempts": 5,
        "window_seconds": 300,
    }


@pytest.mark.parametrize(
    "data",
    [
        [],
        [record(i) for i in range(4)],
        [record(i * 301) for i in range(5)],
        [record(i, ip=f"192.0.2.{i + 1}") for i in range(5)],
        [record(i, outcome="success") for i in range(10)],
    ],
)
def test_normal_activity_does_not_alert(data: list[dict[str, str]]) -> None:
    assert detect_brute_force(parse_events(data)) == []


@pytest.mark.parametrize(("last", "expected"), [(300, 1), (301, 0)])
def test_inclusive_window_boundary(last: int, expected: int) -> None:
    events = parse_events([record(i) for i in [0, 100, 150, 200, last]])
    assert len(detect_brute_force(events)) == expected


def test_unsorted_logs_success_and_alert_suppression() -> None:
    data = [record(i) for i in range(20)] + [record(2, outcome="success")]
    assert len(detect_brute_force(parse_events(list(reversed(data))))) == 1


def test_multiple_sources_alert_independently() -> None:
    data = [record(i, ip=ip) for ip in ["192.0.2.1", "2001:db8::1"] for i in range(5)]
    assert {a.source_ip for a in detect_brute_force(parse_events(data))} == {
        "192.0.2.1",
        "2001:db8::1",
    }


def test_timezone_and_ipv6_normalization() -> None:
    data = record(ip="2001:0db8:0:0:0:0:0:1")
    data["timestamp"] = "2026-01-01T01:00:00+01:00"
    event = parse_events([data])[0]
    assert event.timestamp == datetime(2026, 1, 1, tzinfo=UTC)
    assert event.source_ip == "2001:db8::1"


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        [None],
        [{}],
        [record() | {"extra": "x"}],
        [record() | {"source_ip": "bad\naddress"}],
        [record() | {"source_ip": "fe80::1%eth0"}],
        [record() | {"timestamp": "2026-01-01T00:00:00"}],
        [record() | {"timestamp": "yesterday"}],
        [record() | {"outcome": "unknown"}],
        [record() | {"outcome": 1}],
        [record()] * (MAX_EVENTS + 1),
    ],
)
def test_invalid_input_is_rejected(data: object) -> None:
    with pytest.raises(ValueError):
        parse_events(data)


@pytest.mark.parametrize(("threshold", "window"), [(1, 300), (True, 300), (5, 0), (5, 86401)])
def test_invalid_rule_settings(threshold: int, window: int) -> None:
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=threshold, window_seconds=window)


@pytest.mark.parametrize("raw", [b"{", b"\xff", b"[" * 2000, b" " * (MAX_FILE_BYTES + 1)])
def test_invalid_files(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "logs.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        load_events(path)


def test_file_and_cli(tmp_path: Path) -> None:
    path = tmp_path / "logs.json"
    path.write_text(json.dumps([record(i) for i in range(5)]), encoding="utf-8")
    assert len(load_events(path)) == 5
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "main.py"), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)[0]["failed_attempts"] == 5
    path.write_text("not JSON", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(root / "main.py"), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "valid UTF-8 JSON" in result.stderr
