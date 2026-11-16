"""Validate authentication logs and detect bursts of failed logins."""

import json
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 20_000


@dataclass(frozen=True, slots=True)
class LoginEvent:
    timestamp: datetime
    source_ip: str
    outcome: str


@dataclass(frozen=True, slots=True)
class Alert:
    rule: str
    severity: str
    source_ip: str
    timestamp: str
    window_start: str
    failed_attempts: int
    window_seconds: int

    def to_dict(self) -> dict[str, str | int]:
        """Return a JSON-ready alert without raw log content."""
        return asdict(self)


def parse_events(data: object) -> list[LoginEvent]:
    """Reject an entire batch if any record is invalid; never silently skip it."""
    if not isinstance(data, list) or len(data) > MAX_EVENTS:
        raise ValueError(f"Logs must be a JSON array with at most {MAX_EVENTS} events.")
    events: list[LoginEvent] = []
    for index, record in enumerate(data):
        prefix = f"Event {index + 1}"
        if not isinstance(record, dict) or set(record) != {"timestamp", "source_ip", "outcome"}:
            raise ValueError(f"{prefix}: expected timestamp, source_ip and outcome fields only.")
        if not all(isinstance(value, str) for value in record.values()):
            raise ValueError(f"{prefix}: all fields must be strings.")
        if record["outcome"] not in {"success", "failure"}:
            raise ValueError(f"{prefix}: outcome must be success or failure.")
        timestamp = record["timestamp"]
        if len(timestamp) > 40 or "T" not in timestamp:
            raise ValueError(f"{prefix}: expected an ISO 8601 timestamp with timezone.")
        try:
            moment = datetime.fromisoformat(timestamp)
            if moment.tzinfo is None:
                raise ValueError("Missing timezone")
            moment = moment.astimezone(UTC)
            address = record["source_ip"]
            if len(address) > 45 or "%" in address:
                raise ValueError("Invalid IP address")
            address = str(ip_address(address))
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"{prefix}: invalid timestamp or IP address.") from exc
        events.append(LoginEvent(moment, address, record["outcome"]))
    return events


def load_events(path: Path) -> list[LoginEvent]:
    """Read a bounded UTF-8 JSON file using Python's safe JSON parser."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("Log file exceeds the 5 MiB limit.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Log file must contain valid UTF-8 JSON.") from exc
    return parse_events(data)


def detect_brute_force(
    events: list[LoginEvent], *, threshold: int = 5, window_seconds: int = 300
) -> list[Alert]:
    """Alert once per IP per batch when a rolling inclusive window reaches threshold.

    Pass validated events from parse_events/load_events. Successful logins do not
    erase failures: an attacker may continue guessing after another user logs in.
    """
    if type(threshold) is not int or threshold < 2:
        raise ValueError("Threshold must be an integer of at least 2.")
    if type(window_seconds) is not int or not 1 <= window_seconds <= 86_400:
        raise ValueError("Window must be an integer from 1 to 86400 seconds.")
    window = timedelta(seconds=window_seconds)
    failures: dict[str, deque[datetime]] = defaultdict(deque)
    alerted: set[str] = set()
    alerts: list[Alert] = []
    for event in sorted(events, key=lambda item: item.timestamp):
        if event.outcome != "failure" or event.source_ip in alerted:
            continue
        recent = failures[event.source_ip]
        # Compare differences instead of subtracting from datetime.min.
        while recent and event.timestamp - recent[0] > window:
            recent.popleft()
        recent.append(event.timestamp)
        if len(recent) >= threshold:
            alerts.append(
                Alert(
                    rule="repeated_failed_logins",
                    severity="medium",
                    source_ip=event.source_ip,
                    timestamp=event.timestamp.isoformat(),
                    window_start=recent[0].isoformat(),
                    failed_attempts=len(recent),
                    window_seconds=window_seconds,
                )
            )
            alerted.add(event.source_ip)
    return alerts
