"""Command-line entry point for SentinelGuard."""

import argparse
import json
import sys
from pathlib import Path

from detector import detect_brute_force, load_events


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect repeated failed logins in JSON logs.")
    parser.add_argument("logs", type=Path, help="Path to a UTF-8 JSON log array")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    try:
        alerts = detect_brute_force(
            load_events(args.logs), threshold=args.threshold, window_seconds=args.window_seconds
        )
    except OSError:
        print("Error: unable to read the log file.", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps([alert.to_dict() for alert in alerts], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
