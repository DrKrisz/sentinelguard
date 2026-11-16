# 🛡️ SentinelGuard

**A Python-based security monitoring and threat detection tool.**

SentinelGuard is an open-source cybersecurity project focused on analyzing security logs, identifying suspicious activities, and generating actionable security alerts.

The goal is to build a lightweight security monitoring tool while exploring real-world concepts in **blue team security, threat detection, and security engineering**.

> 🚧 **Project Status: Early Development (v0.1)**
>
> The first offline JSON log detector is implemented. This is a learning and portfolio project, not a production monitoring service.

## 🎯 Project Goals

- Analyze authentication and security event logs.
- Detect potential brute-force login attempts.
- Identify suspicious activity based on configurable detection rules.
- Generate structured security alerts.
- Build a foundation for more advanced security monitoring.

## ⚙️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and detection engine |
| JSON | Security event input and alert output |
| pytest | Automated testing |
| Git & GitHub | Version control |
| GitHub Actions | Planned CI/CD and security checks |

**Future possibilities:** FastAPI, React, PostgreSQL, Docker, and threat intelligence integrations.

## 🔍 Planned Features

### Phase 1: Core Detection Engine
- [x] Load and parse JSON security logs
- [x] Identify successful and failed login attempts
- [x] Detect repeated failed logins from the same IP address
- [x] Generate alerts with timestamps and severity levels
- [x] Implement automated unit tests

### Phase 2: Improved Detection
- [ ] Configurable detection rules
- [ ] Multiple detection patterns
- [ ] Alert export to JSON
- [ ] Log filtering and basic reporting

### Phase 3: Web Dashboard
- [ ] REST API using FastAPI
- [ ] React-based security dashboard
- [ ] Event visualization and alert management
- [ ] Containerized deployment using Docker

## 📁 Project Structure

Current structure:

```text
sentinelguard/
├── main.py
├── detector.py
├── sample_logs.json
├── pyproject.toml
├── tests/
├── .gitignore
├── LICENSE
└── README.md
```

## Run the first version

Requires Python 3.12 or later. The application uses only the standard library.
From the project folder:

```powershell
python main.py sample_logs.json
python main.py sample_logs.json --threshold 3 --window-seconds 60
```

The supplied synthetic example produces one medium-severity alert for
`192.0.2.10`. Alerts are printed as a JSON array; `[]` means no rule matched.
Exit code 0 means analysis completed (including when alerts exist); 2 means
invalid input or a file error. Invalid batches produce no partial alerts.

### Log format

The input is a UTF-8 JSON array. Every event must contain exactly these three
string fields:

```json
[
  {
    "timestamp": "2026-01-01T12:00:00Z",
    "source_ip": "192.0.2.10",
    "outcome": "failure"
  }
]
```

`timestamp` must be an ISO 8601 date and time with a timezone. `source_ip`
must be an IPv4 or IPv6 address (without a scope suffix). `outcome` must be
`success` or `failure`. Addresses and timezones are normalized before detection.

### How detection works

1. Validate the complete batch before analyzing it.
2. Sort events by timestamp, so input order does not affect the result.
3. Keep a rolling list of recent failures for each IP address.
4. Alert when 5 failures occur within 300 seconds, including the exact boundary.

There is at most one alert per IP per run, emitted when the threshold is first
reached. Its count describes failures at that moment, not the final batch total.
Successes do not count as failures and do not reset the failure window. The
threshold is configurable (minimum 2); the time window is 1–86400 seconds.

### Security decisions and limitations

- JSON is parsed as data; no log content is executed. File reads are limited to
  5 MiB and batches to 20,000 events to bound resource use for this offline tool.
- Malformed records stop analysis instead of disappearing silently. Error
  messages identify the record number without repeating untrusted log content.
- Alerts contain only the source IP and detection metadata, without passwords
  or raw log messages. Real IP addresses can still be sensitive information.
- Shared IPs, forgotten passwords, and broken clients can cause false positives.
  An alert is a reason to investigate, not proof of an attack.
- Slow attacks, attacks spread across many IPs, and failures split across
  separate runs can be missed. There is no persistent state, live collection,
  automatic blocking, or verification that a log is authentic.
- Duplicate records count as separate attempts. Deduplicate at the source;
  identical timestamps alone cannot prove that two attempts are duplicates.

### Development checks

```powershell
python -m pip install "pytest>=9,<10" "ruff>=0.17,<1" "bandit>=1.9,<2"
python -m pytest -q
python -m ruff check detector.py main.py tests
python -m bandit -q detector.py main.py
```

Tests cover normal activity, exact window boundaries, separate IPs, successful
logins, out-of-order records, timezone/IPv6 normalization, invalid inputs,
resource limits, and command-line behavior.

For learning, start with `sample_logs.json`, then read `parse_events()` in
`detector.py`, followed by `detect_brute_force()`. Change a sample failure to
`success` and rerun the default command: the alert disappears because only four
failed attempts remain. The tests describe the expected behavior in small cases.

## 🔐 Security Considerations

SentinelGuard is designed for defensive security research and educational purposes.

- Use synthetic or explicitly authorized log data.
- Avoid committing credentials, API keys, or sensitive information.
- Validate and safely parse untrusted log inputs.
- Document detection limitations and potential false positives.

## 📚 Learning Objectives

This project explores:

- Security monitoring and log analysis
- Brute-force attack detection
- Python software development
- Detection engineering
- Automated testing
- Secure software development practices

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**Developed by [DrKrisz](https://github.com/DrKrisz)**

*Building practical cybersecurity tools through hands-on development.*
