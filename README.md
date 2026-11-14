# 🛡️ SentinelGuard

**A Python-based security monitoring and threat detection tool.**

SentinelGuard is an open-source cybersecurity project focused on analyzing security logs, identifying suspicious activities, and generating actionable security alerts.

The goal is to build a lightweight security monitoring tool while exploring real-world concepts in **blue team security, threat detection, and security engineering**.

> 🚧 **Project Status: Early Development (v0.1)**
>
> SentinelGuard is currently under development. Features listed below are planned unless explicitly marked as implemented.

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
- [ ] Load and parse JSON security logs
- [ ] Identify successful and failed login attempts
- [ ] Detect repeated failed logins from the same IP address
- [ ] Generate alerts with timestamps and severity levels
- [ ] Implement automated unit tests

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

Planned initial structure:

```text
sentinelguard/
├── main.py
├── detector.py
├── sample_logs.json
├── tests/
├── .gitignore
├── LICENSE
└── README.md
```

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
