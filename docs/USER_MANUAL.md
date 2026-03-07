# HIDS User Manual

## Table of Contents
1. [Introduction](#introduction)
2. [System Overview](#system-overview)
3. [Starting and Stopping the System](#starting-and-stopping-the-system)
4. [Configuration Reference](#configuration-reference)
5. [Monitoring Modules](#monitoring-modules)
6. [Understanding Events and Alerts](#understanding-events-and-alerts)
7. [Web Dashboard](#web-dashboard)
8. [Email Alerts](#email-alerts)
9. [Log Files](#log-files)
10. [Baseline Management](#baseline-management)
11. [Command-Line Reference](#command-line-reference)
12. [Common Workflows](#common-workflows)

---

## Introduction

The **ARGUS Host-Based Intrusion Detection System (HIDS)** monitors a Fedora host in real time for signs of intrusion, misuse, and policy violations. It consists of two components:

- **Agent** — runs on the monitored host (requires root), collects security events from four monitoring modules, and forwards them to the server.
- **Server** — receives events, stores them in a SQLite database, serves a web dashboard, and sends email alerts for critical findings.

---

## System Overview

```
┌──────────────────────────────────────────┐
│               HIDS Agent                │
│                                          │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ File Monitor│  │  Auth Monitor    │  │
│  └─────────────┘  └──────────────────┘  │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │Process Mon. │  │  Network Monitor │  │
│  └─────────────┘  └──────────────────┘  │
│              │ JSON events               │
└──────────────┼───────────────────────────┘
               ▼
┌──────────────────────────────────────────┐
│           HIDS Server (Flask)            │
│  /api/events  →  SQLite DB               │
│  Dashboard    →  http://localhost:5000   │
│  Email Alerts →  Gmail / SMTP            │
└──────────────────────────────────────────┘
```

### Scan Schedule (default)

| Module | Interval |
|---|---|
| File Integrity Monitor | Every 60 seconds (configurable via `scan_interval`) |
| Authentication Monitor | Every 30 seconds |
| Process Monitor | Every 2 minutes |
| Network Monitor | Every 1 minute |
| Heartbeat | Every 5 minutes |

---

## Starting and Stopping the System

### Start the Server

```bash
cd hids-project-complete/server/api
source ../../venv/bin/activate
python3 server.py
```

The server listens on `http://localhost:5000` by default.

### Start the Agent

Open a second terminal:

```bash
cd hids-project-complete/agent
source ../venv/bin/activate
sudo python3 main.py
```

> **Fedora note:** Root is required to read `/var/log/secure` and access full process/network details. Alternatively, add your user to the `adm` group: `sudo usermod -aG adm $USER` (then log out and back in).

### Stop the Agent

Press `Ctrl+C` in the agent terminal, or send SIGTERM:

```bash
sudo kill -TERM <agent_pid>
```

The agent sends a shutdown event to the server before exiting.

### Skip the Initial Scan

To suppress the first full scan on startup (useful after a reboot when many files may have changed legitimately):

```bash
sudo python3 main.py --skip-initial-scan
```

---

## Configuration Reference

All agent configuration lives in `agent/config.json`. The file is divided into five sections.

### `agent` Section

| Key | Default | Description |
|---|---|---|
| `name` | `"fedora-agent-01"` | Identifier for this agent shown in the dashboard |
| `server_url` | `"http://localhost:5000/api/events"` | URL of the HIDS server events endpoint |
| `scan_interval` | `60` | Seconds between file integrity scans |

### `file_monitor` Section

| Key | Description |
|---|---|
| `enabled` | Enable or disable the module (`true`/`false`) |
| `monitored_paths` | List of files and directories to hash and watch |
| `critical_paths` | Subset of paths that always produce high/critical alerts on any change |
| `exclude_extensions` | File extensions to skip (e.g. `.log`, `.tmp`) |
| `baseline_file` | Path to the stored SHA256 baseline |

### `auth_monitor` Section

| Key | Description |
|---|---|
| `log_files` | Log files to tail — use `["/var/log/secure"]` on Fedora |
| `brute_force_threshold` | Failed login attempts before a brute-force alert fires |
| `brute_force_window` | Time window in seconds for the threshold count |
| `suspicious_usernames` | Usernames that trigger an extra alert on any login attempt |

### `process_monitor` Section

| Key | Description |
|---|---|
| `cpu_threshold` | CPU % above which a process is flagged |
| `memory_threshold` | Memory % above which a process is flagged |
| `whitelist_processes` | Process names that are never alerted on |
| `suspicious_process_names` | Process names that always produce an alert |
| `suspicious_commands` | Command-line substrings that produce a critical alert |
| `suspicious_paths` | Executable paths that are inherently suspicious (e.g. `/tmp`) |
| `suspicious_ports` | Remote ports that trigger a network-connection alert per process |

### `network_monitor` Section

| Key | Description |
|---|---|
| `suspicious_ports` | Ports whose use triggers a high/critical alert |
| `allowed_outbound_ports` | Ports considered normal for outbound traffic |
| `port_scan_threshold` | Unique ports accessed by one IP within the window before scan alert |
| `check_tor_connections` | Alert on connections to known Tor ports |
| `check_proxy_usage` | Alert on connections to common proxy ports |

---

## Monitoring Modules

### File Integrity Monitor (`file_monitor.py`)

Computes SHA256 hashes of all files under `monitored_paths` and compares them against a stored baseline. On first run it creates the baseline and generates no alerts. On subsequent runs it reports:

- **`file_modified`** — hash changed since baseline
- **`file_deleted`** — file present in baseline but now missing
- **`file_created`** — new file detected inside a `critical_path`

Non-critical new files are silently added to the baseline.

### Authentication Monitor (`auth_monitor.py`)

Tails `/var/log/secure` (Fedora) using a saved byte-offset so it never re-reads old entries. Detects:

- SSH failed passwords and invalid user attempts
- SSH successful logins
- Brute-force attacks (configurable threshold + window)
- Sudo command executions and sudo authentication failures
- User account creation and deletion
- Password changes

### Process Monitor (`process_monitor.py`)

Iterates all running processes via `psutil` every two minutes. Checks each process for:

- Suspicious name match (netcat, xmrig, meterpreter, etc.)
- Suspicious command-line patterns (reverse shells, base64 decode, wget/curl)
- Execution from suspicious paths (`/tmp`, `/dev/shm`, etc.)
- High CPU or memory usage (potential crypto miner)
- Cryptocurrency miner indicators (process name + known mining pool ports)
- Reverse shell patterns in the command line
- SUID binaries running from writable directories

Processes listed in `whitelist_processes` are skipped entirely.

### Network Monitor (`network_monitor.py`)

Reads live connection state via `psutil.net_connections()`. Checks for:

- Connections to known suspicious or blacklisted ports
- Connections to user-defined blacklisted IPs
- New listening ports not present in the baseline
- Port scanning activity from a single remote IP
- Connections to Tor ports (9050, 9051, etc.)
- Connections to common proxy ports (3128, 8080, 1080, etc.)
- Unusually high per-process connection rate

---

## Understanding Events and Alerts

Every event is a JSON object forwarded to the server and also appended to `agent/logs/events.log`.

### Severity Levels

| Level | Meaning | Example |
|---|---|---|
| `info` | Normal activity worth recording | Successful SSH login, sudo command executed |
| `medium` | Unusual but not necessarily malicious | File modified in non-critical path |
| `high` | Likely requires investigation | Invalid user SSH attempt, SUID binary, new listening port |
| `critical` | Active attack indicator — act immediately | Brute force confirmed, reverse shell, crypto miner, critical file deleted |

### Event Fields

```json
{
  "event_type": "brute_force_attack",
  "severity": "critical",
  "timestamp": "2026-03-07T14:22:01.123456",
  "username": "root",
  "source_ip": "203.0.113.5",
  "attempt_count": 7,
  "mitre_technique": "T1110",
  "description": "Brute force attack detected: 7 failed login attempts...",
  "agent_info": {
    "agent_name": "fedora-agent-01",
    "hostname": "myhost",
    "ip_address": "192.168.1.10"
  }
}
```

---

## Web Dashboard

Navigate to `http://localhost:5000` in any browser while the server is running.

The dashboard shows:

- **Live event feed** — newest events at the top, colour-coded by severity
- **Charts** — event counts over time, breakdown by type and severity
- **Agent status** — last heartbeat time per registered agent

The dashboard auto-refreshes every few seconds via JavaScript polling.

---

## Email Alerts

Email alerts are sent for `critical` and `high` severity events. To configure:

```bash
cd hids-project-complete/server
python3 tools/configure_email.py
```

The wizard saves credentials to `server/alerts/email_config.json`. Gmail users must create an **App Password** (Settings → Security → 2-Step Verification → App passwords) and use that instead of their account password.

---

## Log Files

| Path | Contents |
|---|---|
| `agent/logs/events.log` | All events generated by the agent (JSONL format, one event per line) |
| `server/database/hids.db` | SQLite database — all events received by the server |

To tail events live:

```bash
tail -f agent/logs/events.log | python3 -m json.tool
```

To query the database directly:

```bash
cd hids-project-complete/tools
python3 query_events.py
```

---

## Baseline Management

### First Run

On first run the File Integrity Monitor automatically creates `data/file_baseline.json` and skips the integrity check. All subsequent runs compare against this baseline.

### Rebuilding After a System Update

After running `sudo dnf upgrade` or making intentional system changes, rebuild the baseline so legitimate changes are not flagged:

```bash
cd agent
sudo python3 main.py --rebuild-baseline
```

This rebuilds the baseline and exits without starting the monitoring loop.

### Manual Rebuild via Python

```python
from modules.file_monitor import FileIntegrityMonitor
import json

with open('config.json') as f:
    config = json.load(f)

fim = FileIntegrityMonitor(config['file_monitor'])
fim.rebuild_baseline()
```

---

## Command-Line Reference

```
usage: main.py [-h] [--config CONFIG] [--rebuild-baseline] [--skip-initial-scan]

options:
  --config CONFIG         Path to configuration file (default: config.json)
  --rebuild-baseline      Rebuild file integrity baseline and exit
  --skip-initial-scan     Skip initial scans on startup
```

---

## Common Workflows

### Investigating a Brute-Force Alert

1. Note the `source_ip` from the event.
2. Check how many attempts occurred: `grep brute_force agent/logs/events.log | python3 -m json.tool`
3. Confirm in the raw log: `sudo grep <source_ip> /var/log/secure`
4. Block the IP with firewalld: `sudo firewall-cmd --add-rich-rule='rule family=ipv4 source address=<IP> drop'`

### Investigating a File Integrity Alert

1. Identify `filepath`, `old_hash`, and `new_hash` from the event.
2. Check who modified the file: `sudo ausearch -f <filepath> -ts recent`
3. Diff the file against a known-good backup if available.
4. If the change is legitimate (e.g. after a package update), run `--rebuild-baseline`.

### Silencing False Positives for a Process

Add the process name to `whitelist_processes` in `config.json`:

```json
"whitelist_processes": ["systemd", "sshd", "crond", "httpd", "my-trusted-app"]
```

Then restart the agent.

### Disabling a Module Temporarily

Set `"enabled": false` for the relevant module in `config.json` and restart the agent. The module will be skipped entirely without affecting the others.
