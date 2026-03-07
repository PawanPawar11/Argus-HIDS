# HIDS Testing Report

**Project:** ARGUS Host-Based Intrusion Detection System  
**Platform:** Fedora 40/41  
**Test Date:** March 2026  
**Status:** ✅ All core detection scenarios passed

---

## Table of Contents
1. [Test Environment](#test-environment)
2. [Test Methodology](#test-methodology)
3. [Module Test Results](#module-test-results)
   - [File Integrity Monitor](#1-file-integrity-monitor)
   - [Authentication Monitor](#2-authentication-monitor)
   - [Process Monitor](#3-process-monitor)
   - [Network Monitor](#4-network-monitor)
4. [End-to-End Pipeline Tests](#end-to-end-pipeline-tests)
5. [Performance Tests](#performance-tests)
6. [False Positive Analysis](#false-positive-analysis)
7. [Known Limitations](#known-limitations)
8. [Summary](#summary)

---

## Test Environment

| Item | Value |
|---|---|
| OS | Fedora 41 (kernel 6.11) |
| Python | 3.12.7 |
| Agent user | root |
| Server host | localhost:5000 |
| Database | SQLite 3.45 |
| Test scripts | `tests/simulate_attacks.sh`, `simulate_process_attacks.sh`, `simulate_network_attacks.sh` |

### Python Dependencies Used in Tests

```
psutil 5.9.x
requests 2.31.x
schedule 1.2.x
```

---

## Test Methodology

Each module was tested in three stages:

1. **Unit** — instantiate the monitor class in isolation, feed it synthetic input, assert correct event output.
2. **Integration** — run the full agent against a live Fedora system with `simulate_attacks.sh` generating real activity.
3. **Pipeline** — confirm that events reach the server, are stored in SQLite, appear in the dashboard, and trigger email alerts where configured.

Severity assertions follow the rules coded in each module:

| Path type | Event type | Expected severity |
|---|---|---|
| Critical path | `file_modified` | `critical` |
| Critical path | `file_deleted` | `critical` |
| Critical path | `file_created` | `high` |
| Non-critical path | `file_modified` | `medium` |
| Non-critical path | `file_deleted` | `high` |
| Brute force confirmed | `brute_force_attack` | `critical` |
| Reverse shell pattern | `reverse_shell_detected` | `critical` |
| Crypto miner name | `cryptocurrency_miner_detected` | `critical` |
| New listening port | `new_listening_port` | `medium` / `critical` |

---

## Module Test Results

### 1. File Integrity Monitor

**Test cases and results:**

| # | Scenario | Expected Event | Severity | Result |
|---|---|---|---|---|
| FIM-01 | First run — no baseline exists | Baseline created, no alerts | — | ✅ Pass |
| FIM-02 | No changes since baseline | No events | — | ✅ Pass |
| FIM-03 | Modify `/etc/passwd` | `file_modified` | `critical` | ✅ Pass |
| FIM-04 | Modify `/etc/hosts` (non-critical) | `file_modified` | `medium` | ✅ Pass |
| FIM-05 | Delete `/etc/sudoers` | `file_deleted` | `critical` | ✅ Pass |
| FIM-06 | Delete file in `/usr/bin` | `file_deleted` | `high` | ✅ Pass |
| FIM-07 | Create new file in `/root/.ssh` | `file_created` | `high` | ✅ Pass |
| FIM-08 | Create new file in `/usr/bin` | No event (silent baseline update) | — | ✅ Pass |
| FIM-09 | Log rotation — file shrinks | Resets to offset 0, no crash | — | ✅ Pass |
| FIM-10 | File with excluded extension (`.log`) | No event | — | ✅ Pass |
| FIM-11 | `--rebuild-baseline` flag | Baseline recreated, agent exits | — | ✅ Pass |
| FIM-12 | Permission-denied file | Silently skipped, no crash | — | ✅ Pass |

**How FIM-03 was simulated:**

```bash
# In simulate_attacks.sh
echo "testuser:x:1001:1001::/home/testuser:/bin/bash" >> /etc/passwd
sleep 70  # wait for next scan cycle
grep file_modified /home/user/agent/logs/events.log
```

---

### 2. Authentication Monitor

**Test cases and results:**

| # | Scenario | Expected Event | Severity | Result |
|---|---|---|---|---|
| AUTH-01 | Single SSH failed password | `ssh_failed_login` | `medium` | ✅ Pass |
| AUTH-02 | 5 failed logins in 300 s (same IP) | `brute_force_attack` | `critical` | ✅ Pass |
| AUTH-03 | Successful SSH login | `ssh_successful_login` | `info` | ✅ Pass |
| AUTH-04 | Login attempt with username `root` | `suspicious_username_attempt` | `high` | ✅ Pass |
| AUTH-05 | Invalid user attempt | `invalid_user_attempt` | `high` | ✅ Pass |
| AUTH-06 | `sudo` command executed | `sudo_command_executed` | `info` | ✅ Pass |
| AUTH-07 | Sudo with wrong password | `sudo_auth_failure` | `high` | ✅ Pass |
| AUTH-08 | `useradd` in log | `user_account_created` | `high` | ✅ Pass |
| AUTH-09 | `userdel` in log | `user_account_deleted` | `high` | ✅ Pass |
| AUTH-10 | `passwd` change in log | `password_changed` | `medium` | ✅ Pass |
| AUTH-11 | Log file absent | Warning printed, no crash | — | ✅ Pass |
| AUTH-12 | Re-read after log rotation | Resets offset, re-reads from 0 | — | ✅ Pass |

**Brute-force simulation (AUTH-02):**

```bash
# In simulate_attacks.sh — 6 rapid SSH failures
for i in $(seq 1 6); do
    ssh -o BatchMode=yes -o ConnectTimeout=2 fakeuser@127.0.0.1 2>/dev/null || true
    sleep 10
done
```

The agent fired `ssh_failed_login` six times and one `brute_force_attack` (threshold = 5) within the 300-second window. After the brute-force event the attempt counter was reset, preventing duplicate alerts.

---

### 3. Process Monitor

**Test cases and results:**

| # | Scenario | Expected Event | Severity | Result |
|---|---|---|---|---|
| PROC-01 | Process named `nc` running | `suspicious_process_name` | `high` | ✅ Pass |
| PROC-02 | Command contains `bash -i` | `suspicious_command_execution` | `critical` | ✅ Pass |
| PROC-03 | Command contains `/dev/tcp/` | `suspicious_command_execution` | `critical` | ✅ Pass |
| PROC-04 | Executable in `/tmp` | `process_from_suspicious_path` | `high` | ✅ Pass |
| PROC-05 | CPU usage > 80% | `high_resource_usage` | `high` | ✅ Pass |
| PROC-06 | CPU > 90% | `high_resource_usage` | `critical` | ✅ Pass |
| PROC-07 | Process named `xmrig` | `cryptocurrency_miner_detected` | `critical` | ✅ Pass |
| PROC-08 | High CPU + connection to port 3333 | `possible_cryptocurrency_miner` | `high` | ✅ Pass |
| PROC-09 | Reverse shell pattern `nc -e /bin/bash` | `reverse_shell_detected` | `critical` | ✅ Pass |
| PROC-10 | Reverse shell pattern `/dev/tcp/10.0.0.1/4444` | `reverse_shell_detected` | `critical` | ✅ Pass |
| PROC-11 | SUID binary running from `/tmp` | `suspicious_suid_execution` | `critical` | ✅ Pass |
| PROC-12 | Whitelisted process (`systemd`) | No event | — | ✅ Pass |
| PROC-13 | Connection to port 4444 | `suspicious_network_connection` | `high` | ✅ Pass |

**Reverse-shell simulation (PROC-09, from `simulate_process_attacks.sh`):**

```bash
# Simulates the command line without actually connecting
bash -c 'sleep 300 & disown; echo dummy | nc -e /bin/bash 127.0.0.1 4444' &
sleep 130  # wait for process scan cycle
kill %1
```

---

### 4. Network Monitor

**Test cases and results:**

| # | Scenario | Expected Event | Severity | Result |
|---|---|---|---|---|
| NET-01 | New port 4444 listening | `new_listening_port` | `critical` | ✅ Pass |
| NET-02 | New non-suspicious port listening | `new_listening_port` | `medium` | ✅ Pass |
| NET-03 | Outbound connection to port 31337 | `connection_to_suspicious_port` | `high` | ✅ Pass |
| NET-04 | Connection to blacklisted IP | `connection_to_suspicious_ip` | `critical` | ✅ Pass |
| NET-05 | 10+ unique ports from one IP in 60 s | `port_scan_detected` | `critical` | ✅ Pass |
| NET-06 | Connection to port 9050 (Tor) | `tor_connection_detected` | `high` | ✅ Pass |
| NET-07 | Connection to port 3128 (Squid proxy) | `proxy_connection_detected` | `medium` | ✅ Pass |
| NET-08 | Outbound to non-standard port by unknown process | `unusual_outbound_connection` | `medium` | ✅ Pass |
| NET-09 | Outbound by `dnf` (whitelisted process) | No event | — | ✅ Pass |
| NET-10 | Connection from whitelisted IP `127.0.0.1` | No event | — | ✅ Pass |

**Port-scan simulation (NET-05, from `simulate_network_attacks.sh`):**

```bash
# nmap SYN scan against localhost generates rapid multi-port connections
nmap -sS --top-ports 20 127.0.0.1
```

---

## End-to-End Pipeline Tests

| # | Test | Expected Outcome | Result |
|---|---|---|---|
| E2E-01 | Agent starts, server offline | Warning printed, events saved locally to `logs/events.log` | ✅ Pass |
| E2E-02 | Agent sends `agent_startup` event | Event appears in server DB and dashboard | ✅ Pass |
| E2E-03 | Critical event generated | Event stored in DB, email alert sent (if configured) | ✅ Pass |
| E2E-04 | Agent graceful shutdown (Ctrl+C) | `agent_shutdown` event sent before exit | ✅ Pass |
| E2E-05 | Heartbeat every 5 minutes | `agent_heartbeat` event appears in dashboard | ✅ Pass |
| E2E-06 | Agent restarts after crash | Log positions preserved, no duplicate events | ✅ Pass |

---

## Performance Tests

The agent was run continuously for 24 hours on a VM with 2 vCPUs and 2 GB RAM.

| Metric | Value |
|---|---|
| Agent idle CPU usage | < 1% |
| Agent CPU during file scan (400 files) | ~3–5% peak, < 5 s duration |
| Agent RAM usage (resident) | ~35 MB |
| Events generated per hour (quiet system) | ~12 (heartbeats + auth logs) |
| Events generated per hour (simulated attacks) | ~80–120 |
| SQLite DB size after 24 h | ~1.2 MB |

No memory leaks were observed over the 24-hour period. The `psutil.process_iter()` call in the process monitor is the most CPU-intensive operation; it completes in under 2 seconds on a typical Fedora desktop.

---

## False Positive Analysis

| Source | Scenario | Why It Fires | Mitigation |
|---|---|---|---|
| Process Monitor | `python3` with high CPU during compilation | CPU threshold hit | Add `python3` to `whitelist_processes` if acceptable |
| Network Monitor | `dnf` updating packages | Outbound to non-standard port | `dnf` is already in the process whitelist in `network_monitor.py` |
| File Monitor | `/etc/` files updated by `dnf upgrade` | Hash changed legitimately | Run `--rebuild-baseline` after system updates |
| Auth Monitor | Own `sudo` commands | `sudo_command_executed` is `info` severity | Expected; severity is informational only |
| Network Monitor | Development server on port 8888 (Jupyter) | Port 8888 is in `suspicious_ports` | Remove 8888 from `suspicious_ports` in `config.json` if used |

---

## Known Limitations

1. **No kernel-level hooks.** The agent polls at intervals; activity between polls may be missed. A determined attacker who creates and removes a file within a 60-second window will not be detected by the file monitor.
2. **SELinux can block log reads.** On a Fedora system with SELinux in enforcing mode, reading `/var/log/secure` may be denied for non-root users. Always run the agent as root or verify SELinux context.
3. **`psutil.net_connections()` requires root.** Running without root produces an empty connection list, silently disabling the network monitor's connection checks.
4. **File baseline does not capture directory permissions.** Only file content hashes and basic metadata are stored; ACL changes are not detected.
5. **No encrypted transport.** Events are sent over plain HTTP to `localhost`. For remote server deployments, place the server behind HTTPS (e.g. nginx + Let's Encrypt).
6. **Brute-force counter resets on agent restart.** The `failed_attempts` dictionary is in-memory only. A slow brute-force attack spread across an agent restart will not be counted cumulatively.

---

## Summary

| Module | Test Cases | Passed | Failed |
|---|---|---|---|
| File Integrity Monitor | 12 | 12 | 0 |
| Authentication Monitor | 12 | 12 | 0 |
| Process Monitor | 13 | 13 | 0 |
| Network Monitor | 10 | 10 | 0 |
| End-to-End Pipeline | 6 | 6 | 0 |
| **Total** | **53** | **53** | **0** |

All 53 test cases passed. The system reliably detects the attack scenarios defined in the MITRE ATT&CK mapping and forwards them to the server within one scan cycle. See `MITRE_MAPPING.md` for full technique coverage.
