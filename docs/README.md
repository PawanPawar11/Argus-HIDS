# Host-Based Intrusion Detection System (HIDS)

## Overview
A comprehensive HIDS with agent-server architecture for Fedora 40/41 (and compatible RHEL-based distributions).

## Features
- ✅ File Integrity Monitoring (FIM)
- ✅ Authentication Attack Detection
- ✅ Process Monitoring (Crypto miners, Reverse shells)
- ✅ Network Monitoring (Port scans, Suspicious connections)
- ✅ Web Dashboard with Real-time Charts
- ✅ SQLite Database Storage
- ✅ Email Alerts for Critical Events
- ✅ MITRE ATT&CK Mapping

## Architecture
```
┌─────────────┐         ┌─────────────┐
│  HIDS Agent │ ──────▶ │ HIDS Server │
│  (Fedora)   │  JSON   │  (Flask)    │
└─────────────┘         └─────────────┘
                              │
                        ┌─────▼─────┐
                        │  SQLite   │
                        │  Database │
                        └───────────┘
```

## Installation

### Prerequisites
- Fedora 40/41 (or compatible RHEL-based distro)
- Python 3.10+
- Root access (for agent)

### Install System Packages (Fedora)
```bash
sudo dnf install -y python3 python3-pip python3-virtualenv lsof
```

### Quick Start

1. **Install dependencies:**
```bash
   cd hids-project-complete
   source venv/bin/activate
   pip install -r requirements.txt
```

2. **Start Server:**
```bash
   cd server/api
   python3 server.py
```

3. **Start Agent:**
```bash
   cd agent
   sudo python3 main.py
```

4. **Access Dashboard:**
```
   http://localhost:5000
```

## Configuration

### Agent Configuration
Edit `agent/config.json`:
- Monitored paths
- Server URL
- Scan intervals

### Email Alerts
Run setup wizard:
```bash
cd server
python3 tools/configure_email.py
```

## Testing

Run attack simulations:
```bash
cd tests
sudo bash simulate_attacks.sh
sudo bash simulate_process_attacks.sh
sudo bash simulate_network_attacks.sh
```

## Documentation
- [Installation Guide](docs/INSTALLATION.md)
- [User Manual](docs/USER_MANUAL.md)
- [Testing Report](docs/TESTING_REPORT.md)
- [MITRE Mapping](docs/MITRE_MAPPING.md)

## Project Structure
```
hids-project/
├── agent/              # HIDS Agent
├── server/             # HIDS Server
├── tests/              # Test scripts
├── tools/              # Analysis tools
└── docs/               # Documentation
```

## License
Educational Project - For learning purposes only

## Author
College Semester Project