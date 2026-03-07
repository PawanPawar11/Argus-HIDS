# HIDS Installation Guide

## System Requirements

### Hardware
- CPU: 2+ cores
- RAM: 2GB minimum
- Disk: 10GB free space

### Software
- Fedora 40/41 (or compatible RHEL-based distro)
- Python 3.10 or higher
- Internet connection

## Installation Steps

### 1. Clone/Download Project
```bash
cd /home/your-username/Desktop
# Extract project files
```

### 2. Install Dependencies
```bash
# Install required system packages (Fedora)
sudo dnf install -y python3 python3-pip python3-virtualenv lsof

cd hids-project-complete
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Agent
```bash
cd agent
nano config.json
```

Edit:
- `server_url`: Your server address
- `monitored_paths`: Files/directories to monitor

### 4. Configure Email Alerts
```bash
cd server
python3 tools/configure_email.py
```

Follow the wizard to set up Gmail alerts.

### 5. Start Services

**Terminal 1 - Server:**
```bash
cd server/api
python3 server.py
```

**Terminal 2 - Agent:**
```bash
cd agent
sudo python3 main.py
```

### 6. Access Dashboard
Open browser: http://localhost:5000

## Troubleshooting

### Permission Errors
```bash
sudo python3 main.py
```

> **Fedora note:** Reading `/var/log/secure` requires root. You can also add your user
> to the `adm` group as an alternative: `sudo usermod -aG adm $USER`

### Port Already in Use
```bash
# lsof must be installed first on Fedora: sudo dnf install -y lsof
sudo lsof -i :5000
kill -9 <PID>
```

### SELinux Blocking Access (Fedora-specific)
If SELinux denies access to log files or network sockets, check audit logs:
```bash
sudo ausearch -m avc -ts recent
# To temporarily set SELinux to permissive mode for testing only:
sudo setenforce 0
```

### Database Issues
```bash
cd server/database
rm hids.db
# Restart server to recreate
```