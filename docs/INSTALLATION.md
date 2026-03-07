# HIDS Installation Guide

## System Requirements

### Hardware
- CPU: 2+ cores
- RAM: 2GB minimum
- Disk: 10GB free space

### Software
- Ubuntu 22.04 LTS
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

### Port Already in Use
```bash
sudo lsof -i :5000
kill -9 <PID>
```

### Database Issues
```bash
cd server/database
rm hids.db
# Restart server to recreate
```
