
#!/bin/bash

echo "Creating all project files with placeholders..."

# Agent files
cat > agent/config.json << 'AGENTCONFIG'
{
    "agent": {
        "name": "ubuntu-agent-01",
        "server_url": "http://localhost:5000/api/events",
        "scan_interval": 60
    },
    "file_monitor": {
        "enabled": true,
        "monitored_paths": ["/etc/passwd", "/etc/hosts"],
        "exclude_extensions": [".log", ".tmp"],
        "baseline_file": "data/file_baseline.json"
    },
    "auth_monitor": {
        "enabled": true,
        "log_files": ["/var/log/auth.log"],
        "position_file": "data/auth_log_position.json",
        "brute_force_threshold": 5,
        "brute_force_window": 300,
        "monitor_sudo": true,
        "monitor_ssh": true,
        "monitor_user_changes": true,
        "suspicious_usernames": ["admin", "root", "test"]
    },
    "process_monitor": {
        "enabled": true,
        "baseline_file": "data/process_baseline.json",
        "cpu_threshold": 80,
        "memory_threshold": 80,
        "check_crypto_miners": true,
        "check_reverse_shells": true,
        "check_privilege_escalation": true,
        "whitelist_processes": ["systemd", "sshd"],
        "suspicious_process_names": ["nc", "netcat", "xmrig"],
        "suspicious_commands": ["bash -i", "/dev/tcp"],
        "suspicious_paths": ["/tmp", "/var/tmp"],
        "monitor_network_connections": true,
        "suspicious_ports": [4444, 5555, 31337]
    },
    "network_monitor": {
        "enabled": true,
        "baseline_file": "data/network_baseline.json",
        "detect_port_scans": true,
        "port_scan_threshold": 10,
        "port_scan_window": 60,
        "suspicious_ports": [4444, 5555, 31337],
        "allowed_outbound_ports": [80, 443, 22, 53]
    }
}
AGENTCONFIG

echo "✅ agent/config.json"

# Create placeholder files
touch agent/main.py
touch agent/modules/__init__.py
touch agent/modules/file_monitor.py
touch agent/modules/auth_monitor.py
touch agent/modules/process_monitor.py
touch agent/modules/network_monitor.py
touch agent/modules/network_client.py

touch server/api/server.py
touch server/database/models.py
touch server/alerts/email_alerts.py
touch server/dashboard/templates/index.html
touch server/dashboard/static/css/dashboard.css
touch server/dashboard/static/js/dashboard.js
touch server/tools/db_manager.py
touch server/tools/configure_email.py

cat > server/tools/backup_db.sh << 'BACKUPSH'
#!/bin/bash
BACKUP_DIR="database/backups"
DB_FILE="database/hids.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
cp $DB_FILE "$BACKUP_DIR/hids_backup_$TIMESTAMP.db"
gzip "$BACKUP_DIR/hids_backup_$TIMESTAMP.db"
echo "✅ Backup created"
BACKUPSH

chmod +x server/tools/backup_db.sh

touch tests/simulate_attacks.sh
touch tests/simulate_process_attacks.sh
touch tests/simulate_network_attacks.sh

chmod +x tests/*.sh

touch tools/monitor_events.py
touch tools/query_events.py
touch tools/network_analysis.py

echo ""
echo "✅ All placeholder files created!"
echo ""
echo "File structure:"
find . -type f -not -path "./venv/*" -not -name "*.pyc" | grep -E "\.(py|json|sh|html|css|js)$" | sort

