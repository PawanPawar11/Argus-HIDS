"""
Email Alerts Module for HIDS Server
Sends email notifications for critical security events
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
import os


class EmailAlertManager:
    def __init__(self, config_file='server/alerts/email_config.json'):
        """
        Initialize Email Alert Manager
        
        Args:
            config_file: Path to email configuration file
        """
        self.config = self.load_config(config_file)
        self.enabled = self.config.get('enabled', False)
        
        # Alert thresholds
        self.alert_on_severity = self.config.get('alert_on_severity', ['critical', 'high'])
        self.alert_on_event_types = self.config.get('alert_on_event_types', [])
        
        # Rate limiting to avoid spam
        self.alert_cooldown = self.config.get('alert_cooldown_minutes', 5)
        self.last_alert_times = {}
        
        print(f"[INFO] Email alerts {'enabled' if self.enabled else 'disabled'}")
    
    def load_config(self, config_file):
        """
        Load email configuration from file
        
        Args:
            config_file: Path to config file
            
        Returns:
            dict: Configuration dictionary
        """
        try:
            if Path(config_file).exists():
                with open(config_file, 'r') as f:
                    return json.load(f)
            else:
                # Return default config
                return self.get_default_config()
        except Exception as e:
            print(f"[ERROR] Failed to load email config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """
        Get default email configuration
        
        Returns:
            dict: Default configuration
        """
        return {
            'enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'use_tls': True,
            'sender_email': 'your-sender@gmail.com',
            'sender_password': '${EMAIL_PASSWORD}' ,
            'recipient_emails': ['your-recipient@example.com'],
            'alert_on_severity': ['critical', 'high'],
            'alert_on_event_types': [
                'brute_force_attack',
                'cryptocurrency_miner_detected',
                'port_scan_detected',
                'reverse_shell_detected',
                'file_modified',
                'user_account_created'
            ],
            'alert_cooldown_minutes': 5,
            'include_mitre_info': True
        }
    
    def save_config(self, config_file='alerts/email_config.json'):
        """
        Save current configuration to file
        
        Args:
            config_file: Path to save config
        """
        try:
            Path(config_file).parent.mkdir(parents=True, exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"[INFO] Email config saved to {config_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save email config: {e}")
    
    def should_send_alert(self, event):
        """
        Determine if alert should be sent for this event
        
        Args:
            event: Event dictionary
            
        Returns:
            bool: True if alert should be sent
        """
        if not self.enabled:
            return False
        
        # Check severity
        severity = event.get('severity', '').lower()
        if severity not in self.alert_on_severity:
            return False
        
        # Check event type (if specific types are configured)
        event_type = event.get('event_type', '')
        if self.alert_on_event_types and event_type not in self.alert_on_event_types:
            return False
        
        # Check rate limiting (cooldown)
        event_key = f"{event_type}_{event.get('agent_info', {}).get('agent_name', 'unknown')}"
        last_alert_time = self.last_alert_times.get(event_key)
        
        if last_alert_time:
            time_diff = (datetime.now() - last_alert_time).total_seconds() / 60
            if time_diff < self.alert_cooldown:
                print(f"[INFO] Alert skipped (cooldown): {event_type}")
                return False
        
        return True
    
    def send_alert(self, event):
        """
        Send email alert for security event
        
        Args:
            event: Event dictionary
            
        Returns:
            bool: True if sent successfully
        """
        if not self.should_send_alert(event):
            return False
        
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = self.get_email_subject(event)
            msg['From'] = self.config['sender_email']
            msg['To'] = ', '.join(self.config['recipient_emails'])
            
            # Create HTML and text versions
            text_body = self.create_text_body(event)
            html_body = self.create_html_body(event)
            
            # Attach both versions
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                if self.config.get('use_tls', True):
                    server.starttls()
                
                password = os.getenv("EMAIL_PASSWORD") or self.config.get("sender_password")
                server.login(self.config['sender_email'], password)
                server.send_message(msg)
            
            # Update last alert time
            event_key = f"{event.get('event_type')}_{event.get('agent_info', {}).get('agent_name', 'unknown')}"
            self.last_alert_times[event_key] = datetime.now()
            
            print(f"[SUCCESS] Alert email sent: {event.get('event_type')}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to send email alert: {e}")
            return False
    
    def get_email_subject(self, event):
        """
        Generate email subject line
        
        Args:
            event: Event dictionary
            
        Returns:
            str: Subject line
        """
        severity = event.get('severity', 'UNKNOWN').upper()
        event_type = event.get('event_type', 'Unknown Event').replace('_', ' ').title()
        agent = event.get('agent_info', {}).get('agent_name', 'Unknown')
        
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'INFO': '🟢'
        }.get(severity, '⚪')
        
        return f"{severity_emoji} HIDS Alert [{severity}] - {event_type} on {agent}"
    
    def create_text_body(self, event):
        """
        Create plain text email body
        
        Args:
            event: Event dictionary
            
        Returns:
            str: Plain text body
        """
        agent_info = event.get('agent_info', {})
        
        body = f"""
HIDS Security Alert
{'='*60}

SEVERITY: {event.get('severity', 'Unknown').upper()}
EVENT TYPE: {event.get('event_type', 'Unknown').replace('_', ' ').title()}
TIMESTAMP: {event.get('timestamp', 'Unknown')}

AGENT INFORMATION:
- Name: {agent_info.get('agent_name', 'Unknown')}
- Hostname: {agent_info.get('hostname', 'Unknown')}
- IP Address: {agent_info.get('ip_address', 'Unknown')}

DESCRIPTION:
{event.get('description', 'No description available')}
"""
        
        # Add MITRE ATT&CK info
        if self.config.get('include_mitre_info', True) and event.get('mitre_technique'):
            body += f"\nMITRE ATT&CK TECHNIQUE: {event.get('mitre_technique')}\n"
        
        # Add event-specific details
        if event.get('source_ip'):
            body += f"\nSource IP: {event.get('source_ip')}"
        
        if event.get('username'):
            body += f"\nUsername: {event.get('username')}"
        
        if event.get('filepath'):
            body += f"\nFile Path: {event.get('filepath')}"
        
        if event.get('process_name'):
            body += f"\nProcess: {event.get('process_name')} (PID: {event.get('pid', 'N/A')})"
        
        if event.get('remote_port'):
            body += f"\nRemote Port: {event.get('remote_port')}"
        
        body += f"\n\n{'='*60}\n"
        body += "This is an automated alert from your HIDS system.\n"
        body += "Please investigate this incident immediately.\n"
        
        return body
    
    def create_html_body(self, event):
        """
        Create HTML email body
        
        Args:
            event: Event dictionary
            
        Returns:
            str: HTML body
        """
        agent_info = event.get('agent_info', {})
        severity = event.get('severity', 'unknown').lower()
        
        # Severity colors
        severity_colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'info': '#27ae60'
        }
        
        color = severity_colors.get(severity, '#95a5a6')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }}
        .severity-badge {{
            display: inline-block;
            background-color: {color};
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .content {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 0 0 8px 8px;
        }}
        .info-row {{
            margin: 10px 0;
            padding: 10px;
            background-color: white;
            border-left: 4px solid {color};
            border-radius: 4px;
        }}
        .label {{
            font-weight: bold;
            color: #555;
        }}
        .value {{
            color: #333;
        }}
        .description {{
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
            border-left: 4px solid {color};
        }}
        .footer {{
            text-align: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #777;
            font-size: 12px;
        }}
        .mitre {{
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ HIDS Security Alert</h1>
        <div class="severity-badge">{event.get('severity', 'Unknown').upper()}</div>
    </div>
    
    <div class="content">
        <h2>{event.get('event_type', 'Unknown Event').replace('_', ' ').title()}</h2>
        
        <div class="info-row">
            <span class="label">Timestamp:</span>
            <span class="value">{event.get('timestamp', 'Unknown')}</span>
        </div>
        
        <div class="info-row">
            <span class="label">Agent:</span>
            <span class="value">{agent_info.get('agent_name', 'Unknown')} ({agent_info.get('hostname', 'Unknown')})</span>
        </div>
        
        <div class="info-row">
            <span class="label">IP Address:</span>
            <span class="value">{agent_info.get('ip_address', 'Unknown')}</span>
        </div>
        
        <div class="description">
            <strong>Description:</strong><br>
            {event.get('description', 'No description available')}
        </div>
"""
        
        # Add MITRE info
        if self.config.get('include_mitre_info', True) and event.get('mitre_technique'):
            html += f"""
        <div class="mitre">
            <strong>🎯 MITRE ATT&CK Technique:</strong> {event.get('mitre_technique')}<br>
            <small>Learn more: <a href="https://attack.mitre.org/techniques/{event.get('mitre_technique')}/">
            attack.mitre.org/techniques/{event.get('mitre_technique')}/</a></small>
        </div>
"""
        
        # Add event-specific details
        details = []
        
        if event.get('source_ip'):
            details.append(('Source IP', event.get('source_ip')))
        
        if event.get('username'):
            details.append(('Username', event.get('username')))
        
        if event.get('filepath'):
            details.append(('File Path', event.get('filepath')))
        
        if event.get('process_name'):
            details.append(('Process', f"{event.get('process_name')} (PID: {event.get('pid', 'N/A')})"))
        
        if event.get('remote_port'):
            details.append(('Remote Port', event.get('remote_port')))
        
        if event.get('attempt_count'):
            details.append(('Attempts', event.get('attempt_count')))
        
        for label, value in details:
            html += f"""
        <div class="info-row">
            <span class="label">{label}:</span>
            <span class="value">{value}</span>
        </div>
"""
        
        html += """
    </div>
    
    <div class="footer">
        <p>This is an automated alert from your HIDS system.</p>
        <p><strong>⚠️ Please investigate this incident immediately.</strong></p>
        <p style="margin-top: 10px;">
            <a href="http://localhost:5000">View Dashboard</a>
        </p>
    </div>
</body>
</html>
"""
        
        return html
    
    def test_email(self):
        """
        Send test email to verify configuration
        """
        test_event = {
            'event_type': 'test_alert',
            'severity': 'critical',   # 🔥 IMPORTANT
            'timestamp': datetime.now().isoformat(),
            'description': 'This is a test alert to verify your HIDS email configuration is working correctly.',
            'agent_info': {
                'agent_name': 'test-agent',
                'hostname': 'test-host',
                'ip_address': '127.0.0.1'
            },
            'mitre_technique': 'T0000'
        }
    
        original_enabled = self.enabled
        self.enabled = True

        # 🔥 Bypass filters temporarily
        original_severity = self.alert_on_severity
        original_event_types = self.alert_on_event_types

        self.alert_on_severity = ['critical', 'high', 'info']
        self.alert_on_event_types = []

        result = self.send_alert(test_event)

        # Restore config
        self.alert_on_severity = original_severity
        self.alert_on_event_types = original_event_types
        self.enabled = original_enabled

        return result



# Convenience function
def init_email_alerts(config_file='alerts/email_config.json'):
    """Initialize email alert manager"""
    return EmailAlertManager(config_file)


if __name__ == "__main__":
    # Test email alerts
    print("Testing Email Alerts...")
    
    alerts = init_email_alerts()
    
    # Save default config
    alerts.save_config()
    print("\n[INFO] Default config saved to alerts/email_config.json")
    print("[INFO] Please edit the config file with your email credentials")
    print("\n[INFO] To test, run: python3 -c 'from alerts.email_alerts import *; init_email_alerts().test_email()'")