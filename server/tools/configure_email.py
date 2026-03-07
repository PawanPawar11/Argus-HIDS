#!/usr/bin/env python3
"""
Email Alert Configuration Tool
Interactive setup for HIDS email alerts
"""

import sys
import os
import json
from getpass import getpass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from alerts.email_alerts import EmailAlertManager


def configure_email_alerts():
    """
    Interactive configuration for email alerts
    """
    print("\n" + "="*60)
    print(" "*15 + "HIDS EMAIL ALERT CONFIGURATION")
    print("="*60 + "\n")
    
    # Load existing config or create new
    try:
        alerts = EmailAlertManager('alerts/email_config.json')
        config = alerts.config
        print("[INFO] Loaded existing configuration\n")
    except:
        config = alerts.get_default_config()
        print("[INFO] Creating new configuration\n")
    
    # Email provider selection
    print("Select Email Provider:")
    print("1. Gmail (Recommended)")
    print("2. Outlook/Hotmail")
    print("3. Yahoo")
    print("4. Custom SMTP Server")
    
    choice = input("\nChoice (1-4) [1]: ").strip() or "1"
    
    if choice == "1":
        config['smtp_server'] = 'smtp.gmail.com'
        config['smtp_port'] = 587
        print("\n📧 Gmail selected")
        print("⚠️  Note: You need to create an App Password")
        print("   Visit: https://myaccount.google.com/apppasswords")
    elif choice == "2":
        config['smtp_server'] = 'smtp-mail.outlook.com'
        config['smtp_port'] = 587
        print("\n📧 Outlook selected")
    elif choice == "3":
        config['smtp_server'] = 'smtp.mail.yahoo.com'
        config['smtp_port'] = 587
        print("\n📧 Yahoo selected")
    else:
        config['smtp_server'] = input("SMTP Server: ").strip()
        config['smtp_port'] = int(input("SMTP Port [587]: ").strip() or "587")
    
    # Sender email
    print("\n" + "-"*60)
    sender = input(f"Sender Email [{config.get('sender_email', '')}]: ").strip()
    if sender:
        config['sender_email'] = sender
    
    # Sender password
    password = getpass("Sender Password (App Password for Gmail): ").strip()
    if password:
        config['sender_password'] = password
    
    # Recipient emails
    print("\n" + "-"*60)
    print("Recipient Email(s)")
    print("(Enter multiple emails separated by commas)")
    recipients = input(f"Recipients [{', '.join(config.get('recipient_emails', []))}]: ").strip()
    if recipients:
        config['recipient_emails'] = [email.strip() for email in recipients.split(',')]
    
    # Alert settings
    print("\n" + "-"*60)
    print("Alert Settings")
    
    enable = input(f"Enable email alerts? (yes/no) [{'yes' if config.get('enabled') else 'no'}]: ").strip().lower()
    config['enabled'] = enable in ['yes', 'y', 'true', '1']
    
    # Severity levels
    print("\nAlert on severity levels:")
    print("1. Critical only")
    print("2. Critical + High (Recommended)")
    print("3. Critical + High + Medium")
    print("4. All levels")
    
    severity_choice = input("Choice (1-4) [2]: ").strip() or "2"
    
    severity_map = {
        '1': ['critical'],
        '2': ['critical', 'high'],
        '3': ['critical', 'high', 'medium'],
        '4': ['critical', 'high', 'medium', 'info']
    }
    config['alert_on_severity'] = severity_map.get(severity_choice, ['critical', 'high'])
    
    # Cooldown
    cooldown = input(f"Alert cooldown in minutes [{config.get('alert_cooldown_minutes', 5)}]: ").strip()
    if cooldown:
        config['alert_cooldown_minutes'] = int(cooldown)
    
    # Save configuration
    print("\n" + "="*60)
    print("Configuration Summary:")
    print("="*60)
    print(f"SMTP Server: {config['smtp_server']}:{config['smtp_port']}")
    print(f"Sender: {config['sender_email']}")
    print(f"Recipients: {', '.join(config['recipient_emails'])}")
    print(f"Enabled: {config['enabled']}")
    print(f"Alert Levels: {', '.join(config['alert_on_severity'])}")
    print(f"Cooldown: {config['alert_cooldown_minutes']} minutes")
    print("="*60)
    
    save = input("\nSave this configuration? (yes/no) [yes]: ").strip().lower()
    if save not in ['no', 'n']:
        # Save config
        os.makedirs('alerts', exist_ok=True)
        with open('alerts/email_config.json', 'w') as f:
            json.dump(config, f, indent=4)
        print("\n✅ Configuration saved to alerts/email_config.json")
        
        # Test email
        test = input("\nSend test email? (yes/no) [yes]: ").strip().lower()
        if test not in ['no', 'n']:
            print("\n📧 Sending test email...")
            alerts = EmailAlertManager('alerts/email_config.json')
            if alerts.test_email():
                print("✅ Test email sent successfully! Check your inbox.")
            else:
                print("❌ Failed to send test email.")
                print("   Please check your credentials and try again.")
    else:
        print("\n❌ Configuration not saved")


if __name__ == "__main__":
    try:
        configure_email_alerts()
    except KeyboardInterrupt:
        print("\n\n❌ Configuration cancelled")
        sys.exit(0)