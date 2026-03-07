#!/usr/bin/env python3
"""
HIDS Database Management Tool
Manage, query, and maintain the HIDS SQLite database
"""

import sys
import os
import argparse
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.models import DatabaseManager


class DatabaseCLI:
    def __init__(self, db_path=None):
        if db_path is None:
            # Get the project root directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(script_dir)
            db_path = os.path.join(project_root, 'server', 'database', 'hids.db')
        
        self.db = DatabaseManager(db_path)
    
    def show_stats(self):
        """Display database statistics"""
        stats = self.db.get_statistics()
        
        print("\n" + "="*70)
        print(" "*25 + "DATABASE STATISTICS")
        print("="*70)
        print(f"Total Events: {stats['total_events']}")
        print()
        
        print("Events by Severity:")
        for severity in ['critical', 'high', 'medium', 'info']:
            count = stats['by_severity'].get(severity, 0)
            percentage = (count / stats['total_events'] * 100) if stats['total_events'] > 0 else 0
            bar = "█" * int(percentage / 2)
            print(f"  {severity.upper():10} : {count:6} ({percentage:5.1f}%) {bar}")
        
        print("\nTop Event Types:")
        for event_type, count in list(stats['by_type'].items())[:10]:
            print(f"  {event_type:35} : {count:5}")
        
        print("\nTop MITRE ATT&CK Techniques:")
        for technique, count in list(stats['by_mitre'].items())[:10]:
            print(f"  {technique:15} : {count:5}")
        
        print("\nEvents by Agent:")
        for agent, count in stats['by_agent'].items():
            print(f"  {agent:30} : {count:5}")
        
        print("="*70 + "\n")
    
    def list_agents(self):
        """List all registered agents"""
        agents = self.db.get_agents()
        
        print("\n" + "="*70)
        print(" "*25 + "REGISTERED AGENTS")
        print("="*70)
        print(f"Total Agents: {len(agents)}\n")
        
        for agent in agents:
            print(f"Agent: {agent['agent_name']}")
            print(f"  Hostname: {agent['hostname']}")
            print(f"  IP: {agent['ip_address']}")
            print(f"  Status: {agent['status']}")
            print(f"  First Seen: {agent['first_seen'][:19]}")
            print(f"  Last Seen: {agent['last_seen'][:19]}")
            print()
        
        print("="*70 + "\n")
    
    def show_recent_events(self, limit=20, severity=None):
        """Show recent events"""
        events = self.db.get_events(limit=limit, severity=severity)
        
        print("\n" + "="*70)
        print(f" "*20 + f"RECENT EVENTS (Last {limit})")
        print("="*70 + "\n")
        
        for i, event in enumerate(events, 1):
            severity_color = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'info': '🟢'
            }.get(event['severity'], '⚪')
            
            print(f"[{i}] {severity_color} {event['event_type']}")
            print(f"    Severity: {event['severity']} | Agent: {event['agent_name']}")
            print(f"    Time: {event['timestamp'][:19]}")
            print(f"    MITRE: {event['mitre_technique'] or 'N/A'}")
            print(f"    Description: {event['description'][:70]}...")
            print()
        
        print("="*70 + "\n")
    
    def search_events(self, term, limit=50):
        """Search events by keyword"""
        events = self.db.search_events(term, limit=limit)
        
        print("\n" + "="*70)
        print(f"SEARCH RESULTS for '{term}' ({len(events)} found)")
        print("="*70 + "\n")
        
        for event in events:
            print(f"[{event['id']}] {event['event_type']} ({event['severity']})")
            print(f"  {event['description']}")
            print(f"  Time: {event['timestamp'][:19]} | Agent: {event['agent_name']}")
            print()
        
        print("="*70 + "\n")
    
    def cleanup_old_events(self, days=30, confirm=True):
        """Delete old events"""
        if confirm:
            cutoff = datetime.now() - timedelta(days=days)
            print(f"\n⚠️  WARNING: This will delete all events before {cutoff.strftime('%Y-%m-%d')}")
            response = input("Are you sure? (yes/no): ")
            
            if response.lower() != 'yes':
                print("Cleanup cancelled.")
                return
        
        deleted = self.db.delete_old_events(days)
        print(f"✅ Deleted {deleted} events older than {days} days")
    
    def export_to_json(self, output_file, limit=None):
        """Export events to JSON file"""
        import json
        
        events = self.db.get_events(limit=limit or 999999)
        
        with open(output_file, 'w') as f:
            json.dump(events, f, indent=2)
        
        print(f"✅ Exported {len(events)} events to {output_file}")
    
    def export_to_csv(self, output_file, limit=None):
        """Export events to CSV file"""
        import csv
        
        events = self.db.get_events(limit=limit or 999999)
        
        if not events:
            print("No events to export")
            return
        
        # Define CSV columns
        columns = ['id', 'event_type', 'severity', 'timestamp', 'agent_name', 
                  'mitre_technique', 'description']
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(events)
        
        print(f"✅ Exported {len(events)} events to {output_file}")
    
    def show_event_details(self, event_id):
        """Show detailed information about a specific event"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get main event
            cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
            event = cursor.fetchone()
            
            if not event:
                print(f"❌ Event {event_id} not found")
                return
            
            event = dict(event)
            
            print("\n" + "="*70)
            print(f" "*25 + f"EVENT DETAILS #{event_id}")
            print("="*70)
            print(f"Type: {event['event_type']}")
            print(f"Severity: {event['severity']}")
            print(f"Timestamp: {event['timestamp']}")
            print(f"Agent: {event['agent_name']} ({event['agent_hostname']})")
            print(f"MITRE Technique: {event['mitre_technique'] or 'N/A'}")
            print(f"Description: {event['description']}")
            print()
            
            # Get type-specific details
            event_type = event['event_type']
            
            if 'file' in event_type:
                cursor.execute('SELECT * FROM file_events WHERE event_id = ?', (event_id,))
                details = cursor.fetchone()
                if details:
                    details = dict(details)
                    print("File Details:")
                    print(f"  Path: {details['filepath']}")
                    print(f"  Old Hash: {details['old_hash'] or 'N/A'}")
                    print(f"  New Hash: {details['new_hash'] or 'N/A'}")
                    print(f"  Permissions: {details['permissions'] or 'N/A'}")
            
            elif any(k in event_type for k in ['auth', 'login', 'sudo']):
                cursor.execute('SELECT * FROM auth_events WHERE event_id = ?', (event_id,))
                details = cursor.fetchone()
                if details:
                    details = dict(details)
                    print("Authentication Details:")
                    print(f"  Username: {details['username'] or 'N/A'}")
                    print(f"  Source IP: {details['source_ip'] or 'N/A'}")
                    print(f"  Command: {details['command'] or 'N/A'}")
                    print(f"  Attempts: {details['attempt_count'] or 'N/A'}")
            
            elif 'process' in event_type:
                cursor.execute('SELECT * FROM process_events WHERE event_id = ?', (event_id,))
                details = cursor.fetchone()
                if details:
                    details = dict(details)
                    print("Process Details:")
                    print(f"  PID: {details['pid']}")
                    print(f"  Name: {details['process_name']}")
                    print(f"  Path: {details['exe_path'] or 'N/A'}")
                    print(f"  Command: {details['cmdline'] or 'N/A'}")
                    print(f"  User: {details['username'] or 'N/A'}")
                    print(f"  CPU: {details['cpu_percent']}%")
                    print(f"  Memory: {details['memory_percent']}%")
            
            elif any(k in event_type for k in ['network', 'connection', 'port']):
                cursor.execute('SELECT * FROM network_events WHERE event_id = ?', (event_id,))
                details = cursor.fetchone()
                if details:
                    details = dict(details)
                    print("Network Details:")
                    print(f"  Source: {details['source_ip'] or 'N/A'}:{details['source_port'] or 'N/A'}")
                    print(f"  Remote: {details['remote_ip'] or 'N/A'}:{details['remote_port'] or 'N/A'}")
                    print(f"  Protocol: {details['protocol'] or 'N/A'}")
                    print(f"  Connections: {details['connection_count'] or 'N/A'}")
                    print(f"  Ports Accessed: {details['unique_ports_accessed'] or 'N/A'}")
            
            print("="*70 + "\n")


def main():
    # Get default database path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_db = os.path.join(project_root, 'server', 'database', 'hids.db')
    
    parser = argparse.ArgumentParser(description='HIDS Database Management Tool')
    parser.add_argument('--db', default=default_db, help='Database path')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')
    
    # Agents command
    subparsers.add_parser('agents', help='List registered agents')
    
    # Recent events command
    recent_parser = subparsers.add_parser('recent', help='Show recent events')
    recent_parser.add_argument('--limit', type=int, default=20, help='Number of events')
    recent_parser.add_argument('--severity', help='Filter by severity')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search events')
    search_parser.add_argument('term', help='Search term')
    search_parser.add_argument('--limit', type=int, default=50, help='Max results')
    
    # Details command
    details_parser = subparsers.add_parser('details', help='Show event details')
    details_parser.add_argument('event_id', type=int, help='Event ID')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Delete old events')
    cleanup_parser.add_argument('--days', type=int, default=30, help='Delete older than N days')
    cleanup_parser.add_argument('--yes', action='store_true', help='Skip confirmation')
    
    # Export commands
    export_json_parser = subparsers.add_parser('export-json', help='Export to JSON')
    export_json_parser.add_argument('output', help='Output file')
    export_json_parser.add_argument('--limit', type=int, help='Limit events')
    
    export_csv_parser = subparsers.add_parser('export-csv', help='Export to CSV')
    export_csv_parser.add_argument('output', help='Output file')
    export_csv_parser.add_argument('--limit', type=int, help='Limit events')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = DatabaseCLI(args.db)
    
    # Execute command
    if args.command == 'stats':
        cli.show_stats()
    
    elif args.command == 'agents':
        cli.list_agents()
    
    elif args.command == 'recent':
        cli.show_recent_events(limit=args.limit, severity=args.severity)
    
    elif args.command == 'search':
        cli.search_events(args.term, limit=args.limit)
    
    elif args.command == 'details':
        cli.show_event_details(args.event_id)
    
    elif args.command == 'cleanup':
        cli.cleanup_old_events(days=args.days, confirm=not args.yes)
    
    elif args.command == 'export-json':
        cli.export_to_json(args.output, limit=args.limit)
    
    elif args.command == 'export-csv':
        cli.export_to_csv(args.output, limit=args.limit)


if __name__ == '__main__':
    main()