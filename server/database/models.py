"""
Database Models for HIDS Server
SQLite database schema and ORM models
"""

import sqlite3
import json
from datetime import datetime
from contextlib import contextmanager


class DatabaseManager:
    def __init__(self, db_path='server/database/hids.db'):
        """
        Initialize Database Manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """
        Get database connection with context manager
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """
        Initialize database schema
        Creates all required tables
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Events table - Main event storage
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    server_received_at TEXT NOT NULL,
                    agent_name TEXT,
                    agent_hostname TEXT,
                    agent_ip TEXT,
                    mitre_technique TEXT,
                    description TEXT,
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # File integrity events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    filepath TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    file_size INTEGER,
                    permissions TEXT,
                    owner_uid INTEGER,
                    owner_gid INTEGER,
                    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
                )
            ''')
            
            # Authentication events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    username TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    target_user TEXT,
                    command TEXT,
                    attempt_count INTEGER,
                    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
                )
            ''')
            
            # Process events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS process_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    exe_path TEXT,
                    cmdline TEXT,
                    username TEXT,
                    cpu_percent REAL,
                    memory_percent REAL,
                    matched_pattern TEXT,
                    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
                )
            ''')
            
            # Network events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    source_ip TEXT,
                    source_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    connection_count INTEGER,
                    unique_ports_accessed INTEGER,
                    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
                )
            ''')
            
            # Agents table - Track registered agents
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_name TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    ip_address TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    modules_enabled TEXT
                )
            ''')
            
            # Create indexes for better query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_technique)')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_events_filepath ON file_events(filepath)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_events_username ON auth_events(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_events_source_ip ON auth_events(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_events_pid ON process_events(pid)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_events_name ON process_events(process_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_events_remote_ip ON network_events(remote_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_events_remote_port ON network_events(remote_port)')
            
            conn.commit()
            print("[INFO] Database schema initialized successfully")
    
    def insert_event(self, event_data):
        """
        Insert event into database
        
        Args:
            event_data: Event dictionary
            
        Returns:
            int: Event ID
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Extract agent information
            agent_info = event_data.get('agent_info', {})
            agent_name = agent_info.get('agent_name', 'unknown')
            agent_hostname = agent_info.get('hostname', 'unknown')
            agent_ip = agent_info.get('ip_address', 'unknown')
            
            # Insert main event
            cursor.execute('''
                INSERT INTO events (
                    event_type, severity, timestamp, server_received_at,
                    agent_name, agent_hostname, agent_ip,
                    mitre_technique, description, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_data.get('event_type'),
                event_data.get('severity'),
                event_data.get('timestamp'),
                event_data.get('server_received_at', datetime.now().isoformat()),
                agent_name,
                agent_hostname,
                agent_ip,
                event_data.get('mitre_technique'),
                event_data.get('description'),
                json.dumps(event_data)
            ))
            
            event_id = cursor.lastrowid
            
            # Insert type-specific data
            event_type = event_data.get('event_type', '')
            
            # File events
            if 'file' in event_type:
                cursor.execute('''
                    INSERT INTO file_events (
                        event_id, filepath, old_hash, new_hash,
                        file_size, permissions, owner_uid, owner_gid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_id,
                    event_data.get('filepath'),
                    event_data.get('old_hash'),
                    event_data.get('new_hash'),
                    event_data.get('metadata', {}).get('size'),
                    event_data.get('metadata', {}).get('permissions'),
                    event_data.get('metadata', {}).get('owner_uid'),
                    event_data.get('metadata', {}).get('owner_gid')
                ))
            
            # Auth events
            elif any(keyword in event_type for keyword in ['auth', 'login', 'sudo', 'user', 'password']):
                cursor.execute('''
                    INSERT INTO auth_events (
                        event_id, username, source_ip, source_port,
                        target_user, command, attempt_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_id,
                    event_data.get('username'),
                    event_data.get('source_ip'),
                    event_data.get('source_port'),
                    event_data.get('target_user'),
                    event_data.get('command'),
                    event_data.get('attempt_count')
                ))
            
            # Process events
            elif 'process' in event_type or 'miner' in event_type or 'shell' in event_type:
                cursor.execute('''
                    INSERT INTO process_events (
                        event_id, pid, process_name, exe_path, cmdline,
                        username, cpu_percent, memory_percent, matched_pattern
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_id,
                    event_data.get('pid'),
                    event_data.get('process_name'),
                    event_data.get('exe'),
                    event_data.get('cmdline'),
                    event_data.get('username'),
                    event_data.get('cpu_percent'),
                    event_data.get('memory_percent'),
                    event_data.get('matched_pattern') or event_data.get('matched_indicator')
                ))
            
            # Network events
            elif any(keyword in event_type for keyword in ['network', 'connection', 'port', 'scan', 'tor', 'proxy']):
                cursor.execute('''
                    INSERT INTO network_events (
                        event_id, source_ip, source_port, remote_ip, remote_port,
                        protocol, connection_count, unique_ports_accessed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_id,
                    event_data.get('source_ip'),
                    event_data.get('source_port') or event_data.get('local_port'),
                    event_data.get('remote_ip') or event_data.get('remote_addr', '').split(':')[0] if event_data.get('remote_addr') else None,
                    event_data.get('remote_port'),
                    event_data.get('protocol'),
                    event_data.get('connection_count'),
                    event_data.get('unique_ports_accessed')
                ))
            
            # Update agent last seen
            self._update_agent(cursor, agent_name, agent_hostname, agent_ip, event_data.get('modules_enabled'))
            
            return event_id
    
    def _update_agent(self, cursor, agent_name, hostname, ip_address, modules_enabled):
        """
        Update agent information
        
        Args:
            cursor: Database cursor
            agent_name: Agent name
            hostname: Agent hostname
            ip_address: Agent IP address
            modules_enabled: Enabled modules
        """
        now = datetime.now().isoformat()
        
        cursor.execute('SELECT id FROM agents WHERE agent_name = ?', (agent_name,))
        result = cursor.fetchone()
        
        if result:
            # Update existing agent
            cursor.execute('''
                UPDATE agents 
                SET hostname = ?, ip_address = ?, last_seen = ?, status = 'active'
                WHERE agent_name = ?
            ''', (hostname, ip_address, now, agent_name))
        else:
            # Insert new agent
            cursor.execute('''
                INSERT INTO agents (
                    agent_name, hostname, ip_address, first_seen, last_seen, modules_enabled
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                agent_name, hostname, ip_address, now, now,
                json.dumps(modules_enabled) if modules_enabled else None
            ))
    
    def get_events(self, limit=100, offset=0, severity=None, event_type=None, 
                   agent_name=None, mitre_technique=None, start_date=None, end_date=None):
        """
        Query events with filters
        
        Args:
            limit: Maximum number of events to return
            offset: Offset for pagination
            severity: Filter by severity
            event_type: Filter by event type
            agent_name: Filter by agent
            mitre_technique: Filter by MITRE technique
            start_date: Filter events after this date
            end_date: Filter events before this date
            
        Returns:
            list: List of event dictionaries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM events WHERE 1=1'
            params = []
            
            if severity:
                query += ' AND severity = ?'
                params.append(severity)
            
            if event_type:
                query += ' AND event_type = ?'
                params.append(event_type)
            
            if agent_name:
                query += ' AND agent_name = ?'
                params.append(agent_name)
            
            if mitre_technique:
                query += ' AND mitre_technique = ?'
                params.append(mitre_technique)
            
            if start_date:
                query += ' AND timestamp >= ?'
                params.append(start_date)
            
            if end_date:
                query += ' AND timestamp <= ?'
                params.append(end_date)
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                event = dict(row)
                # Parse raw_data JSON
                if event.get('raw_data'):
                    try:
                        event['full_data'] = json.loads(event['raw_data'])
                    except:
                        pass
                events.append(event)
            
            return events
    
    def get_event_count(self, severity=None, event_type=None, agent_name=None):
        """
        Get total count of events
        
        Args:
            severity: Filter by severity
            event_type: Filter by event type
            agent_name: Filter by agent
            
        Returns:
            int: Total event count
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = 'SELECT COUNT(*) as count FROM events WHERE 1=1'
            params = []
            
            if severity:
                query += ' AND severity = ?'
                params.append(severity)
            
            if event_type:
                query += ' AND event_type = ?'
                params.append(event_type)
            
            if agent_name:
                query += ' AND agent_name = ?'
                params.append(agent_name)
            
            cursor.execute(query, params)
            result = cursor.fetchone()
            return result['count'] if result else 0
    
    def get_statistics(self):
        """
        Get statistics about stored events
        
        Returns:
            dict: Statistics dictionary
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {
                'total_events': 0,
                'by_severity': {},
                'by_type': {},
                'by_agent': {},
                'by_mitre': {},
                'recent_events': []
            }
            
            # Total events
            cursor.execute('SELECT COUNT(*) as count FROM events')
            stats['total_events'] = cursor.fetchone()['count']
            
            # By severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count 
                FROM events 
                GROUP BY severity
            ''')
            for row in cursor.fetchall():
                stats['by_severity'][row['severity']] = row['count']
            
            # By type
            cursor.execute('''
                SELECT event_type, COUNT(*) as count 
                FROM events 
                GROUP BY event_type 
                ORDER BY count DESC 
                LIMIT 20
            ''')
            for row in cursor.fetchall():
                stats['by_type'][row['event_type']] = row['count']
            
            # By agent
            cursor.execute('''
                SELECT agent_name, COUNT(*) as count 
                FROM events 
                GROUP BY agent_name
            ''')
            for row in cursor.fetchall():
                stats['by_agent'][row['agent_name']] = row['count']
            
            # By MITRE technique
            cursor.execute('''
                SELECT mitre_technique, COUNT(*) as count 
                FROM events 
                WHERE mitre_technique IS NOT NULL
                GROUP BY mitre_technique 
                ORDER BY count DESC
            ''')
            for row in cursor.fetchall():
                stats['by_mitre'][row['mitre_technique']] = row['count']
            
            return stats
    
    def get_agents(self):
        """
        Get all registered agents
        
        Returns:
            list: List of agent dictionaries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_agents_with_status(self):
        """
        Get all agents with real-time status based on last_seen
        
        Returns:
            list: List of agent dictionaries with updated status
        """
        from datetime import timedelta
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC')
            agents = [dict(row) for row in cursor.fetchall()]
            
            # Update status based on last_seen
            now = datetime.now()
            
            for agent in agents:
                try:
                    last_seen = datetime.fromisoformat(agent['last_seen'])
                    time_diff = (now - last_seen).total_seconds()
                    
                    # Agent is active if seen in last 5 minutes
                    if time_diff < 300:  # 5 minutes
                        agent['status'] = 'active'
                        agent['status_text'] = 'Active'
                    # Agent is inactive if not seen for 5-30 minutes
                    elif time_diff < 1800:  # 30 minutes
                        agent['status'] = 'inactive'
                        agent['status_text'] = 'Inactive'
                    # Agent is offline if not seen for more than 30 minutes
                    else:
                        agent['status'] = 'offline'
                        agent['status_text'] = 'Offline'
                    
                    # Add human-readable last seen time
                    if time_diff < 60:
                        agent['last_seen_text'] = 'Just now'
                    elif time_diff < 3600:
                        mins = int(time_diff / 60)
                        agent['last_seen_text'] = f'{mins} min{"s" if mins > 1 else ""} ago'
                    elif time_diff < 86400:
                        hours = int(time_diff / 3600)
                        agent['last_seen_text'] = f'{hours} hour{"s" if hours > 1 else ""} ago'
                    else:
                        days = int(time_diff / 86400)
                        agent['last_seen_text'] = f'{days} day{"s" if days > 1 else ""} ago'
                        
                except Exception as e:
                    agent['status'] = 'unknown'
                    agent['status_text'] = 'Unknown'
                    agent['last_seen_text'] = 'Unknown'
            
            return agents
    
    
    def delete_old_events(self, days=30):
        """
        Delete events older than specified days
        
        Args:
            days: Delete events older than this many days
            
        Returns:
            int: Number of deleted events
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - days)
            
            cursor.execute('''
                DELETE FROM events 
                WHERE timestamp < ?
            ''', (cutoff_date.isoformat(),))
            
            deleted = cursor.rowcount
            print(f"[INFO] Deleted {deleted} events older than {days} days")
            return deleted
    
    def search_events(self, search_term, limit=100):
        """
        Search events by description or other text fields
        
        Args:
            search_term: Search term
            limit: Maximum results
            
        Returns:
            list: Matching events
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM events 
                WHERE description LIKE ? 
                   OR event_type LIKE ?
                   OR agent_name LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%', limit))
            
            return [dict(row) for row in cursor.fetchall()]


# Convenience functions
def init_db(db_path='database/hids.db'):
    """Initialize database"""
    import os
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return DatabaseManager(db_path)


if __name__ == "__main__":
    # Test database
    print("Testing Database...")
    db = init_db()
    
    # Test event insertion
    test_event = {
        'event_type': 'test_event',
        'severity': 'info',
        'timestamp': datetime.now().isoformat(),
        'agent_info': {
            'agent_name': 'test-agent',
            'hostname': 'test-host',
            'ip_address': '127.0.0.1'
        },
        'mitre_technique': 'T9999',
        'description': 'Test event for database'
    }
    
    event_id = db.insert_event(test_event)
    print(f"[SUCCESS] Inserted test event with ID: {event_id}")
    
    # Test retrieval
    events = db.get_events(limit=5)
    print(f"[SUCCESS] Retrieved {len(events)} events")
    
    # Test statistics
    stats = db.get_statistics()
    print(f"[SUCCESS] Statistics: {stats['total_events']} total events")
    
    print("\n[SUCCESS] Database test completed!")