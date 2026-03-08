"""
HIDS Authentication Manager
Role-Based Access Control (RBAC) System
"""

import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import session, redirect, url_for, jsonify


class AuthManager:
    """
    Manages user authentication and role-based access control
    """
    
    def __init__(self, db_path='database/users.db'):
        self.db_path = db_path
        self.init_database()
        self.create_default_users()
    
    def init_database(self):
        """
        Initialize users database
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT,
                email TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active INTEGER DEFAULT 1,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )
        ''')
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Create audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                success INTEGER DEFAULT 1,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """
        Hash password using SHA-256
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_default_users(self):
        """
        Create default users if they don't exist.
        WARNING: Change these passwords immediately after first login.
        On Fedora production systems, disable or delete these accounts after setup.
        """
        default_users = [
            {
                'username': 'admin',
                'password': 'admin',  # CHANGE IMMEDIATELY
                'role': 'admin',
                'full_name': 'System Administrator',
                'email': 'admin@hids.local'
            },
            {
                'username': 'analyst',
                'password': 'analyst',  # CHANGE IMMEDIATELY
                'role': 'analyst',
                'full_name': 'SOC Analyst',
                'email': 'analyst@hids.local'
            },
            {
                'username': 'viewer',
                'password': 'viewer',  # CHANGE IMMEDIATELY
                'role': 'viewer',
                'full_name': 'Security Viewer',
                'email': 'viewer@hids.local'
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for user in default_users:
            cursor.execute('SELECT id FROM users WHERE username = ?', (user['username'],))
            if not cursor.fetchone():
                cursor.execute('''
                    INSERT INTO users (username, password_hash, role, full_name, email, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    user['username'],
                    self.hash_password(user['password']),
                    user['role'],
                    user['full_name'],
                    user['email'],
                    datetime.now().isoformat()
                ))
                print(f"[AUTH] Created default user: {user['username']} (role: {user['role']})")
        
        conn.commit()
        conn.close()
    
    def authenticate(self, username, password, ip_address=None):
        """
        Authenticate user and return user data if successful
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get user
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()
        
        if not user:
            self.log_audit(None, username, 'login_failed', 'authentication', ip_address, False, 'User not found')
            conn.close()
            return None
        
        # Check if account is locked
        if user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                conn.close()
                return None
        
        # Verify password
        password_hash = self.hash_password(password)
        if password_hash != user['password_hash']:
            # Increment failed attempts
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = failed_attempts + 1
                WHERE id = ?
            ''', (user['id'],))
            
            # Lock account after 5 failed attempts
            if user['failed_attempts'] + 1 >= 5:
                locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                cursor.execute('UPDATE users SET locked_until = ? WHERE id = ?', (locked_until, user['id']))
            
            conn.commit()
            self.log_audit(user['id'], username, 'login_failed', 'authentication', ip_address, False, 'Invalid password')
            conn.close()
            return None
        
        # Successful login - reset failed attempts
        cursor.execute('''
            UPDATE users 
            SET failed_attempts = 0, locked_until = NULL, last_login = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), user['id']))
        
        conn.commit()
        
        # Log successful login
        self.log_audit(user['id'], username, 'login_success', 'authentication', ip_address, True)
        
        user_dict = dict(user)
        conn.close()
        
        return user_dict
    
    def create_session(self, user_id, ip_address=None, user_agent=None):
        """
        Create a new session for user
        """
        session_token = secrets.token_urlsafe(32)
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=8)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (user_id, session_token, created_at, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, session_token, created_at.isoformat(), expires_at.isoformat(), ip_address, user_agent))
        
        conn.commit()
        conn.close()
        
        return session_token
    
    def validate_session(self, session_token):
        """
        Validate session token and return user data
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.*, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND u.is_active = 1
        ''', (session_token,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        # Check if session expired
        expires_at = datetime.fromisoformat(result['expires_at'])
        if datetime.now() > expires_at:
            self.delete_session(session_token)
            return None
        
        return dict(result)
    
    def delete_session(self, session_token):
        """
        Delete session (logout)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
        conn.commit()
        conn.close()
    
    def log_audit(self, user_id, username, action, resource, ip_address=None, success=True, details=None):
        """
        Log user action to audit trail
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (user_id, username, action, resource, timestamp, ip_address, success, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, username, action, resource, datetime.now().isoformat(), ip_address, 1 if success else 0, details))
        
        conn.commit()
        conn.close()
    
    def get_all_users(self):
        """
        Get all users (admin only)
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, role, full_name, email, created_at, last_login, is_active
            FROM users
            ORDER BY created_at DESC
        ''')
        
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return users
    
    def get_audit_log(self, limit=100):
        """
        Get audit log entries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return logs


# Role definitions and permissions
ROLES = {
    'admin': {
        'name': 'Administrator',
        'permissions': [
            'view_dashboard',
            'view_events',
            'acknowledge_events',
            'delete_events',
            'export_reports',
            'view_agents',
            'manage_agents',
            'view_users',
            'manage_users',
            'view_settings',
            'manage_settings',
            'view_audit_log',
            'threat_hunting',
            'forensics',
            'incident_timeline'
        ]
    },
    'analyst': {
        'name': 'SOC Analyst',
        'permissions': [
            'view_dashboard',
            'view_events',
            'acknowledge_events',
            'export_reports',
            'view_agents',
            'threat_hunting',
            'forensics',
            'incident_timeline'
        ]
    },
    'viewer': {
        'name': 'Security Viewer',
        'permissions': [
            'view_dashboard',
            'view_events',
            'view_agents'
        ]
    }
}


def has_permission(user, permission):
    """
    Check if user has specific permission
    """
    if not user:
        return False
    
    role = user.get('role')
    if role not in ROLES:
        return False
    
    return permission in ROLES[role]['permissions']


def login_required(f):
    """
    Decorator to require login for routes
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(permission):
    """
    Decorator to require specific permission
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not has_permission(session['user'], permission):
                return jsonify({'error': 'Permission denied'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(role):
    """
    Decorator to require specific role
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            
            if session['user'].get('role') != role:
                return jsonify({'error': 'Insufficient privileges'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator