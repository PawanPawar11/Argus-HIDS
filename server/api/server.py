"""
HIDS Server with Role-Based Access Control (RBAC)
Enhanced version with user authentication and authorization
FIXED VERSION - Corrects login redirect issue
"""

from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for
from datetime import datetime
import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.models import DatabaseManager
from auth_manager import AuthManager, login_required, permission_required, role_required, has_permission, ROLES


app = Flask(__name__, 
            template_folder='../dashboard/templates',
            static_folder='../dashboard/static')

# Secret key for session management (change this in production!)
app.secret_key = 'your-secret-key-change-in-production-2026'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 28800  # 8 hours

# Initialize database and auth
db = DatabaseManager('database/hids.db')
auth = AuthManager('database/users.db')

# Create logs directory
os.makedirs('logs', exist_ok=True)


# ========== AUTHENTICATION ROUTES ==========

@app.route('/login')
def login_page():
    """
    Serve login page
    """
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    # Serve login.html directly
    try:
        return render_template('login.html')
    except Exception as e:
        print(f"[ERROR] Failed to load login page: {e}")
        # If template not found, try sending file directly
        try:
            return send_from_directory('../dashboard/templates', 'login.html')
        except:
            return f"""
            <h1>Login Page Not Found</h1>
            <p>Please ensure login.html is in: server/dashboard/templates/</p>
            <p>Error: {e}</p>
            """, 404


@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Handle user login (POST only)
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        remember = data.get('remember', False)
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Get client IP
        ip_address = request.remote_addr
        
        # Authenticate user
        user = auth.authenticate(username, password, ip_address)
        
        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Create session
        session['user'] = {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'full_name': user['full_name'],
            'email': user['email']
        }
        
        if remember:
            session.permanent = True
        
        # Create session token
        session_token = auth.create_session(user['id'], ip_address, request.headers.get('User-Agent'))
        session['session_token'] = session_token
        
        print(f"[AUTH] User logged in: {username} (role: {user['role']}) from {ip_address}")
        
        return jsonify({
            'success': True,
            'user': session['user'],
            'permissions': ROLES[user['role']]['permissions']
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Login failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """
    Handle user logout
    """
    try:
        if 'user' in session:
            username = session['user']['username']
            
            # Delete session from database
            if 'session_token' in session:
                auth.delete_session(session['session_token'])
            
            # Log logout
            auth.log_audit(session['user']['id'], username, 'logout', 'authentication', request.remote_addr)
            
            print(f"[AUTH] User logged out: {username}")
            
            # Clear session
            session.clear()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        print(f"[ERROR] Logout failed: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@app.route('/api/auth/current-user', methods=['GET'])
@login_required
def get_current_user():
    """
    Get current logged-in user info
    """
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'user': user,
        'role_name': ROLES[user['role']]['name'],
        'permissions': ROLES[user['role']]['permissions']
    }), 200


# ========== DASHBOARD ROUTES WITH RBAC ==========

@app.route('/')
@login_required
@permission_required('view_dashboard')
def dashboard():
    """
    Serve main dashboard page (requires authentication)
    """
    try:
        return render_template('index.html')
    except Exception as e:
        print(f"[ERROR] Failed to load dashboard: {e}")
        return f"Dashboard template not found: {e}", 500


@app.route('/static/<path:path>')
def send_static(path):
    """
    Serve static files
    """
    return send_from_directory('../dashboard/static', path)


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint (public)
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'server': 'HIDS Server v2.0 with RBAC',
        'database': 'SQLite',
        'total_events': db.get_event_count(),
        'auth_enabled': True
    }), 200


# ========== EVENT ROUTES WITH RBAC ==========

@app.route('/api/events', methods=['POST'])
def receive_event():
    """
    Receive security events from agents (no auth required for agents)
    """
    try:
        event = request.get_json()
        
        if not event:
            return jsonify({'error': 'No event data provided'}), 400
        
        event['server_received_at'] = datetime.now().isoformat()
        event_id = db.insert_event(event)
        
        log_event(event)
        
        agent_name = event.get('agent_info', {}).get('agent_name', 'unknown')
        event_type = event.get('event_type', 'unknown')
        severity = event.get('severity', 'unknown')
        
        print(f"[EVENT RECEIVED] Agent: {agent_name} | Type: {event_type} | Severity: {severity} | ID: {event_id}")
        
        if severity in ['high', 'critical']:
            print(f"[ALERT] {event.get('description', 'No description')}")
        
        return jsonify({
            'status': 'success',
            'message': 'Event received and stored',
            'event_id': event_id
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to process event: {e}")
        return jsonify({'error': str(e)}), 500


def log_event(event):
    """
    Log event to file (backup)
    """
    try:
        log_file = 'logs/server_events.log'
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}")


@app.route('/api/events', methods=['GET'])
@login_required
@permission_required('view_events')
def get_events():
    """
    Retrieve stored events with filtering (requires view_events permission)
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        severity = request.args.get('severity', None)
        event_type = request.args.get('event_type', None)
        agent = request.args.get('agent', None)
        mitre = request.args.get('mitre', None)
        start_date = request.args.get('start_date', None)
        end_date = request.args.get('end_date', None)
        
        if limit > 1000:
            limit = 1000
        
        events = db.get_events(
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            agent_name=agent,
            mitre_technique=mitre,
            start_date=start_date,
            end_date=end_date
        )
        
        total = db.get_event_count(
            severity=severity,
            event_type=event_type,
            agent_name=agent
        )
        
        return jsonify({
            'total': total,
            'limit': limit,
            'offset': offset,
            'count': len(events),
            'events': events
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to retrieve events: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<int:event_id>', methods=['GET'])
@login_required
@permission_required('view_events')
def get_event_details(event_id):
    """
    Get detailed information about a specific event
    """
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
            row = cursor.fetchone()
            
            if not row:
                return jsonify({'error': 'Event not found'}), 404
            
            event = dict(row)
            
            # Get type-specific data
            event_type = event.get('event_type', '')
            
            if 'file' in event_type:
                cursor.execute('SELECT * FROM file_events WHERE event_id = ?', (event_id,))
                file_data = cursor.fetchone()
                if file_data:
                    event['file_details'] = dict(file_data)
            
            elif any(k in event_type for k in ['auth', 'login', 'sudo']):
                cursor.execute('SELECT * FROM auth_events WHERE event_id = ?', (event_id,))
                auth_data = cursor.fetchone()
                if auth_data:
                    event['auth_details'] = dict(auth_data)
            
            elif 'process' in event_type:
                cursor.execute('SELECT * FROM process_events WHERE event_id = ?', (event_id,))
                process_data = cursor.fetchone()
                if process_data:
                    event['process_details'] = dict(process_data)
            
            elif any(k in event_type for k in ['network', 'connection', 'port']):
                cursor.execute('SELECT * FROM network_events WHERE event_id = ?', (event_id,))
                network_data = cursor.fetchone()
                if network_data:
                    event['network_details'] = dict(network_data)
            
            return jsonify(event), 200
    except Exception as e:
        print(f"[ERROR] Failed to get event details: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<int:event_id>/acknowledge', methods=['POST'])
@login_required
@permission_required('acknowledge_events')
def acknowledge_event(event_id):
    """
    Acknowledge an event (requires acknowledge_events permission)
    """
    try:
        user = session.get('user')
        
        # Log acknowledgment
        auth.log_audit(
            user['id'],
            user['username'],
            'acknowledge_event',
            f'event_{event_id}',
            request.remote_addr,
            True,
            'Event acknowledged'
        )
        
        print(f"[EVENT] Event {event_id} acknowledged by {user['username']}")
        
        return jsonify({
            'success': True,
            'message': f'Event {event_id} acknowledged by {user["username"]}'
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to acknowledge event: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/delete-old', methods=['POST'])
@login_required
@permission_required('delete_events')
def delete_old_events():
    """
    Delete old events (requires delete_events permission - admin only)
    """
    try:
        days = request.args.get('days', 30, type=int)
        
        if days < 7:
            return jsonify({'error': 'Minimum retention is 7 days'}), 400
        
        deleted = db.delete_old_events(days)
        
        # Log deletion
        user = session.get('user')
        auth.log_audit(
            user['id'],
            user['username'],
            'delete_old_events',
            'events',
            request.remote_addr,
            True,
            f'Deleted {deleted} events older than {days} days'
        )
        
        return jsonify({
            'status': 'success',
            'deleted': deleted,
            'days': days
        }), 200
    except Exception as e:
        print(f"[ERROR] Failed to delete old events: {e}")
        return jsonify({'error': str(e)}), 500


# ========== DASHBOARD DATA ROUTES ==========

@app.route('/api/stats', methods=['GET'])
@login_required
@permission_required('view_dashboard')
def get_stats():
    """
    Get statistics (requires view_dashboard permission)
    """
    try:
        stats = db.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        print(f"[ERROR] Failed to get statistics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/agents', methods=['GET'])
@login_required
@permission_required('view_agents')
def get_agents():
    """
    Get all agents (requires view_agents permission)
    """
    try:
        agents = db.get_agents_with_status()
        return jsonify({
            'total': len(agents),
            'agents': agents
        }), 200
    except Exception as e:
        print(f"[ERROR] Failed to get agents: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/search', methods=['GET'])
@login_required
@permission_required('view_events')
def search_events():
    """
    Search events (requires view_events permission)
    """
    try:
        query = request.args.get('q', '')
        limit = request.args.get('limit', 100, type=int)
        
        if not query:
            return jsonify({'error': 'Search query required'}), 400
        
        events = db.search_events(query, limit=limit)
        
        return jsonify({
            'query': query,
            'count': len(events),
            'events': events
        }), 200
    except Exception as e:
        print(f"[ERROR] Search failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard', methods=['GET'])
@login_required
@permission_required('view_dashboard')
def get_dashboard_data():
    """
    Get dashboard data (requires view_dashboard permission)
    """
    try:
        stats = db.get_statistics()
        
        try:
            agents = db.get_agents_with_status()
        except AttributeError:
            agents = db.get_agents()
            for agent in agents:
                agent['status'] = 'active'
                agent['status_text'] = 'Active'
                agent['last_seen_text'] = 'Unknown'
        
        recent_events = db.get_events(limit=100)
        critical_events = db.get_events(severity='critical', limit=10)
        active_agents = len([a for a in agents if a.get('status') == 'active'])
        
        if 'by_severity' not in stats:
            stats['by_severity'] = {}
        if 'by_type' not in stats:
            stats['by_type'] = {}
        if 'by_mitre' not in stats:
            stats['by_mitre'] = {}
        
        dashboard = {
            'summary': {
                'total_events': stats.get('total_events', 0),
                'active_agents': active_agents,
                'critical_events': len(critical_events),
                'severity_breakdown': stats['by_severity']
            },
            'recent_events': recent_events,
            'critical_events': critical_events,
            'agents': agents,
            'top_event_types': dict(list(stats['by_type'].items())[:10]) if stats['by_type'] else {},
            'mitre_techniques': stats['by_mitre']
        }
        
        return jsonify(dashboard), 200
    except Exception as e:
        print(f"[ERROR] Failed to get dashboard data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ========== ADMIN ROUTES ==========

@app.route('/api/admin/users', methods=['GET'])
@login_required
@role_required('admin')
def get_users():
    """
    Get all users (admin only)
    """
    try:
        users = auth.get_all_users()
        return jsonify({
            'total': len(users),
            'users': users
        }), 200
    except Exception as e:
        print(f"[ERROR] Failed to get users: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/audit-log', methods=['GET'])
@login_required
@permission_required('view_audit_log')
def get_audit_log():
    """
    Get audit log (requires view_audit_log permission)
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        logs = auth.get_audit_log(limit=limit)
        return jsonify({
            'total': len(logs),
            'logs': logs
        }), 200
    except Exception as e:
        print(f"[ERROR] Failed to get audit log: {e}")
        return jsonify({'error': str(e)}), 500


# ========== ERROR HANDLERS ==========

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


def print_banner():
    """
    Print server banner
    """
    print("\n" + "="*70)
    print("  HOST-BASED INTRUSION DETECTION SYSTEM (HIDS) SERVER v2.0")
    print("  with Role-Based Access Control (RBAC)")
    print("="*70)
    print("  Status: Running")
    print("  Port: 5000")
    print("  Database: SQLite (database/hids.db)")
    print(f"  Total Events: {db.get_event_count()}")
    print("  Authentication: ENABLED")
    print("  " + "-"*66)
    print("  Demo Credentials:")
    print("    - admin / admin (Full Access)")
    print("    - analyst / analyst (SOC Analyst)")
    print("    - viewer / viewer (Read Only)")
    print("  " + "-"*66)
    print("  Access Points:")
    print("    - http://localhost:5000/login  (Login Page)")
    print("    - http://localhost:5000/       (Dashboard - Auth Required)")
    print("    - http://localhost:5000/health (Health Check - Public)")
    print("  " + "-"*66)
    print("  API Endpoints:")
    print("    - POST /api/auth/login      (Authentication)")
    print("    - POST /api/auth/logout     (Logout)")
    print("    - GET  /api/auth/current-user (Get session)")
    print("    - POST /api/events          (Receive events - No Auth)")
    print("    - GET  /api/events          (Query events - Auth Required)")
    print("    - GET  /api/dashboard       (Dashboard data - Auth Required)")
    print("    - GET  /api/admin/users     (User management - Admin Only)")
    print("    - GET  /api/admin/audit-log (Audit log - Admin/Analyst)")
    print("="*70 + "\n")


if __name__ == '__main__':
    print_banner()
    
    # Run server
    app.run(host='0.0.0.0', port=5000, debug=True)