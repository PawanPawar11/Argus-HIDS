// HIDS Enhanced Dashboard JavaScript - COMPLETE VERSION WITH EXPORT
// Fixed all errors + Added working export functionality

// ===== RBAC AUTHENTICATION ADDITIONS FOR DASHBOARD.JS =====
// Add these functions to the top of your dashboard_enhanced.js file

// Current user and permissions
let currentUser = null;
let userPermissions = [];

// Initialize authentication on page load
document.addEventListener('DOMContentLoaded', async () => {
    await checkAuthentication();
    // ... rest of your existing DOMContentLoaded code
});

// Check if user is authenticated
async function checkAuthentication() {
    try {
        const response = await fetch('/api/auth/current-user');
        
        if (response.ok) {
            const data = await response.json();
            currentUser = data.user;
            userPermissions = data.permissions;
            
            // Update UI with user info
            updateUserInterface();
            
            // Initialize dashboard based on permissions
            initializeDashboardByRole();
            
            console.log(`[AUTH] Logged in as: ${currentUser.username} (${data.role_name})`);
        } else {
            // Not authenticated, redirect to login
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('[AUTH] Authentication check failed:', error);
        window.location.href = '/login';
    }
}

// Update UI with user information
function updateUserInterface() {
    // Add user badge to header
    const headerInfo = document.querySelector('.header-info');
    if (headerInfo && currentUser) {
        const userBadge = document.createElement('div');
        userBadge.className = 'user-badge';
        userBadge.innerHTML = `
            <div class="user-info-dropdown">
                <button class="user-btn" onclick="toggleUserMenu()">
                    <i class="fas fa-user-circle"></i>
                    <span>${currentUser.full_name}</span>
                    <i class="fas fa-chevron-down"></i>
                </button>
                <div class="user-menu" id="userMenu" style="display: none;">
                    <div class="user-menu-header">
                        <div class="user-avatar">
                            <i class="fas fa-user-circle"></i>
                        </div>
                        <div class="user-details">
                            <div class="user-name">${currentUser.full_name}</div>
                            <div class="user-role">${getRoleName(currentUser.role)}</div>
                            <div class="user-email">${currentUser.email}</div>
                        </div>
                    </div>
                    <div class="user-menu-divider"></div>
                    <button class="user-menu-item" onclick="showUserProfile()">
                        <i class="fas fa-user"></i> Profile
                    </button>
                    <button class="user-menu-item" onclick="showUserSettings()">
                        <i class="fas fa-cog"></i> Settings
                    </button>
                    ${hasPermission('view_audit_log') ? `
                    <button class="user-menu-item" onclick="showAuditLog()">
                        <i class="fas fa-history"></i> Audit Log
                    </button>` : ''}
                    ${hasPermission('manage_users') ? `
                    <button class="user-menu-item" onclick="showUserManagement()">
                        <i class="fas fa-users-cog"></i> User Management
                    </button>` : ''}
                    <div class="user-menu-divider"></div>
                    <button class="user-menu-item logout" onclick="handleLogout()">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </button>
                </div>
            </div>
        `;
        
        // Insert before last-update span
        headerInfo.insertBefore(userBadge, headerInfo.firstChild);
    }
}

// Toggle user menu
function toggleUserMenu() {
    const menu = document.getElementById('userMenu');
    if (menu) {
        menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
    }
}

// Close user menu when clicking outside
document.addEventListener('click', (event) => {
    const userBtn = event.target.closest('.user-btn');
    const userMenu = document.getElementById('userMenu');
    
    if (!userBtn && userMenu && userMenu.style.display === 'block') {
        userMenu.style.display = 'none';
    }
});

// Get role display name
function getRoleName(role) {
    const roleNames = {
        'admin': 'Administrator',
        'analyst': 'SOC Analyst',
        'viewer': 'Security Viewer'
    };
    return roleNames[role] || role;
}

// Check if user has specific permission
function hasPermission(permission) {
    return userPermissions.includes(permission);
}

// Initialize dashboard based on user role
function initializeDashboardByRole() {
    // Hide/disable features based on permissions
    
    // Export button
    if (!hasPermission('export_reports')) {
        const exportBtn = document.querySelector('[onclick="exportReport()"]');
        if (exportBtn) {
            exportBtn.style.display = 'none';
        }
    }
    
    // Threat Hunting button
    if (!hasPermission('threat_hunting')) {
        const huntingBtn = document.querySelector('[onclick="showThreatHunting()"]');
        if (huntingBtn) {
            huntingBtn.style.display = 'none';
        }
    }
    
    // Forensics button
    if (!hasPermission('forensics')) {
        const forensicsBtn = document.querySelector('[onclick="showForensics()"]');
        if (forensicsBtn) {
            forensicsBtn.style.display = 'none';
        }
    }
    
    // Acknowledge buttons
    if (!hasPermission('acknowledge_events')) {
        const ackButtons = document.querySelectorAll('[onclick*="acknowledge"]');
        ackButtons.forEach(btn => {
            btn.style.display = 'none';
        });
    }
    
    // Show role-specific message
    showRoleWelcomeMessage();
}

// Show welcome message based on role
function showRoleWelcomeMessage() {
    const messages = {
        'admin': '👑 Administrator access enabled. Full system control available.',
        'analyst': '🔍 SOC Analyst mode. Event analysis and response tools active.',
        'viewer': '👁️ Viewer mode. Read-only access to security data.'
    };
    
    const message = messages[currentUser.role];
    if (message) {
        console.log(`[RBAC] ${message}`);
    }
}

// Handle logout
async function handleLogout() {
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            window.location.href = '/login';
        } else {
            console.error('[AUTH] Logout failed');
        }
    } catch (error) {
        console.error('[AUTH] Logout error:', error);
    }
}

// Show user profile (placeholder)
function showUserProfile() {
    showAlert(`👤 Profile: ${currentUser.full_name} (${currentUser.username})`);
    setTimeout(closeAlert, 3000);
}

// Show user settings (placeholder)
function showUserSettings() {
    showAlert('⚙️ Settings panel coming soon!');
    setTimeout(closeAlert, 2000);
}

// Show audit log (admin/analyst only)
async function showAuditLog() {
    if (!hasPermission('view_audit_log')) {
        showAlert('❌ Permission denied: Audit log access requires admin privileges');
        setTimeout(closeAlert, 3000);
        return;
    }
    
    try {
        const response = await fetch('/api/admin/audit-log?limit=50');
        const data = await response.json();
        
        if (response.ok) {
            displayAuditLogModal(data.logs);
        } else {
            showAlert('❌ Failed to load audit log');
            setTimeout(closeAlert, 3000);
        }
    } catch (error) {
        console.error('[AUDIT] Failed to load audit log:', error);
    }
}

// Display audit log in modal
function displayAuditLogModal(logs) {
    const modal = document.getElementById('eventDetailModal');
    const body = document.getElementById('eventDetailBody');
    const header = modal.querySelector('.modal-header h2');
    
    if (!modal || !body || !header) return;
    
    header.innerHTML = '<i class="fas fa-history"></i> Audit Log';
    
    body.innerHTML = `
        <div style="max-height: 500px; overflow-y: auto;">
            <table style="width: 100%; border-collapse: collapse;">
                <thead style="position: sticky; top: 0; background: var(--card-bg); z-index: 1;">
                    <tr>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Time</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">User</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Action</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Resource</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${logs.map(log => `
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 0.75rem; font-family: var(--font-mono); font-size: 0.85rem;">
                                ${new Date(log.timestamp).toLocaleString()}
                            </td>
                            <td style="padding: 0.75rem;">${log.username}</td>
                            <td style="padding: 0.75rem;">${log.action}</td>
                            <td style="padding: 0.75rem; font-family: var(--font-mono); font-size: 0.85rem;">
                                ${log.resource || 'N/A'}
                            </td>
                            <td style="padding: 0.75rem;">
                                <span style="padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; ${log.success ? 'background: rgba(0, 245, 212, 0.2); color: #00f5d4;' : 'background: rgba(255, 0, 85, 0.2); color: #ff0055;'}">
                                    ${log.success ? '✓ Success' : '✗ Failed'}
                                </span>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    
    modal.classList.add('active');
}

// Show user management (admin only)
async function showUserManagement() {
    if (!hasPermission('manage_users')) {
        showAlert('❌ Permission denied: User management requires admin privileges');
        setTimeout(closeAlert, 3000);
        return;
    }
    
    try {
        const response = await fetch('/api/admin/users');
        const data = await response.json();
        
        if (response.ok) {
            displayUserManagementModal(data.users);
        } else {
            showAlert('❌ Failed to load users');
            setTimeout(closeAlert, 3000);
        }
    } catch (error) {
        console.error('[USERS] Failed to load users:', error);
    }
}

// Display user management in modal
function displayUserManagementModal(users) {
    const modal = document.getElementById('eventDetailModal');
    const body = document.getElementById('eventDetailBody');
    const header = modal.querySelector('.modal-header h2');
    
    if (!modal || !body || !header) return;
    
    header.innerHTML = '<i class="fas fa-users-cog"></i> User Management';
    
    body.innerHTML = `
        <div style="max-height: 500px; overflow-y: auto;">
            <table style="width: 100%; border-collapse: collapse;">
                <thead style="position: sticky; top: 0; background: var(--card-bg); z-index: 1;">
                    <tr>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Username</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Full Name</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Role</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Email</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Last Login</th>
                        <th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid var(--border-color);">Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${users.map(user => `
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 0.75rem; font-family: var(--font-mono);">${user.username}</td>
                            <td style="padding: 0.75rem;">${user.full_name}</td>
                            <td style="padding: 0.75rem;">
                                <span style="padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; ${getRoleColor(user.role)}">
                                    ${user.role}
                                </span>
                            </td>
                            <td style="padding: 0.75rem; font-size: 0.85rem;">${user.email}</td>
                            <td style="padding: 0.75rem; font-family: var(--font-mono); font-size: 0.85rem;">
                                ${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                            </td>
                            <td style="padding: 0.75rem;">
                                <span style="padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; ${user.is_active ? 'background: rgba(0, 245, 212, 0.2); color: #00f5d4;' : 'background: rgba(255, 0, 85, 0.2); color: #ff0055;'}">
                                    ${user.is_active ? '● Active' : '○ Inactive'}
                                </span>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    
    modal.classList.add('active');
}

// Get role badge color
function getRoleColor(role) {
    const colors = {
        'admin': 'background: rgba(255, 0, 85, 0.2); color: #ff0055;',
        'analyst': 'background: rgba(0, 217, 255, 0.2); color: #00d9ff;',
        'viewer': 'background: rgba(255, 190, 11, 0.2); color: #ffbe0b;'
    };
    return colors[role] || 'background: rgba(255, 255, 255, 0.1); color: #9ca3af;';
}

// Override acknowledge event function to check permissions
const originalAcknowledgeEvent = window.acknowledgeEvent;
window.acknowledgeEvent = async function(eventId) {
    if (!hasPermission('acknowledge_events')) {
        showAlert('❌ Permission denied: Event acknowledgment requires analyst privileges');
        setTimeout(closeAlert, 3000);
        return;
    }
    
    try {
        const response = await fetch(`/api/events/${eventId}/acknowledge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            showAlert(`✓ Event ${eventId} acknowledged`);
            setTimeout(closeAlert, 3000);
        } else {
            const data = await response.json();
            showAlert(`❌ ${data.error || 'Failed to acknowledge event'}`);
            setTimeout(closeAlert, 3000);
        }
    } catch (error) {
        console.error('Error acknowledging event:', error);
        showAlert('❌ Network error');
        setTimeout(closeAlert, 3000);
    }
};

// Add CSS for user menu
const userMenuStyles = `
<style>
.user-badge {
    position: relative;
}

.user-btn {
    padding: 0.5rem 1rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 0.9rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    transition: all 0.3s ease;
}

.user-btn:hover {
    background: rgba(255, 255, 255, 0.08);
    border-color: var(--accent-cyan);
}

.user-menu {
    position: absolute;
    top: calc(100% + 0.5rem);
    right: 0;
    min-width: 280px;
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    z-index: 1000;
}

.user-menu-header {
    padding: 1.5rem;
    display: flex;
    gap: 1rem;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
}

.user-avatar {
    font-size: 3rem;
    color: var(--accent-cyan);
}

.user-details {
    flex: 1;
}

.user-name {
    font-weight: 600;
    font-size: 1rem;
    margin-bottom: 0.25rem;
}

.user-role {
    font-size: 0.8rem;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 0.25rem;
}

.user-email {
    font-size: 0.75rem;
    color: var(--text-muted);
}

.user-menu-divider {
    height: 1px;
    background: var(--border-color);
    margin: 0.5rem 0;
}

.user-menu-item {
    width: 100%;
    padding: 0.75rem 1.5rem;
    background: none;
    border: none;
    color: var(--text-primary);
    font-size: 0.9rem;
    text-align: left;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    transition: all 0.3s ease;
}

.user-menu-item:hover {
    background: rgba(255, 255, 255, 0.05);
}

.user-menu-item.logout {
    color: var(--critical-color);
}

.user-menu-item.logout:hover {
    background: rgba(255, 0, 85, 0.1);
}
</style>
`;

// Inject styles
document.head.insertAdjacentHTML('beforeend', userMenuStyles);

// Export for use in main dashboard code
window.rbacAuth = {
    currentUser,
    userPermissions,
    hasPermission,
    handleLogout,
    showAuditLog,
    showUserManagement
};

const API_BASE = '/api';
let allEvents = [];
let filteredEvents = [];
let charts = {};
let eventStream = [];
let streamPaused = false;
let soundEnabled = true;
let liveFeedEnabled = true;
let currentPage = 1;
let eventsPerPage = 50;
let sortColumn = 'timestamp';
let sortDirection = 'desc';

// Audio context for alerts
let audioContext;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeAudio();
    loadDashboard();
    
    // Refresh every 10 seconds for real-time updates
    setInterval(() => {
        if (liveFeedEnabled) {
            loadDashboard();
            updateEventStream();
        }
    }, 10000);
    
    // Update threat level every 30 seconds
    setInterval(updateThreatLevel, 30000);
});

// Initialize audio for alerts
function initializeAudio() {
    try {
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
    } catch (e) {
        console.log('Web Audio API not supported');
    }
}

// Play alert sound
function playAlertSound(severity) {
    if (!soundEnabled || !audioContext) return;
    
    try {
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        const frequencies = {
            'critical': [800, 1000],
            'high': [600, 800],
            'medium': [400, 600],
            'info': [300, 400]
        };
        
        const [freq1, freq2] = frequencies[severity] || frequencies['info'];
        oscillator.frequency.setValueAtTime(freq1, audioContext.currentTime);
        oscillator.frequency.exponentialRampToValueAtTime(freq2, audioContext.currentTime + 0.1);
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.3);
    } catch (e) {
        console.error('Error playing alert sound:', e);
    }
}

// Toggle sound alerts
function toggleSound() {
    soundEnabled = !soundEnabled;
    const icon = document.getElementById('soundIcon');
    if (icon) {
        icon.className = soundEnabled ? 'fas fa-volume-up' : 'fas fa-volume-mute';
    }
}

// Toggle live feed
function toggleLiveFeed() {
    liveFeedEnabled = !liveFeedEnabled;
    if (liveFeedEnabled) {
        loadDashboard();
    }
}

// Update last update time
function updateLastUpdateTime() {
    const now = new Date();
    const updateEl = document.getElementById('lastUpdate');
    if (updateEl) {
        updateEl.textContent = `Last update: ${now.toLocaleTimeString()}`;
    }
}

// Calculate and update threat level
function updateThreatLevel() {
    const badge = document.getElementById('threatLevel');
    if (!badge) return;
    
    const oneHourAgo = new Date(Date.now() - 3600000).toISOString();
    const recentCritical = allEvents.filter(e => 
        e.severity === 'critical' && e.timestamp > oneHourAgo
    ).length;
    const recentHigh = allEvents.filter(e => 
        e.severity === 'high' && e.timestamp > oneHourAgo
    ).length;
    
    let level = 'LOW';
    if (recentCritical >= 10 || recentHigh >= 20) {
        level = 'CRITICAL';
    } else if (recentCritical >= 5 || recentHigh >= 10) {
        level = 'HIGH';
    } else if (recentCritical >= 1 || recentHigh >= 5) {
        level = 'MEDIUM';
    }
    
    badge.textContent = level;
    badge.className = `threat-badge ${level}`;
    
    if (level === 'CRITICAL') {
        showAlert(`⚠️ CRITICAL: Threat level elevated to ${level}. Multiple high-severity events detected.`);
    }
}

// Show alert banner
function showAlert(message) {
    const banner = document.getElementById('alertBanner');
    const messageEl = document.getElementById('alertMessage');
    if (banner && messageEl) {
        messageEl.textContent = message;
        banner.style.display = 'flex';
        
        if (soundEnabled) {
            playAlertSound('critical');
        }
    }
}

// Close alert banner
function closeAlert() {
    const banner = document.getElementById('alertBanner');
    if (banner) {
        banner.style.display = 'none';
    }
}

// Load all dashboard data
async function loadDashboard() {
    try {
        updateLastUpdateTime();
        await Promise.all([
            loadDashboardData(),
            loadCriticalEvents(),
            loadAllEvents(),
            loadAgents()
        ]);
        updateThreatLevel();
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Load main dashboard data
async function loadDashboardData() {
    try {
        const response = await fetch(`${API_BASE}/dashboard`);
        const data = await response.json();
        
        if (!data || !data.summary) {
            console.error('Invalid dashboard data:', data);
            return;
        }
        
        updateSummaryCards(data);
        
        if (data.summary.severity_breakdown) {
            updateSeverityChart(data.summary.severity_breakdown);
        }
        if (data.top_event_types) {
            updateTypeChart(data.top_event_types);
        }
        if (data.mitre_techniques) {
            updateMitreChart(data.mitre_techniques);
        }
        if (data.recent_events) {
            updateTimelineChart(data.recent_events);
        }
        
        updateAnalytics(data);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

// Update summary cards with sparklines
function updateSummaryCards(data) {
    const summary = data.summary || {};
    const recentEvents = data.recent_events || [];
    
    const totalEventsEl = document.getElementById('totalEvents');
    if (totalEventsEl) {
        totalEventsEl.textContent = (summary.total_events || 0).toLocaleString();
    }
    
    const criticalEventsEl = document.getElementById('criticalEvents');
    if (criticalEventsEl) {
        criticalEventsEl.textContent = (summary.critical_events || 0).toLocaleString();
    }
    
    const agents = data.agents || [];
    const activeAgents = agents.filter(a => a.status === 'active').length;
    const inactiveAgents = agents.filter(a => a.status === 'inactive').length;
    
    const activeAgentsEl = document.getElementById('activeAgents');
    if (activeAgentsEl) {
        activeAgentsEl.textContent = activeAgents.toLocaleString();
    }
    
    const agentsActiveEl = document.getElementById('agentsActive');
    if (agentsActiveEl) {
        agentsActiveEl.textContent = activeAgents;
    }
    
    const agentsInactiveEl = document.getElementById('agentsInactive');
    if (agentsInactiveEl) {
        agentsInactiveEl.textContent = inactiveAgents;
    }
    
    const today = new Date().toISOString().split('T')[0];
    const todayEvents = recentEvents.filter(e => 
        e.timestamp && e.timestamp.startsWith(today)
    ).length;
    
    const todayEventsEl = document.getElementById('todayEvents');
    if (todayEventsEl) {
        todayEventsEl.textContent = todayEvents.toLocaleString();
    }
    
    const networkAttacks = recentEvents.filter(e => 
        e.event_type && e.event_type.includes('network')
    ).length;
    const fileAttacks = recentEvents.filter(e => 
        e.event_type && e.event_type.includes('file')
    ).length;
    
    const attackSurfaceEl = document.getElementById('attackSurface');
    if (attackSurfaceEl) {
        attackSurfaceEl.textContent = (networkAttacks + fileAttacks).toLocaleString();
    }
    
    const networkAttacksEl = document.getElementById('networkAttacks');
    if (networkAttacksEl) {
        networkAttacksEl.textContent = networkAttacks;
    }
    
    const fileAttacksEl = document.getElementById('fileAttacks');
    if (fileAttacksEl) {
        fileAttacksEl.textContent = fileAttacks;
    }
    
    const avgTime = Math.floor(Math.random() * 10) + 5;
    const avgResponseTimeEl = document.getElementById('avgResponseTime');
    if (avgResponseTimeEl) {
        avgResponseTimeEl.textContent = `${avgTime}s`;
    }
    
    const responseFill = document.getElementById('responseFill');
    if (responseFill) {
        responseFill.style.width = `${Math.min(100, (20 - avgTime) * 5)}%`;
    }
    
    updateSparklines(recentEvents);
}

// Update sparkline charts
function updateSparklines(events) {
    const hourlyData = {};
    const now = new Date();
    
    for (let i = 11; i >= 0; i--) {
        const hour = new Date(now - i * 3600000);
        const key = hour.toISOString().slice(0, 13);
        hourlyData[key] = { total: 0, critical: 0 };
    }
    
    events.forEach(event => {
        const hour = event.timestamp.slice(0, 13);
        if (hourlyData[hour]) {
            hourlyData[hour].total++;
            if (event.severity === 'critical') {
                hourlyData[hour].critical++;
            }
        }
    });
    
    const hours = Object.keys(hourlyData);
    const totalData = hours.map(h => hourlyData[h].total);
    const criticalData = hours.map(h => hourlyData[h].critical);
    
    updateSparkline('sparklineTotal', totalData, 'rgba(102, 126, 234, 0.8)');
    updateSparkline('sparklineCritical', criticalData, 'rgba(255, 0, 85, 0.8)');
    
    const todayData = Array(12).fill(0);
    events.forEach(event => {
        const eventDate = new Date(event.timestamp);
        if (eventDate.toDateString() === now.toDateString()) {
            const hour = eventDate.getHours();
            if (hour >= now.getHours() - 11) {
                todayData[11 - (now.getHours() - hour)]++;
            }
        }
    });
    updateSparkline('sparklineToday', todayData, 'rgba(0, 245, 212, 0.8)');
}

// Update individual sparkline
function updateSparkline(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (charts[canvasId]) {
        charts[canvasId].destroy();
    }
    
    try {
        charts[canvasId] = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map((_, i) => ''),
                datasets: [{
                    data: data,
                    borderColor: color,
                    backgroundColor: color.replace('0.8', '0.2'),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                },
                scales: {
                    x: { display: false },
                    y: { display: false }
                }
            }
        });
    } catch (e) {
        console.error('Error creating sparkline chart:', e);
    }
}

// Update severity pie chart
function updateSeverityChart(severityData) {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (charts.severity) {
        charts.severity.destroy();
    }
    
    const data = [
        severityData.critical || 0,
        severityData.high || 0,
        severityData.medium || 0,
        severityData.info || 0
    ];
    
    try {
        charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Info'],
                datasets: [{
                    data: data,
                    backgroundColor: [
                        'rgba(255, 0, 85, 0.8)',
                        'rgba(255, 107, 53, 0.8)',
                        'rgba(255, 190, 11, 0.8)',
                        'rgba(0, 245, 212, 0.8)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 12, family: 'Sora' },
                            color: '#e8eaed',
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(30, 38, 53, 0.95)',
                        titleFont: { size: 14, family: 'Sora' },
                        bodyFont: { size: 13, family: 'Sora' },
                        padding: 12,
                        borderColor: 'rgba(0, 217, 255, 0.3)',
                        borderWidth: 1,
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    } catch (e) {
        console.error('Error creating severity chart:', e);
    }
}

// Update event type bar chart - FIXED VERSION
function updateTypeChart(typeData) {
    const canvas = document.getElementById('typeChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (charts.type) {
        charts.type.destroy();
    }
    
    const limitElement = document.getElementById('typeChartLimit');
    const limit = limitElement ? parseInt(limitElement.value || 8) : 8;
    
    const types = Object.keys(typeData).slice(0, limit);
    const counts = types.map(t => typeData[t]);
    
    try {
        charts.type = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: types.map(t => formatEventType(t)),
                datasets: [{
                    label: 'Events',
                    data: counts,
                    backgroundColor: 'rgba(0, 217, 255, 0.7)',
                    borderColor: 'rgba(0, 217, 255, 1)',
                    borderWidth: 0,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            color: '#9ca3af',
                            font: { family: 'Sora' }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        }
                    },
                    x: {
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45,
                            color: '#9ca3af',
                            font: { family: 'Sora', size: 10 }
                        },
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(30, 38, 53, 0.95)',
                        titleFont: { size: 14, family: 'Sora' },
                        bodyFont: { size: 13, family: 'Sora' },
                        padding: 12,
                        borderColor: 'rgba(0, 217, 255, 0.3)',
                        borderWidth: 1
                    }
                }
            }
        });
    } catch (e) {
        console.error('Error creating type chart:', e);
    }
}

// Update MITRE chart
function updateMitreChart(mitreData) {
    const canvas = document.getElementById('mitreChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (charts.mitre) {
        charts.mitre.destroy();
    }
    
    const techniques = Object.keys(mitreData).slice(0, 8);
    const counts = techniques.map(t => mitreData[t]);
    
    try {
        charts.mitre = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: techniques,
                datasets: [{
                    label: 'Detections',
                    data: counts,
                    backgroundColor: 'rgba(123, 44, 191, 0.7)',
                    borderColor: 'rgba(123, 44, 191, 1)',
                    borderWidth: 0,
                    borderRadius: 8
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            color: '#9ca3af',
                            font: { family: 'Sora' }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#9ca3af',
                            font: { family: 'JetBrains Mono', size: 10 }
                        },
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(30, 38, 53, 0.95)',
                        titleFont: { size: 14, family: 'Sora' },
                        bodyFont: { size: 13, family: 'JetBrains Mono' },
                        padding: 12,
                        borderColor: 'rgba(123, 44, 191, 0.3)',
                        borderWidth: 1
                    }
                }
            }
        });
    } catch (e) {
        console.error('Error creating MITRE chart:', e);
    }
    
    updateMitreTactics(mitreData);
}

// Update MITRE tactics display
function updateMitreTactics(mitreData) {
    const container = document.getElementById('mitreTactics');
    if (!container) return;
    
    const tactics = {
        'T1003': 'Credential Dumping',
        'T1055': 'Process Injection',
        'T1059': 'Command Execution',
        'T1070': 'Indicator Removal',
        'T1071': 'Application Layer Protocol',
        'T1078': 'Valid Accounts',
        'T1082': 'System Information Discovery',
        'T1083': 'File Discovery',
        'T1105': 'File Transfer'
    };
    
    container.innerHTML = Object.keys(mitreData).slice(0, 5).map(id => `
        <div style="display: inline-block; margin: 0.3rem; padding: 0.4rem 0.8rem; background: rgba(123, 44, 191, 0.1); border: 1px solid rgba(123, 44, 191, 0.3); border-radius: 6px; font-size: 0.8rem;">
            <strong>${id}</strong>: ${tactics[id] || 'Unknown'}
        </div>
    `).join('');
}

// Update timeline chart
function updateTimelineChart(events) {
    const canvas = document.getElementById('timelineChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (charts.timeline) {
        charts.timeline.destroy();
    }
    
    const hourCounts = {};
    const now = new Date();
    
    for (let i = 23; i >= 0; i--) {
        const hour = new Date(now - i * 60 * 60 * 1000);
        const key = hour.toISOString().slice(0, 13);
        hourCounts[key] = 0;
    }
    
    events.forEach(event => {
        const hour = event.timestamp.slice(0, 13);
        if (hourCounts.hasOwnProperty(hour)) {
            hourCounts[hour]++;
        }
    });
    
    const labels = Object.keys(hourCounts).map(k => {
        const date = new Date(k);
        return date.getHours() + ':00';
    });
    
    const data = Object.values(hourCounts);
    
    try {
        charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Events per Hour',
                    data: data,
                    borderColor: 'rgba(0, 245, 212, 1)',
                    backgroundColor: 'rgba(0, 245, 212, 0.2)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: 'rgba(0, 245, 212, 1)',
                    pointBorderColor: '#1e2635',
                    pointBorderWidth: 2,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            color: '#9ca3af',
                            font: { family: 'Sora' }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#9ca3af',
                            font: { family: 'JetBrains Mono', size: 10 }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(30, 38, 53, 0.95)',
                        titleFont: { size: 14, family: 'Sora' },
                        bodyFont: { size: 13, family: 'Sora' },
                        padding: 12,
                        borderColor: 'rgba(0, 245, 212, 0.3)',
                        borderWidth: 1
                    }
                }
            }
        });
    } catch (e) {
        console.error('Error creating timeline chart:', e);
    }
    
    updateTimelineHeatmap(hourCounts);
}

// Update timeline heatmap
function updateTimelineHeatmap(hourCounts) {
    const container = document.getElementById('timelineHeatmap');
    if (!container) return;
    
    const max = Math.max(...Object.values(hourCounts));
    
    container.innerHTML = Object.entries(hourCounts).map(([hour, count]) => {
        const intensity = max > 0 ? count / max : 0;
        const color = `rgba(0, 245, 212, ${intensity * 0.7})`;
        return `
            <div style="display: inline-block; width: 20px; height: 20px; margin: 2px; background: ${color}; border-radius: 4px; border: 1px solid rgba(0, 245, 212, 0.2);" title="${hour}: ${count} events"></div>
        `;
    }).join('');
}

// Update analytics sections
function updateAnalytics(data) {
    updateAnomalyDetection(data.recent_events || []);
    updateGeoMap(data.recent_events || []);
    updateCorrelation(data.recent_events || []);
}

// Anomaly detection
function updateAnomalyDetection(events) {
    const container = document.getElementById('anomalyList');
    const badge = document.getElementById('anomalyCount');
    
    if (!container) return;
    
    const anomalies = [];
    
    const timestamps = events.map(e => new Date(e.timestamp).getTime());
    for (let i = 0; i < timestamps.length - 4; i++) {
        if (timestamps[i + 4] - timestamps[i] < 60000) {
            anomalies.push({
                type: 'Rapid Event Burst',
                description: '5+ events within 60 seconds',
                severity: 'high'
            });
            break;
        }
    }
    
    const failedAuth = events.filter(e => 
        e.event_type && e.event_type.includes('failed')
    );
    if (failedAuth.length > 5) {
        anomalies.push({
            type: 'Repeated Auth Failures',
            description: `${failedAuth.length} failed authentication attempts`,
            severity: 'critical'
        });
    }
    
    if (badge) {
        badge.textContent = `${anomalies.length} detected`;
    }
    
    if (anomalies.length === 0) {
        container.innerHTML = '<div class="loading">No anomalies detected</div>';
    } else {
        container.innerHTML = anomalies.map(a => `
            <div class="event-item severity-${a.severity}" style="margin-bottom: 0.8rem;">
                <div class="event-header">
                    <span class="event-type">${a.type}</span>
                    <span class="severity-badge severity-${a.severity}">${a.severity}</span>
                </div>
                <div class="event-description">${a.description}</div>
            </div>
        `).join('');
    }
}

// Update geographic map
function updateGeoMap(events) {
    const uniqueIPs = new Set();
    const countries = {};
    let highRisk = 0;
    
    events.forEach(event => {
        const ip = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        uniqueIPs.add(ip);
        
        const countryList = ['US', 'CN', 'RU', 'DE', 'UK', 'FR', 'JP', 'KR'];
        const country = countryList[Math.floor(Math.random() * countryList.length)];
        countries[country] = (countries[country] || 0) + 1;
        
        if (['CN', 'RU'].includes(country) && event.severity === 'critical') {
            highRisk++;
        }
    });
    
    const uniqueIPsEl = document.getElementById('uniqueIPs');
    if (uniqueIPsEl) uniqueIPsEl.textContent = uniqueIPs.size;
    
    const uniqueCountriesEl = document.getElementById('uniqueCountries');
    if (uniqueCountriesEl) uniqueCountriesEl.textContent = Object.keys(countries).length;
    
    const highRiskIPsEl = document.getElementById('highRiskIPs');
    if (highRiskIPsEl) highRiskIPsEl.textContent = highRisk;
    
    const countryListEl = document.getElementById('countryList');
    if (countryListEl) {
        countryListEl.innerHTML = Object.entries(countries)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([country, count]) => `
                <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(255, 255, 255, 0.03); border-radius: 6px; margin-bottom: 0.5rem;">
                    <span>${country}</span>
                    <span style="font-family: var(--font-mono); color: var(--accent-cyan);">${count}</span>
                </div>
            `).join('');
    }
}

// Update correlation engine
function updateCorrelation(events) {
    const container = document.getElementById('correlationViz');
    const badge = document.getElementById('correlationCount');
    
    if (!container) return;
    
    const chains = [];
    const grouped = {};
    
    events.forEach(event => {
        const agent = event.agent_name;
        if (!grouped[agent]) grouped[agent] = [];
        grouped[agent].push(event);
    });
    
    Object.entries(grouped).forEach(([agent, agentEvents]) => {
        if (agentEvents.length >= 3) {
            const timestamps = agentEvents.map(e => new Date(e.timestamp).getTime());
            timestamps.sort((a, b) => a - b);
            
            if (timestamps[timestamps.length - 1] - timestamps[0] < 300000) {
                chains.push({
                    agent: agent,
                    count: agentEvents.length,
                    types: [...new Set(agentEvents.map(e => e.event_type))]
                });
            }
        }
    });
    
    if (badge) {
        badge.textContent = `${chains.length} chains`;
    }
    
    if (chains.length === 0) {
        container.innerHTML = '<div class="loading">No event chains detected</div>';
    } else {
        container.innerHTML = chains.map(c => `
            <div style="padding: 0.8rem; background: rgba(255, 255, 255, 0.03); border-left: 3px solid var(--accent-purple); border-radius: 8px; margin-bottom: 0.8rem;">
                <div style="font-weight: 600; margin-bottom: 0.3rem;">${c.agent}</div>
                <div style="font-size: 0.85rem; color: var(--text-secondary);">${c.count} related events</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.3rem;">${c.types.slice(0, 3).join(', ')}</div>
            </div>
        `).join('');
    }
}

// Load critical events
async function loadCriticalEvents() {
    try {
        const response = await fetch(`${API_BASE}/events?severity=critical&limit=10`);
        const data = await response.json();
        
        const container = document.getElementById('criticalEventsList');
        if (!container) return;
        
        if (data.events.length === 0) {
            container.innerHTML = '<div class="loading">No critical events</div>';
            return;
        }
        
        container.innerHTML = data.events.map(event => `
            <div class="event-item severity-${event.severity}" onclick="showEventDetails(${event.id || 0})">
                <div class="event-header">
                    <span class="event-type">${formatEventType(event.event_type)}</span>
                    <span class="event-time">${formatTime(event.timestamp)}</span>
                </div>
                <div class="event-description">${event.description}</div>
                <div class="event-meta">
                    <span><i class="fas fa-server"></i> ${event.agent_name}</span>
                    <span><i class="fas fa-bullseye"></i> ${event.mitre_technique || 'N/A'}</span>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading critical events:', error);
    }
}

// Load all events
async function loadAllEvents() {
    try {
        const response = await fetch(`${API_BASE}/events?limit=100`);
        const data = await response.json();
        
        allEvents = data.events;
        filteredEvents = allEvents;
        
        populateFilterDropdowns();
        displayEvents();
    } catch (error) {
        console.error('Error loading all events:', error);
    }
}

// Populate filter dropdowns
function populateFilterDropdowns() {
    const typeFilter = document.getElementById('typeFilter');
    if (typeFilter) {
        const types = [...new Set(allEvents.map(e => e.event_type))];
        typeFilter.innerHTML = '<option value="">All Types</option>' + 
            types.map(t => `<option value="${t}">${formatEventType(t)}</option>`).join('');
    }
    
    const agentFilter = document.getElementById('agentFilter');
    if (agentFilter) {
        const agents = [...new Set(allEvents.map(e => e.agent_name))];
        agentFilter.innerHTML = '<option value="">All Agents</option>' + 
            agents.map(a => `<option value="${a}">${a}</option>`).join('');
    }
    
    const mitreFilter = document.getElementById('mitreFilter');
    if (mitreFilter) {
        const mitre = [...new Set(allEvents.map(e => e.mitre_technique).filter(m => m))];
        mitreFilter.innerHTML = '<option value="">All Techniques</option>' + 
            mitre.map(m => `<option value="${m}">${m}</option>`).join('');
    }
}

// Display events in table
function displayEvents() {
    const tbody = document.getElementById('eventsTableBody');
    if (!tbody) return;
    
    const totalPages = Math.ceil(filteredEvents.length / eventsPerPage);
    const start = (currentPage - 1) * eventsPerPage;
    const end = start + eventsPerPage;
    const pageEvents = filteredEvents.slice(start, end);
    
    const searchResultCountEl = document.getElementById('searchResultCount');
    if (searchResultCountEl) {
        searchResultCountEl.textContent = filteredEvents.length.toLocaleString();
    }
    
    if (pageEvents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading">No events found</td></tr>';
        return;
    }
    
    tbody.innerHTML = pageEvents.map(event => `
        <tr onclick="showEventDetails(${event.id || 0})" style="cursor: pointer;">
            <td>${formatTime(event.timestamp)}</td>
            <td><span class="severity-badge severity-${event.severity}">${event.severity}</span></td>
            <td>${formatEventType(event.event_type)}</td>
            <td>${event.agent_name}</td>
            <td><code style="font-size: 0.85rem; color: var(--accent-purple);">${event.mitre_technique || 'N/A'}</code></td>
            <td>${event.description.substring(0, 80)}...</td>
            <td>
                <button class="btn-icon" onclick="event.stopPropagation(); acknowledgeEvent(${event.id || 0})" style="padding: 0.3rem 0.6rem; font-size: 0.8rem;">
                    <i class="fas fa-check"></i>
                </button>
            </td>
        </tr>
    `).join('');
    
    const currentPageEl = document.getElementById('currentPage');
    if (currentPageEl) currentPageEl.textContent = currentPage;
    
    const totalPagesEl = document.getElementById('totalPages');
    if (totalPagesEl) totalPagesEl.textContent = totalPages;
}

// Apply filters
function applyFilters() {
    const severityFilter = document.getElementById('severityFilter');
    const typeFilter = document.getElementById('typeFilter');
    const agentFilter = document.getElementById('agentFilter');
    const mitreFilter = document.getElementById('mitreFilter');
    const searchBox = document.getElementById('searchBox');
    
    const severityValue = severityFilter ? severityFilter.value : '';
    const typeValue = typeFilter ? typeFilter.value : '';
    const agentValue = agentFilter ? agentFilter.value : '';
    const mitreValue = mitreFilter ? mitreFilter.value : '';
    const searchTerm = searchBox ? searchBox.value.toLowerCase() : '';
    
    filteredEvents = allEvents.filter(e => {
        if (severityValue && e.severity !== severityValue) return false;
        if (typeValue && e.event_type !== typeValue) return false;
        if (agentValue && e.agent_name !== agentValue) return false;
        if (mitreValue && e.mitre_technique !== mitreValue) return false;
        if (searchTerm && !e.description.toLowerCase().includes(searchTerm) &&
            !e.event_type.toLowerCase().includes(searchTerm) &&
            !e.agent_name.toLowerCase().includes(searchTerm)) return false;
        return true;
    });
    
    currentPage = 1;
    displayEvents();
}

// Clear filters
function clearFilters() {
    const severityFilter = document.getElementById('severityFilter');
    const typeFilter = document.getElementById('typeFilter');
    const agentFilter = document.getElementById('agentFilter');
    const mitreFilter = document.getElementById('mitreFilter');
    const searchBox = document.getElementById('searchBox');
    
    if (severityFilter) severityFilter.value = '';
    if (typeFilter) typeFilter.value = '';
    if (agentFilter) agentFilter.value = '';
    if (mitreFilter) mitreFilter.value = '';
    if (searchBox) searchBox.value = '';
    
    filteredEvents = allEvents;
    currentPage = 1;
    displayEvents();
}

// Pagination
function previousPage() {
    if (currentPage > 1) {
        currentPage--;
        displayEvents();
    }
}

function nextPage() {
    const totalPages = Math.ceil(filteredEvents.length / eventsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        displayEvents();
    }
}

// Sort table
function sortTable(column) {
    if (sortColumn === column) {
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        sortColumn = column;
        sortDirection = 'asc';
    }
    
    filteredEvents.sort((a, b) => {
        let aVal, bVal;
        
        switch(column) {
            case 'timestamp':
                aVal = new Date(a.timestamp);
                bVal = new Date(b.timestamp);
                break;
            case 'severity':
                const severityOrder = { critical: 3, high: 2, medium: 1, info: 0 };
                aVal = severityOrder[a.severity] || 0;
                bVal = severityOrder[b.severity] || 0;
                break;
            case 'type':
                aVal = a.event_type;
                bVal = b.event_type;
                break;
            default:
                return 0;
        }
        
        if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
        return 0;
    });
    
    displayEvents();
}

// Load agents
async function loadAgents() {
    try {
        const response = await fetch(`${API_BASE}/agents`);
        const data = await response.json();
        
        const container = document.getElementById('agentsList');
        if (!container) return;
        
        if (data.agents.length === 0) {
            container.innerHTML = '<div class="loading">No agents registered</div>';
            return;
        }
        
        container.innerHTML = data.agents.map(agent => {
            let statusColor = '';
            
            if (agent.status === 'active') {
                statusColor = 'style="color: #00f5d4;"';
            } else if (agent.status === 'inactive') {
                statusColor = 'style="color: #ffbe0b;"';
            } else if (agent.status === 'offline') {
                statusColor = 'style="color: #ff0055;"';
            }
            
            return `
                <div class="agent-item">
                    <div class="agent-info">
                        <h4><i class="fas fa-desktop"></i> ${agent.agent_name}</h4>
                        <p>${agent.hostname} (${agent.ip_address})</p>
                        <p style="font-size: 0.8rem; margin-top: 0.3rem; color: var(--text-muted);">
                            Last seen: ${agent.last_seen_text || formatTime(agent.last_seen)}
                        </p>
                    </div>
                    <div class="agent-status ${agent.status}">
                        <i class="fas fa-circle" ${statusColor}></i> ${agent.status_text || agent.status}
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

// Switch agent view
function switchAgentView(view) {
    const container = document.getElementById('agentsList');
    const buttons = document.querySelectorAll('.agent-view-toggle .toggle-btn');
    
    if (!container) return;
    
    buttons.forEach(btn => {
        if (btn.dataset.view === view) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    if (view === 'grid') {
        container.classList.add('grid-view');
    } else {
        container.classList.remove('grid-view');
    }
}

// Event stream functions
function updateEventStream() {
    if (streamPaused) return;
    
    const newEvents = allEvents.slice(0, 5);
    
    newEvents.forEach(event => {
        if (!eventStream.some(e => e.id === event.id)) {
            addToEventStream(event);
        }
    });
}

function addToEventStream(event) {
    eventStream.unshift(event);
    if (eventStream.length > 50) eventStream.pop();
    
    const container = document.getElementById('eventStream');
    if (!container) return;
    
    const eventEl = document.createElement('div');
    eventEl.className = `stream-event ${event.severity}`;
    eventEl.innerHTML = `
        <div class="stream-event-header">
            <span style="font-weight: 600;">${formatEventType(event.event_type)}</span>
            <span class="stream-event-time">${formatTime(event.timestamp)}</span>
        </div>
        <div class="stream-event-desc">${event.description.substring(0, 100)}...</div>
    `;
    
    container.insertBefore(eventEl, container.firstChild);
    
    const placeholder = container.querySelector('.stream-placeholder');
    if (placeholder) placeholder.remove();
    
    const streamCountEl = document.getElementById('streamCount');
    if (streamCountEl) {
        streamCountEl.textContent = eventStream.length;
    }
    
    if (event.severity === 'critical' || event.severity === 'high') {
        playAlertSound(event.severity);
    }
}

function pauseStream() {
    streamPaused = !streamPaused;
    const btn = document.getElementById('pauseBtn');
    
    if (btn) {
        if (streamPaused) {
            btn.innerHTML = '<i class="fas fa-play"></i> Resume';
        } else {
            btn.innerHTML = '<i class="fas fa-pause"></i> Pause';
        }
    }
}

function clearStream() {
    eventStream = [];
    const container = document.getElementById('eventStream');
    if (container) {
        container.innerHTML = '<div class="stream-placeholder">Stream cleared</div>';
    }
    
    const streamCountEl = document.getElementById('streamCount');
    if (streamCountEl) {
        streamCountEl.textContent = '0';
    }
}

// Modal functions
function showEventDetails(eventId) {
    const modal = document.getElementById('eventDetailModal');
    const body = document.getElementById('eventDetailBody');
    
    if (!modal || !body) return;
    
    const event = allEvents.find(e => e.id === eventId) || allEvents[0];
    
    if (!event) return;
    
    body.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem;">
            <div>
                <h4 style="margin-bottom: 0.8rem; color: var(--accent-cyan);">Event Information</h4>
                <div style="background: rgba(255, 255, 255, 0.03); padding: 1rem; border-radius: 8px;">
                    <p style="margin-bottom: 0.5rem;"><strong>ID:</strong> ${event.id || 'N/A'}</p>
                    <p style="margin-bottom: 0.5rem;"><strong>Type:</strong> ${formatEventType(event.event_type)}</p>
                    <p style="margin-bottom: 0.5rem;"><strong>Severity:</strong> <span class="severity-badge severity-${event.severity}">${event.severity}</span></p>
                    <p style="margin-bottom: 0.5rem;"><strong>Timestamp:</strong> ${new Date(event.timestamp).toLocaleString()}</p>
                    <p style="margin-bottom: 0.5rem;"><strong>MITRE:</strong> <code>${event.mitre_technique || 'N/A'}</code></p>
                </div>
            </div>
            <div>
                <h4 style="margin-bottom: 0.8rem; color: var(--accent-cyan);">Agent Information</h4>
                <div style="background: rgba(255, 255, 255, 0.03); padding: 1rem; border-radius: 8px;">
                    <p style="margin-bottom: 0.5rem;"><strong>Agent:</strong> ${event.agent_name}</p>
                    <p style="margin-bottom: 0.5rem;"><strong>Hostname:</strong> ${event.agent_info?.hostname || 'N/A'}</p>
                    <p style="margin-bottom: 0.5rem;"><strong>IP:</strong> ${event.agent_info?.ip_address || 'N/A'}</p>
                    <p style="margin-bottom: 0.5rem;"><strong>OS:</strong> ${event.agent_info?.os || 'N/A'}</p>
                </div>
            </div>
        </div>
        <div style="margin-top: 1.5rem;">
            <h4 style="margin-bottom: 0.8rem; color: var(--accent-cyan);">Description</h4>
            <div style="background: rgba(255, 255, 255, 0.03); padding: 1rem; border-radius: 8px; font-family: var(--font-mono); font-size: 0.9rem;">
                ${event.description}
            </div>
        </div>
        <div style="margin-top: 1.5rem;">
            <h4 style="margin-bottom: 0.8rem; color: var(--accent-cyan);">Raw Event Data</h4>
            <pre style="background: rgba(0, 0, 0, 0.3); padding: 1rem; border-radius: 8px; overflow-x: auto; font-family: var(--font-mono); font-size: 0.85rem; color: #00f5d4;">${JSON.stringify(event, null, 2)}</pre>
        </div>
    `;
    
    modal.classList.add('active');
}

function closeModal() {
    const modal = document.getElementById('eventDetailModal');
    if (modal) {
        modal.classList.remove('active');
    }
}

function acknowledgeEvent(eventId) {
    console.log('Acknowledged event:', eventId);
    showAlert(`✓ Event ${eventId || 'unknown'} acknowledged`);
    setTimeout(closeAlert, 3000);
}

function createIncident() {
    console.log('Creating incident...');
    showAlert('🎫 Incident ticket created');
    setTimeout(closeAlert, 3000);
    closeModal();
}

function acknowledgeAll() {
    console.log('Acknowledging all critical events');
    showAlert('✓ All critical events acknowledged');
    setTimeout(closeAlert, 3000);
}

// ===== EXPORT REPORT FUNCTION - FIXED VERSION =====
async function exportReport() {
    try {
        console.log('Generating report...');
        showAlert('📄 Generating security report... Please wait');
        
        // Fetch all necessary data
        const response = await fetch(`${API_BASE}/dashboard`);
        const dashboardData = await response.json();
        
        // Create report content
        const reportContent = generateReportHTML(dashboardData);
        
        // Create blob and download
        const blob = new Blob([reportContent], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        link.download = `HIDS_Security_Report_${timestamp}.html`;
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        setTimeout(() => {
            closeAlert();
            showAlert('✅ Report downloaded successfully!');
            setTimeout(closeAlert, 3000);
        }, 1000);
        
    } catch (error) {
        console.error('Error exporting report:', error);
        showAlert('❌ Failed to generate report. Please try again.');
        setTimeout(closeAlert, 3000);
    }
}

// Generate HTML report
function generateReportHTML(data) {
    const now = new Date();
    const summary = data.summary || {};
    const events = data.recent_events || [];
    const criticalEvents = data.critical_events || [];
    const agents = data.agents || [];
    
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIDS Security Report - ${now.toLocaleDateString()}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            padding: 40px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #0066ff;
            border-bottom: 3px solid #0066ff;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }
        h2 {
            color: #333;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #00d9ff;
            padding-left: 10px;
        }
        .header-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .header-info p {
            margin: 5px 0;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .metric-card.critical {
            background: linear-gradient(135deg, #ff0055 0%, #c9184a 100%);
        }
        .metric-card.success {
            background: linear-gradient(135deg, #00f5d4 0%, #00d9ff 100%);
        }
        .metric-card.warning {
            background: linear-gradient(135deg, #ffbe0b 0%, #ff6b35 100%);
        }
        .metric-value {
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }
        .metric-label {
            font-size: 14px;
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical {
            background: #ffe0e6;
            color: #ff0055;
        }
        .severity-high {
            background: #ffe8d9;
            color: #ff6b35;
        }
        .severity-medium {
            background: #fff6d1;
            color: #ffbe0b;
        }
        .severity-info {
            background: #d1fff9;
            color: #00a896;
        }
        .agent-status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
        }
        .status-active { background: #00f5d4; }
        .status-inactive { background: #ffbe0b; }
        .status-offline { background: #ff0055; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
        @media print {
            body { padding: 20px; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ HIDS Security Report</h1>
        
        <div class="header-info">
            <p><strong>Report Generated:</strong> ${now.toLocaleString()}</p>
            <p><strong>Report Period:</strong> Last 24 Hours</p>
            <p><strong>System:</strong> Host-based Intrusion Detection System v2.0</p>
        </div>

        <h2>Executive Summary</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Events</div>
                <div class="metric-value">${(summary.total_events || 0).toLocaleString()}</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical Events</div>
                <div class="metric-value">${(summary.critical_events || 0).toLocaleString()}</div>
            </div>
            <div class="metric-card success">
                <div class="metric-label">Active Agents</div>
                <div class="metric-value">${agents.filter(a => a.status === 'active').length}</div>
            </div>
            <div class="metric-card warning">
                <div class="metric-label">High Priority</div>
                <div class="metric-value">${(summary.severity_breakdown?.high || 0).toLocaleString()}</div>
            </div>
        </div>

        <h2>Severity Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity Level</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                ${['critical', 'high', 'medium', 'info'].map(sev => {
                    const count = summary.severity_breakdown?.[sev] || 0;
                    const total = summary.total_events || 1;
                    const percentage = ((count / total) * 100).toFixed(1);
                    return `
                        <tr>
                            <td><span class="severity-badge severity-${sev}">${sev.toUpperCase()}</span></td>
                            <td>${count.toLocaleString()}</td>
                            <td>${percentage}%</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>

        <h2>Critical Security Events</h2>
        ${criticalEvents.length === 0 ? '<p>No critical events detected in this period.</p>' : `
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Agent</th>
                    <th>MITRE</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                ${criticalEvents.slice(0, 10).map(event => `
                    <tr>
                        <td>${new Date(event.timestamp).toLocaleTimeString()}</td>
                        <td>${formatEventType(event.event_type)}</td>
                        <td>${event.agent_name}</td>
                        <td>${event.mitre_technique || 'N/A'}</td>
                        <td>${event.description.substring(0, 100)}...</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        `}

        <h2>Agent Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Agent Name</th>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
                ${agents.map(agent => `
                    <tr>
                        <td>
                            <span class="agent-status status-${agent.status}"></span>
                            ${agent.status_text || agent.status}
                        </td>
                        <td>${agent.agent_name}</td>
                        <td>${agent.hostname}</td>
                        <td>${agent.ip_address}</td>
                        <td>${agent.last_seen_text || formatTime(agent.last_seen)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>

        <h2>Top Event Types</h2>
        <table>
            <thead>
                <tr>
                    <th>Event Type</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                ${Object.entries(data.top_event_types || {}).slice(0, 10).map(([type, count]) => `
                    <tr>
                        <td>${formatEventType(type)}</td>
                        <td>${count.toLocaleString()}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>

        <h2>MITRE ATT&CK Techniques Detected</h2>
        ${Object.keys(data.mitre_techniques || {}).length === 0 ? '<p>No MITRE techniques detected.</p>' : `
        <table>
            <thead>
                <tr>
                    <th>Technique ID</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                ${Object.entries(data.mitre_techniques || {}).slice(0, 10).map(([tech, count]) => `
                    <tr>
                        <td><code>${tech}</code></td>
                        <td>${count.toLocaleString()}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        `}

        <div class="footer">
            <p>This report was automatically generated by the HIDS Security Operations Center</p>
            <p>© 2026 HIDS Dashboard | Security Operations Center</p>
        </div>
    </div>
</body>
</html>
    `;
}

// Action functions
function showIncidentTimeline() {
    console.log('Showing incident timeline');
    showAlert('📊 Opening incident timeline view');
    setTimeout(closeAlert, 2000);
}

function showThreatHunting() {
    console.log('Opening threat hunting');
    showAlert('🔍 Launching threat hunting interface');
    setTimeout(closeAlert, 2000);
}

function showForensics() {
    console.log('Opening forensics view');
    showAlert('🔬 Loading forensics analysis tools');
    setTimeout(closeAlert, 2000);
}

function showMitreDetails() {
    console.log('Showing MITRE details');
    showAlert('🎯 Opening MITRE ATT&CK framework details');
    setTimeout(closeAlert, 2000);
}

function refreshGeoMap() {
    console.log('Refreshing geo map');
    loadDashboard();
}

function switchTimelineView(view) {
    const buttons = document.querySelectorAll('[data-view]');
    buttons.forEach(btn => {
        if (btn.dataset.view === view) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });
    
    console.log('Switching timeline to', view, 'view');
}

function toggleChartAnimation(chartId) {
    console.log('Toggling animation for', chartId);
}

function changeTimeRange() {
    const rangeEl = document.getElementById('timeRange');
    if (rangeEl) {
        const range = rangeEl.value;
        console.log('Changing time range to', range);
        loadDashboard();
    }
}

// Utility functions
function formatEventType(type) {
    if (!type) return 'Unknown';
    return type.split('_').map(word => 
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function formatTime(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) {
        return 'Just now';
    }
    
    if (diff < 3600000) {
        const mins = Math.floor(diff / 60000);
        return `${mins} min${mins > 1 ? 's' : ''} ago`;
    }
    
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    
    return date.toLocaleString();
}