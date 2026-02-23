#!/usr/bin/env python3
"""Authentication module for ragMyAdmin"""
import os
import sqlite3
import bcrypt
import json
import ipaddress
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import request, session, redirect, url_for, abort

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "users.db")

# Rate limiting configuration
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def get_db():
    """Get database connection"""
    return sqlite3.connect(DB_PATH)

def sanitize_ip(raw_ip):
    """Extract safe IP address from X-Forwarded-For or remote address"""
    if not raw_ip:
        return 'unknown'
    
    try:
        # Get first IP from comma-separated list (proxy chain)
        ip_str = raw_ip.split(',')[0].strip()
        ipaddress.ip_address(ip_str)  # Validate
        return ip_str
    except (ValueError, AttributeError):
        return 'invalid'

def get_client_ip():
    """Get client IP address from request"""
    return sanitize_ip(request.environ.get('HTTP_X_FORWARDED_FOR') or 
                      request.environ.get('REMOTE_ADDR'))

def check_rate_limit(username, ip_address):
    """Check if user/IP has exceeded rate limit"""
    cutoff = f'-{LOCKOUT_MINUTES} minutes'
    
    with get_db() as conn:
        # Check user-based attempts
        user_attempts = conn.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE username = ? AND success = 0 AND attempted_at > datetime('now', 'utc', ?)
        """, (username, cutoff)).fetchone()[0]
        
        # Check IP-based attempts (higher threshold to prevent collateral damage)
        ip_attempts = conn.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ? AND success = 0 AND attempted_at > datetime('now', 'utc', ?)
        """, (ip_address, cutoff)).fetchone()[0]
        
        return user_attempts < MAX_ATTEMPTS and ip_attempts < MAX_ATTEMPTS * 3

def log_login_attempt(username, ip_address, success=False):
    """Log login attempt for rate limiting and audit"""
    with get_db() as conn:
        # Log attempt
        conn.execute("""
            INSERT INTO login_attempts (username, ip_address, success, attempted_at)
            VALUES (?, ?, ?, datetime('now', 'utc'))
        """, (username, ip_address, 1 if success else 0))
        
        # Get user_id for audit log
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        user_id = user[0] if user else 0
        
        # Add audit log
        action = 'login' if success else 'login_failed'
        conn.execute("""
            INSERT INTO audit_log (user_id, username, action, ip_address, created_at)
            VALUES (?, ?, ?, ?, datetime('now', 'utc'))
        """, (user_id, username, action, ip_address))
        
        if success:
            # Clear failed attempts for this user on successful login
            conn.execute("""
                DELETE FROM login_attempts 
                WHERE username = ? AND success = 0
            """, (username,))

def verify_password(username, password):
    """Verify username and password"""
    with get_db() as conn:
        user = conn.execute("""
            SELECT id, password_hash, role, groups, session_version
            FROM users WHERE username = ?
        """, (username,)).fetchone()
        
        if not user:
            return None
        
        user_id, password_hash, role, groups, session_version = user
        
        if bcrypt.checkpw(password.encode(), password_hash.encode()):
            return {
                'id': user_id,
                'username': username,
                'role': role,
                'groups': groups,
                'session_version': session_version
            }
        
        return None

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            # For API endpoints, return JSON error instead of redirect
            if request.path.startswith('/api/'):
                from flask import jsonify
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('login'))
        
        # Check session version (security event invalidation)
        if 'session_version' in session:
            with get_db() as conn:
                current_version = conn.execute("""
                    SELECT session_version FROM users WHERE username = ?
                """, (session['username'],)).fetchone()
                
                if not current_version or current_version[0] != session['session_version']:
                    session.clear()
                    if request.path.startswith('/api/'):
                        from flask import jsonify
                        return jsonify({"error": "Session expired"}), 401
                    return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_role(*allowed_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Phase 2 authorization system is now complete
PHASE2_COMPLETE = True

def phase1_policy():
    """Phase 1 security policy - admin only for modifications"""
    if not PHASE2_COMPLETE and session.get('role') != 'admin':
        if request.method in ('POST', 'PUT', 'DELETE'):
            # Allow read operations even if they use POST
            read_endpoints = ['/api/search']
            if not any(request.path.startswith(endpoint) for endpoint in read_endpoints):
                abort(403)

def get_user_info(username):
    """Get user information"""
    with get_db() as conn:
        user = conn.execute("""
            SELECT id, username, role, groups, created_at, updated_at
            FROM users WHERE username = ?
        """, (username,)).fetchone()
        
        if not user:
            return None
        
        return {
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'groups': json.loads(user[3]) if user[3] else [],
            'created_at': user[4],
            'updated_at': user[5]
        }

def audit_log(username, action, detail=None, chunk_id=None):
    """Add entry to audit log"""
    ip_address = get_client_ip()
    
    with get_db() as conn:
        # Get user_id
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        user_id = user[0] if user else 0
        
        # Truncate detail to prevent log bloat
        if detail and len(detail) > 4096:
            detail = detail[:4093] + "..."
        
        conn.execute("""
            INSERT INTO audit_log (user_id, username, action, detail, chunk_id, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'utc'))
        """, (user_id, username, action, detail, chunk_id, ip_address))

def check_chunk_permission(chunk_meta, username, user_role, user_groups, required='r'):
    """Check if user has permission to access chunk
    
    Args:
        chunk_meta: Chunk metadata dict
        username: Username making the request
        user_role: User's role ('admin', 'editor', 'viewer')
        user_groups: List of user's groups
        required: Required permission ('r' for read, 'w' for write, 'x' for execute)
    
    Returns:
        bool: True if permission granted
    """
    # Admin has full access to everything
    if user_role == 'admin':
        return True
    
    # Get chunk permission info
    owner = chunk_meta.get('__owner', 'system')
    permission = chunk_meta.get('__permission', '744')
    visibility = chunk_meta.get('__visibility', 'public')
    chunk_groups_str = chunk_meta.get('__groups', '[]')
    
    # Parse chunk groups
    try:
        chunk_groups = json.loads(chunk_groups_str) if chunk_groups_str else []
    except (json.JSONDecodeError, TypeError):
        chunk_groups = []
    
    # Validate permission format (3-digit unix style)
    if not re.match(r'^[0-7]{3}$', permission):
        permission = '744'  # Default fallback
    
    # Check visibility for read access
    if required == 'r' and visibility == 'private':
        # Private chunks only accessible by owner or group members
        if username != owner and not any(g in user_groups for g in chunk_groups):
            return False
    
    # Determine permission level based on ownership/group membership
    if username == owner:
        level = int(permission[0])  # owner bits
    elif any(g in user_groups for g in chunk_groups):
        level = int(permission[1])  # group bits  
    else:
        level = int(permission[2])  # other bits
    
    # Check required permission bit
    required_bit = {'r': 4, 'w': 2, 'x': 1}[required]
    return bool(level & required_bit)

def check_collection_permission(col_name, username, user_role, required='r'):
    """Check if user has permission to access collection
    
    Args:
        col_name: Collection name
        username: Username making the request  
        user_role: User's role ('admin', 'editor', 'viewer')
        required: Required permission ('r' for read, 'w' for write, 'x' for execute)
    
    Returns:
        bool: True if permission granted
    """
    # Role-based collection access
    if user_role == 'admin':
        return True
    elif user_role == 'editor':
        return required in ['r', 'w']
    elif user_role == 'viewer':
        return required == 'r'
    
    return False