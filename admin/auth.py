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
    """Get client IP address from request.
    Only trust X-Forwarded-For when the direct connection is from localhost (Apache proxy)."""
    remote_addr = request.environ.get('REMOTE_ADDR', '')
    forwarded_for = request.environ.get('HTTP_X_FORWARDED_FOR')
    
    # Only trust X-Forwarded-For if request comes from localhost (Apache reverse proxy)
    if forwarded_for and remote_addr in ('127.0.0.1', '::1', 'localhost'):
        return sanitize_ip(forwarded_for)
    
    return sanitize_ip(remote_addr)

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password against policy"""
    if len(password) < 12:
        return False, "パスワードは12文字以上必要です"
    
    if not re.search(r'[a-z]', password):
        return False, "小文字を含めてください"
    if not re.search(r'[A-Z]', password):
        return False, "大文字を含めてください"  
    if not re.search(r'[0-9]', password):
        return False, "数字を含めてください"
    
    return True, ""

def check_rate_limit(username, ip_address):
    """Check if user/IP has exceeded rate limit"""
    cutoff = f'-{LOCKOUT_MINUTES} minutes'
    
    with get_db() as conn:
        # Check user-based attempts
        user_attempts = conn.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE username = ? AND success = 0 AND created_at > datetime('now', 'utc', ?)
        """, (username, cutoff)).fetchone()[0]
        
        # Check IP-based attempts (higher threshold to prevent collateral damage)
        ip_attempts = conn.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ? AND success = 0 AND created_at > datetime('now', 'utc', ?)
        """, (ip_address, cutoff)).fetchone()[0]
        
        return user_attempts < MAX_ATTEMPTS and ip_attempts < MAX_ATTEMPTS * 3

def log_login_attempt(username, ip_address, success=False):
    """Log login attempt for rate limiting and audit"""
    with get_db() as conn:
        # Log attempt
        conn.execute("""
            INSERT INTO login_attempts (username, ip_address, success, created_at)
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

def audit_log(username, action, detail=None, target=None):
    """Add entry to audit log
    
    Args:
        username: Username performing the action
        action: Action name
        detail: dict or None - Details of the action
        target: Target of the action (optional)
    """
    ip_address = get_client_ip()
    
    with get_db() as conn:
        # Get user_id
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        user_id = user[0] if user else 0
        
        # Convert non-string detail to JSON
        if detail and not isinstance(detail, str):
            import json
            detail = json.dumps(detail, ensure_ascii=False)
        # Truncate detail to prevent log bloat
        if detail and len(detail) > 4096:
            detail = detail[:4093] + "..."
        
        conn.execute("""
            INSERT INTO audit_log (user_id, username, action, detail, target, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'utc'))
        """, (user_id, username, action, detail, target, ip_address))

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

# User management functions for UI

def get_all_users():
    """Get all users for admin interface"""
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT id, username, role, groups, created_at, updated_at
            FROM users 
            ORDER BY username
        """)
        return [dict(row) for row in cursor.fetchall()]

def get_user_by_id(user_id):
    """Get user by ID"""
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT id, username, role, groups, created_at, updated_at
            FROM users 
            WHERE id = ?
        """, (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def create_user(username, password, role, groups):
    """Create a new user"""
    import bcrypt
    import json
    
    # Validate inputs
    if not username or not password:
        return False, "ユーザー名とパスワードは必須です"
    
    # Validate username format
    import re
    if not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', username):
        return False, "ユーザー名は英数字、アンダースコア、ドット、ハイフンのみ使用可能です（最大64文字）"
    
    # Validate password policy
    if len(password) < 12:
        return False, "パスワードは12文字以上必要です"
    if not re.search(r'[a-z]', password):
        return False, "小文字を含めてください"
    if not re.search(r'[A-Z]', password):
        return False, "大文字を含めてください"
    if not re.search(r'[0-9]', password):
        return False, "数字を含めてください"
    
    # Validate role
    if role not in ['admin', 'editor', 'viewer']:
        return False, "ロールはadmin、editor、viewerのいずれかを選択してください"
    
    # Parse and validate groups
    try:
        if isinstance(groups, str):
            if groups.strip() == '':
                groups_list = []
            else:
                # Support comma-separated format
                if groups.strip().startswith('['):
                    groups_list = json.loads(groups)
                else:
                    groups_list = [g.strip() for g in groups.split(',') if g.strip()]
        else:
            groups_list = groups or []
    except (json.JSONDecodeError, ValueError):
        return False, "グループ形式が不正です"
    
    groups_json = json.dumps(groups_list)
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    
    with get_db() as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO users (username, password_hash, role, groups)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, role, groups_json))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            # Log creation (after commit so audit_log's separate connection can see the user)
            try:
                audit_log(username, 'user_create', {'user_id': user_id, 'role': role, 'groups': groups_list})
            except Exception:
                pass  # Don't fail user creation if audit logging fails
            
            return True, "ユーザーが作成されました"
            
        except sqlite3.IntegrityError:
            return False, "ユーザー名が既に存在します"

def update_user_password(user_id, new_password, admin_username):
    """Update user password"""
    import bcrypt
    
    # Validate password policy
    import re
    if len(new_password) < 12:
        return False, "パスワードは12文字以上必要です"
    if not re.search(r'[a-z]', new_password):
        return False, "小文字を含めてください"
    if not re.search(r'[A-Z]', new_password):
        return False, "大文字を含めてください"
    if not re.search(r'[0-9]', new_password):
        return False, "数字を含めてください"
    
    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12)).decode()
    
    with get_db() as conn:
        # Get target user info
        user_info = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_info:
            return False, "ユーザーが見つかりません"
        
        conn.execute("""
            UPDATE users 
            SET password_hash = ?, session_version = session_version + 1, updated_at = datetime('now', 'utc')
            WHERE id = ?
        """, (password_hash, user_id))
        target_username = user_info[0]
    
    # Log outside the db context to avoid nested lock
    audit_log(admin_username, 'user_password_change', {'target_user': target_username, 'user_id': user_id})
    
    return True, "パスワードが変更されました"

def update_user_role(user_id, new_role, admin_username):
    """Update user role"""
    if new_role not in ['admin', 'editor', 'viewer']:
        return False, "ロールはadmin、editor、viewerのいずれかを選択してください"
    
    with get_db() as conn:
        # Get current user info
        user_info = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_info:
            return False, "ユーザーが見つかりません"
        
        old_role = user_info[1]
        target_username = user_info[0]
        
        # Prevent admin from removing their own admin role (last admin protection)
        if target_username == admin_username and old_role == 'admin' and new_role != 'admin':
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
            if admin_count <= 1:
                return False, "最後のadminユーザーの権限を変更することはできません"
        
        conn.execute("""
            UPDATE users 
            SET role = ?, session_version = session_version + 1, updated_at = datetime('now', 'utc')
            WHERE id = ?
        """, (new_role, user_id))
    
    audit_log(admin_username, 'user_role_change', {
        'target_user': target_username, 
        'user_id': user_id,
        'old_role': old_role, 
        'new_role': new_role
    })
    
    return True, "ロールが変更されました"

def update_user_groups(user_id, new_groups, admin_username):
    """Update user groups"""
    import json
    
    try:
        if isinstance(new_groups, str):
            if new_groups.strip() == '':
                groups_list = []
            else:
                # Support comma-separated format
                if new_groups.strip().startswith('['):
                    groups_list = json.loads(new_groups)
                else:
                    groups_list = [g.strip() for g in new_groups.split(',') if g.strip()]
        else:
            groups_list = new_groups or []
    except (json.JSONDecodeError, ValueError):
        return False, "グループ形式が不正です"
    
    groups_json = json.dumps(groups_list)
    
    with get_db() as conn:
        # Get target user info
        user_info = conn.execute("SELECT username, groups FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_info:
            return False, "ユーザーが見つかりません"
        
        old_groups = user_info[1]
        
        conn.execute("""
            UPDATE users 
            SET groups = ?, updated_at = datetime('now', 'utc')
            WHERE id = ?
        """, (groups_json, user_id))
        target_username = user_info[0]
    
    audit_log(admin_username, 'user_groups_change', {
        'target_user': target_username,
        'user_id': user_id,
        'old_groups': old_groups,
        'new_groups': groups_json
    })
    
    return True, "グループが変更されました"

def delete_user(user_id, admin_username):
    """Delete user (admin only)"""
    with get_db() as conn:
        # Get target user info
        user_info = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_info:
            return False, "ユーザーが見つかりません"
        
        target_username = user_info[0]
        target_role = user_info[1]
        
        # Prevent admin from deleting themselves
        if target_username == admin_username:
            return False, "自分自身を削除することはできません"
        
        # Prevent deleting last admin
        if target_role == 'admin':
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
            if admin_count <= 1:
                return False, "最後のadminユーザーを削除することはできません"
        
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    audit_log(admin_username, 'user_delete', {
        'target_user': target_username,
        'user_id': user_id,
        'role': target_role
    })
    
    return True, "ユーザーが削除されました"

def get_audit_logs(limit=50, offset=0, username_filter=None, action_filter=None):
    """Get audit logs with pagination and filters"""
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        
        where_conditions = []
        params = []
        
        if username_filter:
            where_conditions.append("username LIKE ?")
            params.append(f"%{username_filter}%")
        
        if action_filter:
            where_conditions.append("action = ?")
            params.append(action_filter)
        
        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM audit_log {where_clause}"
        total = conn.execute(count_query, params).fetchone()[0]
        
        # Get logs
        logs_query = f"""
            SELECT id, username, action, target, detail, ip_address, created_at
            FROM audit_log {where_clause}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        
        cursor = conn.execute(logs_query, params)
        logs = [dict(row) for row in cursor.fetchall()]
        
        return {
            'logs': logs,
            'total': total,
            'limit': limit,
            'offset': offset
        }

def get_audit_actions():
    """Get distinct action types for filter dropdown"""
    with get_db() as conn:
        cursor = conn.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")
        return [row[0] for row in cursor.fetchall()]