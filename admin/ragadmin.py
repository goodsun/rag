#!/usr/bin/env python3
"""ragMyAdmin CLI Tool - User Management for Permission System"""
import os
import sys
import sqlite3
import bcrypt
import json
import re
import argparse
import getpass
from datetime import datetime, timedelta
import ipaddress

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "users.db")

# Password policy
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_MIXED = True

def get_db():
    """Get database connection"""
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        print("Run create_users_db.py first")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password against policy"""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"パスワードは{PASSWORD_MIN_LENGTH}文字以上必要です"
    
    if PASSWORD_REQUIRE_MIXED:
        if not re.search(r'[a-z]', password):
            return False, "小文字を含めてください"
        if not re.search(r'[A-Z]', password):
            return False, "大文字を含めてください"
        if not re.search(r'[0-9]', password):
            return False, "数字を含めてください"
    
    return True, ""

def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format"""
    if not re.match(r'^[a-zA-Z0-9_.-]{1,64}$', username):
        return False, "ユーザー名は英数字、アンダースコア、ドット、ハイフンのみ使用可能です（最大64文字）"
    return True, ""

def validate_groups(groups_json: str) -> tuple[bool, str]:
    """Validate groups JSON array"""
    try:
        groups = json.loads(groups_json)
        if not isinstance(groups, list):
            return False, "グループは配列形式で指定してください"
        
        if len(groups) > 10:
            return False, "グループは最大10個まで指定可能です"
        
        for group in groups:
            if not isinstance(group, str):
                return False, "グループ名は文字列で指定してください"
            if not re.match(r'^[a-z0-9_-]{1,32}$', group):
                return False, f"グループ名 '{group}' が無効です。小文字英数字、アンダースコア、ハイフンのみ使用可能（最大32文字）"
        
        if len(groups_json.encode()) > 512:
            return False, "グループ情報は最大512バイトまでです"
        
        return True, ""
    except json.JSONDecodeError:
        return False, "グループ情報が正しいJSON形式ではありません"

def hash_password(password: str) -> str:
    """Hash password with bcrypt (cost factor 12)"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def audit_log(conn, user_id: int, username: str, action: str, target: str = None, detail: dict = None, ip_address: str = 'localhost'):
    """Add audit log entry"""
    conn.execute("""
        INSERT INTO audit_log (user_id, username, action, target, detail, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, username, action, target, json.dumps(detail) if detail else None, ip_address))

def invalidate_sessions(conn, username: str):
    """Invalidate all sessions for a user by incrementing session_version"""
    conn.execute("""
        UPDATE users SET session_version = session_version + 1 
        WHERE username = ?
    """, (username,))

def cmd_useradd(args):
    """Add new user"""
    username = args.username
    
    # Validate username
    valid, msg = validate_username(username)
    if not valid:
        print(f"Error: {msg}")
        return
    
    # Check if user already exists
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            print(f"Error: User '{username}' already exists")
            return
    
    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Error: Passwords do not match")
            return
    
    # Validate password
    valid, msg = validate_password(password)
    if not valid:
        print(f"Error: {msg}")
        return
    
    # Determine role
    role = 'admin' if args.admin else 'viewer'
    
    # Admin creation restriction
    if role == 'admin':
        print("Creating admin user. Admin users can only be created via CLI.")
    
    # Hash password
    password_hash = hash_password(password)
    
    # Create user
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO users (username, password_hash, role, groups)
            VALUES (?, ?, ?, '[]')
        """, (username, password_hash, role))
        user_id = cursor.lastrowid
        
        # Log user creation
        audit_log(conn, 0, 'system', 'create_user', username, {
            'created_user_id': user_id,
            'role': role,
            'created_by': 'cli'
        })
    
    print(f"User '{username}' created successfully with role '{role}'")

def cmd_passwd(args):
    """Change user password"""
    username = args.username
    
    # Check if user exists
    with get_db() as conn:
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            print(f"Error: User '{username}' not found")
            return
        user_id = user[0]
    
    # Get new password
    if args.password:
        new_password = args.password
    else:
        new_password = getpass.getpass("New password: ")
        password_confirm = getpass.getpass("Confirm new password: ")
        if new_password != password_confirm:
            print("Error: Passwords do not match")
            return
    
    # Validate password
    valid, msg = validate_password(new_password)
    if not valid:
        print(f"Error: {msg}")
        return
    
    # Hash password
    password_hash = hash_password(new_password)
    
    # Update password and invalidate sessions
    with get_db() as conn:
        conn.execute("""
            UPDATE users SET password_hash = ?, updated_at = datetime('now', 'utc')
            WHERE username = ?
        """, (password_hash, username))
        
        invalidate_sessions(conn, username)
        
        # Log password change
        audit_log(conn, user_id, username, 'change_password', username, {
            'changed_by': 'cli'
        })
    
    print(f"Password changed for user '{username}'")

def cmd_roles(args):
    """Manage user roles and groups"""
    username = args.username
    
    # Check if user exists
    with get_db() as conn:
        user = conn.execute("""
            SELECT id, role, groups FROM users WHERE username = ?
        """, (username,)).fetchone()
        if not user:
            print(f"Error: User '{username}' not found")
            return
        user_id, current_role, current_groups = user
    
    # Handle role change
    if args.role:
        new_role = args.role
        if new_role not in ['admin', 'editor', 'viewer']:
            print("Error: Role must be one of: admin, editor, viewer")
            return
        
        # Prevent self-demotion from admin (simplified - assumes CLI user is admin)
        if current_role == 'admin' and new_role != 'admin':
            # Count remaining admins
            with get_db() as conn:
                admin_count = conn.execute("""
                    SELECT COUNT(*) FROM users WHERE role = 'admin'
                """).fetchone()[0]
                if admin_count <= 1:
                    print("Error: Cannot remove last admin user")
                    return
        
        with get_db() as conn:
            conn.execute("""
                UPDATE users SET role = ?, updated_at = datetime('now', 'utc')
                WHERE username = ?
            """, (new_role, username))
            
            invalidate_sessions(conn, username)
            
            # Log role change
            audit_log(conn, user_id, username, 'change_role', username, {
                'old_role': current_role,
                'new_role': new_role,
                'changed_by': 'cli'
            })
        
        print(f"Role changed for user '{username}': {current_role} -> {new_role}")
        current_role = new_role
    
    # Handle groups change
    if args.groups is not None:
        groups_str = args.groups if args.groups else '[]'
        
        # Validate groups
        valid, msg = validate_groups(groups_str)
        if not valid:
            print(f"Error: {msg}")
            return
        
        with get_db() as conn:
            conn.execute("""
                UPDATE users SET groups = ?, updated_at = datetime('now', 'utc')
                WHERE username = ?
            """, (groups_str, username))
            
            invalidate_sessions(conn, username)
            
            # Log groups change
            audit_log(conn, user_id, username, 'change_group', username, {
                'old_groups': current_groups,
                'new_groups': groups_str,
                'changed_by': 'cli'
            })
        
        print(f"Groups updated for user '{username}': {groups_str}")
        current_groups = groups_str
    
    # Show current status
    if not args.role and args.groups is None:
        groups_list = json.loads(current_groups) if current_groups else []
        print(f"User: {username}")
        print(f"Role: {current_role}")
        print(f"Groups: {groups_list}")

def cmd_unlock(args):
    """Unlock user from brute force protection"""
    username = args.username
    
    # Clear failed login attempts
    with get_db() as conn:
        deleted = conn.execute("""
            DELETE FROM login_attempts 
            WHERE username = ? AND success = 0
        """, (username,)).rowcount
    
    print(f"Cleared {deleted} failed login attempts for user '{username}'")

def cmd_audit(args):
    """Show or purge audit log"""
    if args.purge:
        if not args.older_than:
            print("Error: --older-than required for purge operation")
            return
        
        # Parse older_than (e.g., "90d", "30d")
        match = re.match(r'^(\d+)d$', args.older_than)
        if not match:
            print("Error: --older-than format should be like '90d'")
            return
        
        days = int(match.group(1))
        
        with get_db() as conn:
            # Count records to purge
            count = conn.execute("""
                SELECT COUNT(*) FROM audit_log 
                WHERE created_at < datetime('now', 'utc', '-{} days')
            """.format(days)).fetchone()[0]
            
            if count == 0:
                print("No records to purge")
                return
            
            # Confirm purge
            confirm = input(f"This will delete {count} audit log records older than {days} days. Continue? (y/N): ")
            if confirm.lower() != 'y':
                print("Cancelled")
                return
            
            # Record purge operation first
            conn.execute("""
                INSERT INTO audit_log (user_id, username, action, detail, ip_address)
                VALUES (0, 'cli', 'purge_audit_log', ?, 'localhost')
            """, (json.dumps({"older_than_days": days, "records_purged": count}),))
            
            # Delete old records (except purge logs themselves)
            conn.execute("""
                DELETE FROM audit_log 
                WHERE created_at < datetime('now', 'utc', '-{} days') 
                AND action != 'purge_audit_log'
            """.format(days))
            
            conn.commit()
        
        print(f"Purged {count} audit log records")
    
    else:
        # Show recent audit log
        limit = args.limit if hasattr(args, 'limit') and args.limit else 50
        
        with get_db() as conn:
            logs = conn.execute("""
                SELECT created_at, username, action, target, detail, ip_address
                FROM audit_log 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (limit,)).fetchall()
        
        if not logs:
            print("No audit log entries found")
            return
        
        print(f"Recent audit log entries (showing {len(logs)}):")
        print("-" * 80)
        for log in logs:
            created_at, username, action, target, detail, ip_address = log
            detail_str = ""
            if detail:
                try:
                    detail_obj = json.loads(detail)
                    detail_str = f" | {json.dumps(detail_obj, separators=(',', ':'))}"
                except:
                    detail_str = f" | {detail}"
            target_str = f" -> {target}" if target else ""
            print(f"{created_at} | {username:15} | {action:20} | {ip_address:15}{target_str}{detail_str}")

def main():
    parser = argparse.ArgumentParser(description='ragMyAdmin User Management CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # useradd command
    parser_useradd = subparsers.add_parser('useradd', help='Add new user')
    parser_useradd.add_argument('username', help='Username')
    parser_useradd.add_argument('--admin', action='store_true', help='Create admin user')
    parser_useradd.add_argument('--password', help='Password (will prompt if not specified)')
    
    # passwd command
    parser_passwd = subparsers.add_parser('passwd', help='Change user password')
    parser_passwd.add_argument('username', help='Username')
    parser_passwd.add_argument('--password', help='New password (will prompt if not specified)')
    
    # roles command
    parser_roles = subparsers.add_parser('roles', help='Manage user roles and groups')
    parser_roles.add_argument('username', help='Username')
    parser_roles.add_argument('--role', choices=['admin', 'editor', 'viewer'], help='Set user role')
    parser_roles.add_argument('--groups', help='Set user groups (JSON array, e.g., \'["devteam","rag"]\')')
    
    # unlock command
    parser_unlock = subparsers.add_parser('unlock', help='Unlock user from brute force protection')
    parser_unlock.add_argument('username', help='Username')
    
    # audit command
    parser_audit = subparsers.add_parser('audit', help='Show or manage audit log')
    parser_audit.add_argument('--purge', action='store_true', help='Purge old audit log entries')
    parser_audit.add_argument('--older-than', help='Delete entries older than (e.g., "90d")')
    parser_audit.add_argument('--limit', type=int, default=50, help='Number of entries to show (default: 50)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Route to command handlers
    if args.command == 'useradd':
        cmd_useradd(args)
    elif args.command == 'passwd':
        cmd_passwd(args)
    elif args.command == 'roles':
        cmd_roles(args)
    elif args.command == 'unlock':
        cmd_unlock(args)
    elif args.command == 'audit':
        cmd_audit(args)

if __name__ == '__main__':
    main()