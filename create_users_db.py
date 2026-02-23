#!/usr/bin/env python3
"""Initialize users.db with schema for ragMyAdmin Permission System"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def create_schema():
    """Create the users database schema according to design v4"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            groups TEXT NOT NULL DEFAULT '[]',
            session_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        )
    """)
    
    # Login attempts table (brute force protection)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            attempted_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        )
    """)
    
    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        )
    """)
    
    conn.commit()
    conn.close()
    
    # Set secure file permissions (600 - owner read/write only)
    os.chmod(DB_PATH, 0o600)
    
    print(f"Database created at: {DB_PATH}")
    print("Schema initialized successfully")

if __name__ == "__main__":
    create_schema()