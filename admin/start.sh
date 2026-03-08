#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export APP_ROOT="${APP_ROOT:-/ragmyadmin}"
export SECRET_KEY="$(cat ~/.config/ragmyadmin/secret_key 2>/dev/null)"
cd "$SCRIPT_DIR"
exec /opt/homebrew/bin/python3 app.py
