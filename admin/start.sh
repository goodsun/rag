#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export APP_ROOT="${APP_ROOT:-/ragmyadmin}"
cd "$SCRIPT_DIR"
exec python3 app.py
