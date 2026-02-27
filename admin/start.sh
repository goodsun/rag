#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export HOME="${HOME:-/Users/teddy}"
export APP_ROOT=/ragmyadmin
cd "$SCRIPT_DIR"
exec /opt/homebrew/bin/python3 app.py
