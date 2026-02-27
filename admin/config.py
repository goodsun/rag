"""Centralized configuration for ragMyAdmin"""
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DB_DSN = os.environ.get("DB_DSN", "")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/embed")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")
SECRET_KEY_FILE = os.path.expanduser("~/.config/staff-auth/secret_key")
