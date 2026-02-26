"""Centralized configuration for ragMyAdmin"""
import os

DB_DSN = os.environ.get("DB_DSN", "dbname=bonsoleil user=teddy")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/embed")
EMBEDDING_MODEL = "nomic-embed-text"
SECRET_KEY_FILE = os.path.expanduser("~/.config/staff-auth/secret_key")
