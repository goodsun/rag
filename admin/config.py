"""Centralized configuration for ragMyAdmin"""
import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

DB_DSN = os.environ.get("DB_DSN", "")
if not DB_DSN:
    raise EnvironmentError(
        "DB_DSN が設定されていません。.env を確認してください。\n"
        "例: DB_DSN=host=localhost dbname=mydb user=myuser password=mypassword\n"
        "参考: .env.sample"
    )
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/embed")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")
SECRET_KEY_FILE = os.path.expanduser("~/.config/staff-auth/secret_key")
