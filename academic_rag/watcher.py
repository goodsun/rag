#!/usr/bin/env python3
"""
academic_rag/watcher.py
documents/inbox/ を監視し、新ファイルを自動でインジェストする

使い方:
    python watcher.py

依存:
    pip install watchdog
"""

import subprocess
import sys
import time
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("[ERROR] watchdog が必要: pip install watchdog")
    sys.exit(1)

INBOX_DIR = Path(__file__).parent.parent / "documents" / "inbox"
SUPPORTED = {".pdf", ".docx", ".txt", ".md"}


class InboxHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() not in SUPPORTED:
            return

        print(f"[WATCH] 新ファイル検出: {path.name}")
        # 書き込み完了を待つ
        time.sleep(1)

        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "ingest.py"),
             "--file", str(path), "--move"],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"[ERROR] {result.stderr}")


def main():
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[WATCH] 監視開始: {INBOX_DIR}")
    print("[WATCH] Ctrl+C で停止")

    observer = Observer()
    observer.schedule(InboxHandler(), str(INBOX_DIR), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
