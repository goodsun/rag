#!/usr/bin/env python3
"""
academic_rag/ingest.py
論文・文書ファイルをChromaDBに取り込む

対応フォーマット: PDF, Word (.docx), テキスト (.txt, .md)

使い方:
    python ingest.py --file path/to/paper.pdf
    python ingest.py --dir path/to/folder/
"""

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

# --- 依存ライブラリ ---
# pip install chromadb fastembed pdfminer.six python-docx

try:
    import chromadb
    from fastembed import TextEmbedding
    from pdfminer.high_level import extract_text as pdf_extract
    from docx import Document as DocxDocument
except ImportError as e:
    print(f"[ERROR] 依存ライブラリが不足: {e}")
    print("pip install chromadb fastembed pdfminer.six python-docx")
    exit(1)

# --- 設定 ---
BASE_DIR = Path(__file__).parent
CHROMA_DIR = BASE_DIR / "chroma_db"
PROCESSED_DIR = BASE_DIR.parent / "documents" / "processed"
ERROR_DIR = BASE_DIR.parent / "documents" / "error"
HASH_FILE = BASE_DIR / "ingested_hashes.json"

CHUNK_SIZE = 500       # 文字数
CHUNK_OVERLAP = 50     # オーバーラップ
COLLECTION_NAME = "academic_docs"
EMBED_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def load_hashes() -> dict:
    if HASH_FILE.exists():
        return json.loads(HASH_FILE.read_text())
    return {}


def save_hashes(hashes: dict):
    HASH_FILE.write_text(json.dumps(hashes, ensure_ascii=False, indent=2))


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return pdf_extract(str(path)) or ""
    elif suffix == ".docx":
        doc = DocxDocument(str(path))
        return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
    elif suffix in (".txt", ".md"):
        return path.read_text(encoding="utf-8", errors="ignore")
    else:
        raise ValueError(f"非対応フォーマット: {suffix}")


def chunk_text(text: str, filename: str) -> list[dict]:
    """テキストをチャンクに分割し、メタデータを付与する"""
    chunks = []
    start = 0
    idx = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        chunk = text[start:end].strip()
        if chunk:
            chunks.append({
                "text": f"【{filename}】\n{chunk}",
                "metadata": {
                    "filename": filename,
                    "chunk_index": idx,
                    "ingested_at": datetime.now().isoformat(),
                }
            })
            idx += 1
        start = end - CHUNK_OVERLAP
    return chunks


def ingest_file(path: Path, collection, embedder, hashes: dict) -> bool:
    """1ファイルを取り込む。成功したらTrueを返す"""
    h = file_hash(path)
    if h in hashes:
        print(f"[SKIP] 取り込み済み: {path.name}")
        return True

    print(f"[INFO] 取り込み開始: {path.name}")
    try:
        text = extract_text(path)
        if not text.strip():
            print(f"[WARN] テキストが空: {path.name}")
            return False

        chunks = chunk_text(text, path.name)
        print(f"[INFO] チャンク数: {len(chunks)}")

        # Embedding 生成
        texts = [c["text"] for c in chunks]
        embeddings = list(embedder.embed(texts))

        # ChromaDB に格納
        collection.add(
            ids=[f"{h}_{i}" for i in range(len(chunks))],
            embeddings=[e.tolist() for e in embeddings],
            documents=texts,
            metadatas=[c["metadata"] for c in chunks],
        )

        hashes[h] = {"filename": path.name, "ingested_at": datetime.now().isoformat()}
        print(f"[OK] 取り込み完了: {path.name} ({len(chunks)} チャンク)")
        return True

    except Exception as e:
        print(f"[ERROR] 取り込み失敗: {path.name} — {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="学術文書をRAGに取り込む")
    parser.add_argument("--file", help="取り込むファイルパス")
    parser.add_argument("--dir", help="取り込むフォルダパス")
    parser.add_argument("--move", action="store_true", help="成功時にprocessed/へ移動")
    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        return

    # ChromaDB 初期化
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_or_create_collection(COLLECTION_NAME)

    # Embedder 初期化
    print("[INFO] Embeddingモデルを読み込み中...")
    embedder = TextEmbedding(EMBED_MODEL)

    hashes = load_hashes()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    ERROR_DIR.mkdir(parents=True, exist_ok=True)

    targets = []
    if args.file:
        targets = [Path(args.file)]
    elif args.dir:
        targets = [p for p in Path(args.dir).iterdir()
                   if p.suffix.lower() in (".pdf", ".docx", ".txt", ".md")]

    print(f"[INFO] 対象ファイル数: {len(targets)}")
    success, fail = 0, 0

    for path in targets:
        ok = ingest_file(path, collection, embedder, hashes)
        if ok:
            success += 1
            if args.move:
                shutil.move(str(path), str(PROCESSED_DIR / path.name))
        else:
            fail += 1
            if args.move:
                shutil.move(str(path), str(ERROR_DIR / path.name))

    save_hashes(hashes)
    print(f"\n[DONE] 成功: {success} / 失敗: {fail}")
    print(f"[INFO] コレクション件数: {collection.count()} チャンク")


if __name__ == "__main__":
    main()
