#!/usr/bin/env python3
"""チャンクをpgvector(PostgreSQL)に格納する（ollama nomic-embed-text使用）

Usage:
    python embed.py                          # デフォルト: teddy_notes
    python embed.py --collection flow_notes  # コレクション名指定
    python embed.py --append                 # 既存チャンクに追記（削除しない）
"""

import argparse
import json
import os
try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import psycopg2
import psycopg2.extras

CHUNKS_FILE = Path(__file__).parent.parent / "data" / "chunks" / "all_chunks.json"
COLLECTION_NAME = "teddy_notes"
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/embed")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")
BATCH_SIZE = 50
DB_DSN = os.environ.get("DB_DSN", "dbname=bonsoleil user=teddy")


def parse_date(date_str) -> str | None:
    """ISO 8601等の日付文字列をYYYY-MM-DD形式に変換"""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(str(date_str)).date().isoformat()
    except (ValueError, TypeError):
        return None


def get_embeddings(texts: list[str], retries: int = 3) -> list[list[float]]:
    for attempt in range(retries):
        try:
            data = json.dumps({"model": EMBEDDING_MODEL, "input": texts}).encode()
            req = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type": "application/json"})
            res = urllib.request.urlopen(req, timeout=60)
            result = json.loads(res.read())
            if "embeddings" not in result:
                raise ValueError(f"Unexpected response: {result}")
            return result["embeddings"]
        except Exception as e:
            if attempt == retries - 1:
                raise
            print(f"  ⚠️ Embedding失敗 (attempt {attempt+1}/{retries}): {e}")
            time.sleep(2 ** attempt)


def main():
    parser = argparse.ArgumentParser(description="チャンクをpgvectorに格納")
    parser.add_argument("--collection", default=COLLECTION_NAME, help="コレクション名")
    parser.add_argument("--chunks", default=str(CHUNKS_FILE), help="チャンクJSONファイルパス")
    parser.add_argument("--append", action="store_true", help="既存チャンクに追記（削除しない）")
    args = parser.parse_args()

    chunks_path = Path(args.chunks)
    chunks = json.loads(chunks_path.read_text())
    print(f"{len(chunks)}チャンクをpgvectorに格納開始")
    print(f"  コレクション: {args.collection}")
    print(f"  Embeddingモデル: {EMBEDDING_MODEL} (ollama)")
    print(f"  モード: {'追記' if args.append else '再構築'}")

    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()

        # コレクション登録（なければ作成）
        cur.execute("""
            INSERT INTO rag.collections (name, description)
            VALUES (%s, %s)
            ON CONFLICT (name) DO NOTHING
        """, (args.collection, f"{args.collection} - nomic-embed-text"))

        total = 0
        try:
            # 再構築モードは既存チャンクを削除（INSERTと同一トランザクション内）
            if not args.append:
                cur.execute("DELETE FROM rag.chunks WHERE collection = %s", (args.collection,))
                print(f"  既存チャンク削除完了")

            for i in range(0, len(chunks), BATCH_SIZE):
                batch = chunks[i: i + BATCH_SIZE]
                texts = [c["text"] for c in batch]

                embeddings = get_embeddings(texts)

                rows = []
                for c, emb in zip(batch, embeddings):
                    meta = c.get("metadata", {})
                    chunk_id = c.get("chunk_id", f"{args.collection}_{i}_{len(rows)}")
                    doc_key = meta.get("key", c.get("article_key", ""))
                    title = meta.get("title", c.get("article_title", ""))
                    url = meta.get("origin", "") + meta.get("key", c.get("article_url", ""))
                    date_str = parse_date(meta.get("date", c.get("published_at", None)))
                    chunk_index = meta.get("index", c.get("chunk_index", 0))
                    total_chunks = c.get("total_chunks", meta.get("total_chunks", 0))

                    rows.append((
                        chunk_id,
                        args.collection,
                        doc_key,
                        c["text"],
                        json.dumps(emb),
                        title,
                        url,
                        date_str or None,
                        chunk_index,
                        total_chunks,
                        json.dumps(meta),
                    ))

                psycopg2.extras.execute_batch(cur, """
                    INSERT INTO rag.chunks
                        (id, collection, doc_key, content, embedding, title, url, date, chunk_index, total, metadata)
                    VALUES (%s, %s, %s, %s, %s::vector, %s, %s, %s::date, %s, %s, %s::jsonb)
                    ON CONFLICT (id) DO UPDATE SET
                        content = EXCLUDED.content,
                        embedding = EXCLUDED.embedding,
                        title = EXCLUDED.title,
                        url = EXCLUDED.url,
                        date = EXCLUDED.date,
                        chunk_index = EXCLUDED.chunk_index,
                        total = EXCLUDED.total,
                        metadata = EXCLUDED.metadata,
                        updated_at = now()
                """, rows)

                total += len(batch)
                print(f"  [{total}/{len(chunks)}] 格納完了")

            conn.commit()  # 全バッチ成功後に一括コミット

        except Exception as e:
            conn.rollback()
            print(f"\n❌ エラーが発生しました: {e}")
            raise

        # テストクエリ
        print("\n--- テストクエリ ---")
        test_queries = ["法華経の教え", "教育問題といじめ", "備前焼の伝統", "プログラミングと開発"]
        for q in test_queries:
            emb = get_embeddings([q])[0]
            cur.execute("""
                SELECT title, 1 - (embedding <=> %s::vector) AS score, content
                FROM rag.chunks
                WHERE collection = %s
                ORDER BY embedding <=> %s::vector
                LIMIT 3
            """, (json.dumps(emb), args.collection, json.dumps(emb)))
            rows = cur.fetchall()
            print(f"\n「{q}」:")
            for title, score, content in rows:
                print(f"  [{score:.3f}] {title}")
                print(f"         {content[:80]}...")

        cur.close()
    finally:
        conn.close()
    print(f"\n格納完了！コレクション '{args.collection}' への格納が完了しました")


if __name__ == "__main__":
    main()
