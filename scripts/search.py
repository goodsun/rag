#!/usr/bin/env python3
"""RAG検索CLI — pgvector + ollama nomic-embed-text版"""

import json
import os
try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass
import sys
import urllib.request

import psycopg2

DB_DSN = os.environ.get("DB_DSN", "dbname=bonsoleil user=teddy")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/embed")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")
DEFAULT_COLLECTION = "teddy_notes"


def get_embedding(text: str) -> list[float]:
    data = json.dumps({"model": EMBEDDING_MODEL, "input": [text]}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req, timeout=30)
    return json.loads(res.read())["embeddings"][0]


def search(query: str, n: int = 5, collection: str = DEFAULT_COLLECTION):
    emb = get_embedding(query)
    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT
                title,
                url,
                1 - (embedding <=> %s::vector) AS score,
                content
            FROM rag.chunks
            WHERE collection = %s
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """, (json.dumps(emb), collection, json.dumps(emb), n))
        rows = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return [
        {
            "score": round(score, 4),
            "title": title,
            "url": url,
            "text": content[:300],
        }
        for title, url, score, content in rows
    ]


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="RAG検索CLI")
    p.add_argument("query", nargs="*", default=["法華経"])
    p.add_argument("--collection", default=DEFAULT_COLLECTION, help="検索対象コレクション")
    p.add_argument("-n", type=int, default=5, help="取得件数")
    args = p.parse_args()
    results = search(" ".join(args.query), args.n, args.collection)
    print(json.dumps(results, ensure_ascii=False, indent=2))
