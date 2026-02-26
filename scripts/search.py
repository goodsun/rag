#!/usr/bin/env python3
"""RAG検索CLI — pgvector + ollama nomic-embed-text版"""

import json
import os
import sys
import urllib.request

import psycopg2

DB_DSN = os.environ.get("DB_DSN", "dbname=bonsoleil user=teddy")
OLLAMA_URL = "http://localhost:11434/api/embed"
EMBEDDING_MODEL = "nomic-embed-text"
DEFAULT_COLLECTION = "teddy_notes"


def get_embedding(text: str) -> list[float]:
    data = json.dumps({"model": EMBEDDING_MODEL, "input": [text]}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req, timeout=30)
    return json.loads(res.read())["embeddings"][0]


def search(query: str, n: int = 5, collection: str = DEFAULT_COLLECTION):
    emb = get_embedding(query)
    conn = psycopg2.connect(DB_DSN)
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
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "法華経"
    results = search(query)
    print(json.dumps(results, ensure_ascii=False, indent=2))
