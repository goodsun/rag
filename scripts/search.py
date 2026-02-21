#!/usr/bin/env python3
"""RAG検索CLI — テディがexecで呼び出す用"""

import json
import sys
import chromadb
from fastembed import TextEmbedding
from pathlib import Path

CHROMA_DIR = str(Path(__file__).parent.parent / "chroma_db")
COLLECTION_NAME = "note_articles"
MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


class FastEmbedFunction(chromadb.EmbeddingFunction):
    def __init__(self, model_name: str):
        self.model = TextEmbedding(model_name)
    def __call__(self, input: list[str]) -> list[list[float]]:
        return [e.tolist() for e in self.model.embed(input)]


def search(query: str, n: int = 5):
    ef = FastEmbedFunction(MODEL)
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    col = client.get_collection(name=COLLECTION_NAME, embedding_function=ef)

    results = col.query(query_texts=[query], n_results=n)
    items = []
    for doc, meta, dist in zip(
        results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        items.append({
            "distance": round(dist, 4),
            "title": meta.get('title', ''),
            "url": (meta.get('origin','') + meta.get('key','')),
            "text": doc[:300],
        })
    return items


if __name__ == "__main__":
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "法華経"
    n = 5
    results = search(query, n)
    print(json.dumps(results, ensure_ascii=False, indent=2))
