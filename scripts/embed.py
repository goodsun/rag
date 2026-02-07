#!/usr/bin/env python3
"""チャンクをChromaDBに格納する"""

import json
from pathlib import Path

import chromadb

CHUNKS_FILE = Path(__file__).parent.parent / "data" / "chunks" / "all_chunks.json"
CHROMA_DIR = Path(__file__).parent.parent / "chroma_db"
COLLECTION_NAME = "note_articles"
BATCH_SIZE = 100  # ChromaDBのadd上限対策


def main():
    # チャンク読み込み
    chunks = json.loads(CHUNKS_FILE.read_text())
    print(f"{len(chunks)}チャンクをChromaDBに格納開始")

    # ChromaDB初期化（永続化）
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # 既存コレクションがあれば削除して再作成
    try:
        client.delete_collection(COLLECTION_NAME)
        print(f"  既存コレクション '{COLLECTION_NAME}' を削除")
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},  # コサイン類似度
    )

    # バッチで追加
    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i : i + BATCH_SIZE]
        collection.add(
            ids=[c["chunk_id"] for c in batch],
            documents=[c["text"] for c in batch],
            metadatas=[
                {
                    "article_key": c["article_key"],
                    "article_title": c["article_title"],
                    "article_url": c["article_url"],
                    "published_at": c["published_at"],
                    "chunk_index": c["chunk_index"],
                    "total_chunks": c["total_chunks"],
                }
                for c in batch
            ],
        )
        print(f"  [{min(i + BATCH_SIZE, len(chunks))}/{len(chunks)}] 格納完了")

    # 検証
    print(f"\n格納完了！コレクション '{COLLECTION_NAME}' に {collection.count()} チャンク")

    # テストクエリ
    print("\n--- テストクエリ ---")
    test_queries = ["法華経の教え", "教育問題", "備前焼", "プログラミング"]
    for q in test_queries:
        results = collection.query(query_texts=[q], n_results=3)
        print(f"\n「{q}」:")
        for doc, meta, dist in zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        ):
            print(f"  [{dist:.3f}] {meta['article_title']}")
            print(f"         {doc[:80]}...")


if __name__ == "__main__":
    main()
