#!/usr/bin/env python3
"""チャンクをChromaDBに格納する（多言語Embeddingモデル使用）

Usage:
    python embed.py                          # デフォルト: note_articles
    python embed.py --collection my_docs     # コレクション名指定
    python embed.py --append                 # 既存コレクションに追記（削除しない）
"""

import argparse
import json
from pathlib import Path

import chromadb
from fastembed import TextEmbedding

CHUNKS_FILE = Path(__file__).parent.parent / "data" / "chunks" / "all_chunks.json"
CHROMA_DIR = Path(__file__).parent.parent / "chroma_db"
COLLECTION_NAME = "teddy_notes"
EMBEDDING_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
BATCH_SIZE = 50


class FastEmbedFunction(chromadb.EmbeddingFunction):
    """fastembed を ChromaDB の embedding_function として使うラッパー"""

    def __init__(self, model_name: str):
        self.model = TextEmbedding(model_name)

    def __call__(self, input: list[str]) -> list[list[float]]:
        return [e.tolist() for e in self.model.embed(input)]


def main():
    parser = argparse.ArgumentParser(description="チャンクをChromaDBに格納")
    parser.add_argument("--collection", default=COLLECTION_NAME, help="コレクション名")
    parser.add_argument("--chunks", default=str(CHUNKS_FILE), help="チャンクJSONファイルパス")
    parser.add_argument("--append", action="store_true", help="既存コレクションに追記")
    args = parser.parse_args()

    chunks_path = Path(args.chunks)
    chunks = json.loads(chunks_path.read_text())
    print(f"{len(chunks)}チャンクをChromaDBに格納開始")
    print(f"  コレクション: {args.collection}")
    print(f"  Embeddingモデル: {EMBEDDING_MODEL}")
    print(f"  モード: {'追記' if args.append else '再構築'}")

    ef = FastEmbedFunction(EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    if not args.append:
        try:
            client.delete_collection(args.collection)
            print(f"  既存コレクション '{args.collection}' を削除")
        except Exception:
            pass

    collection = client.get_or_create_collection(
        name=args.collection,
        embedding_function=ef,
        metadata={
            "hnsw:space": "cosine",
            "embedding_model": EMBEDDING_MODEL,
        },
    )

    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i : i + BATCH_SIZE]
        
        # メタデータ: 新形式（metadata フィールド）と旧形式の両対応
        metadatas = []
        for c in batch:
            if "metadata" in c:
                # 新形式: chunker.py が metadata dict を生成
                metadatas.append(c["metadata"])
            else:
                # 旧形式互換
                metadatas.append({
                    "article_key": c.get("article_key", ""),
                    "article_title": c.get("article_title", ""),
                    "article_url": c.get("article_url", ""),
                    "published_at": c.get("published_at", ""),
                    "chunk_index": c.get("chunk_index", 0),
                    "total_chunks": c.get("total_chunks", 0),
                })
        
        collection.add(
            ids=[c["chunk_id"] for c in batch],
            documents=[c["text"] for c in batch],
            metadatas=metadatas,
        )
        print(f"  [{min(i + BATCH_SIZE, len(chunks))}/{len(chunks)}] 格納完了")

    print(f"\n格納完了！コレクション '{args.collection}' に {collection.count()} チャンク")

    # テストクエリ
    print("\n--- テストクエリ ---")
    test_queries = ["法華経の教え", "教育問題といじめ", "備前焼の伝統", "プログラミングと開発"]
    for q in test_queries:
        results = collection.query(query_texts=[q], n_results=3)
        print(f"\n「{q}」:")
        for doc, meta, dist in zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        ):
            title = meta.get("title", "?")
            print(f"  [{dist:.3f}] {title}")
            print(f"         {doc[:80]}...")


if __name__ == "__main__":
    main()
