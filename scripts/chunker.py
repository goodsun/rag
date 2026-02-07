#!/usr/bin/env python3
"""記事をチャンクに分割してchunks/に保存する"""

import json
import re
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent / "data" / "raw"
CHUNKS_DIR = Path(__file__).parent.parent / "data" / "chunks"

# チャンク設定
CHUNK_SIZE = 600       # 目標文字数
CHUNK_OVERLAP = 100    # オーバーラップ文字数
MIN_CHUNK_SIZE = 50    # これ以下は前のチャンクに結合


def split_into_sections(text: str) -> list[str]:
    """見出し（##）やダブル改行でセクション分割"""
    # ## 見出し で分割
    parts = re.split(r"\n(?=## )", text)
    # さらにダブル改行で段落分割
    sections = []
    for part in parts:
        paragraphs = re.split(r"\n\n+", part.strip())
        sections.extend([p.strip() for p in paragraphs if p.strip()])
    return sections


def chunk_article(body_text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """記事テキストをチャンクに分割"""
    if not body_text or len(body_text) < MIN_CHUNK_SIZE:
        return [body_text] if body_text.strip() else []

    sections = split_into_sections(body_text)
    chunks = []
    current = ""

    for section in sections:
        # セクション自体が大きい場合は文単位で分割
        if len(section) > chunk_size * 1.5:
            # 現在のバッファをフラッシュ
            if current:
                chunks.append(current)
                current = ""
            # 文単位で分割
            sentences = re.split(r"(?<=[。！？\n])", section)
            for sent in sentences:
                if not sent.strip():
                    continue
                if len(current) + len(sent) > chunk_size and current:
                    chunks.append(current)
                    # オーバーラップ: 末尾をキャリーオーバー
                    current = current[-overlap:] + sent if overlap else sent
                else:
                    current += sent
            continue

        # 通常: セクション単位で結合
        if len(current) + len(section) + 1 > chunk_size and current:
            chunks.append(current)
            # オーバーラップ
            current = current[-overlap:] + "\n" + section if overlap else section
        else:
            current = current + "\n" + section if current else section

    if current.strip():
        chunks.append(current)

    # 小さすぎるチャンクを前に結合
    merged = []
    for chunk in chunks:
        if merged and len(chunk) < MIN_CHUNK_SIZE:
            merged[-1] += "\n" + chunk
        else:
            merged.append(chunk)

    return merged


def main():
    CHUNKS_DIR.mkdir(parents=True, exist_ok=True)

    raw_files = sorted(RAW_DIR.glob("*.json"))
    print(f"{len(raw_files)}件の記事をチャンク分割開始")

    all_chunks = []
    total_chunks = 0

    for f in raw_files:
        article = json.loads(f.read_text())
        title = article["title"]
        chunks = chunk_article(article["body_text"])

        for i, chunk_text in enumerate(chunks):
            chunk = {
                "chunk_id": f"{article['key']}_c{i:03d}",
                "article_key": article["key"],
                "article_title": title,
                "article_url": article["url"],
                "published_at": article["published_at"],
                "chunk_index": i,
                "total_chunks": len(chunks),
                "text": chunk_text,
                "char_count": len(chunk_text),
            }
            all_chunks.append(chunk)

        total_chunks += len(chunks)

    # 全チャンクを1ファイルに保存（Embedding時に便利）
    out_path = CHUNKS_DIR / "all_chunks.json"
    out_path.write_text(json.dumps(all_chunks, ensure_ascii=False, indent=2))

    # 統計
    sizes = [c["char_count"] for c in all_chunks]
    print(f"\n完了！")
    print(f"  記事数: {len(raw_files)}")
    print(f"  チャンク数: {total_chunks}")
    print(f"  文字数: min={min(sizes)}, max={max(sizes)}, avg={sum(sizes)//len(sizes)}")
    print(f"  保存先: {out_path}")


if __name__ == "__main__":
    main()
