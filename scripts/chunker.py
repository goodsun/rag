#!/usr/bin/env python3
"""記事をチャンクに分割してchunks/に保存する

## Dunder (__) メタデータ規約
- __key: ドキュメントグルーピング用キー（chunk IDのプレフィックス）
- __title: 表示用タイトル
- __url: 元ソースURL
- __date: 公開日/作成日
- __index: チャンク順序（自動付与）
- __total: 総チャンク数（自動付与）
- __chunk_prefix: チャンク先頭に付与するメタデータキー名（カンマ区切り）
  例: "__title" → 1行目にタイトルを追加
  例: "__title, tags, author" → 1行目にタイトル・タグ・著者を追加
"""

import json
import re
import sys
from pathlib import Path

RAW_DIR = Path(__file__).parent.parent / "data" / "raw"
CHUNKS_DIR = Path(__file__).parent.parent / "data" / "chunks"

# チャンク設定
CHUNK_SIZE = 600       # 目標文字数
CHUNK_OVERLAP = 100    # オーバーラップ文字数
MIN_CHUNK_SIZE = 50    # これ以下は前のチャンクに結合


def split_into_sections(text: str) -> list[str]:
    """見出し（##）やダブル改行でセクション分割"""
    parts = re.split(r"\n(?=## )", text)
    sections = []
    for part in parts:
        paragraphs = re.split(r"\n\n+", part.strip())
        sections.extend([p.strip() for p in paragraphs if p.strip()])
    return sections


def chunk_text(body_text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """テキストをチャンクに分割"""
    if not body_text or len(body_text) < MIN_CHUNK_SIZE:
        return [body_text] if body_text and body_text.strip() else []

    sections = split_into_sections(body_text)
    chunks = []
    current = ""

    for section in sections:
        if len(section) > chunk_size * 1.5:
            if current:
                chunks.append(current)
                current = ""
            sentences = re.split(r"(?<=[。！？\n])", section)
            for sent in sentences:
                if not sent.strip():
                    continue
                if len(current) + len(sent) > chunk_size and current:
                    chunks.append(current)
                    current = current[-overlap:] + sent if overlap else sent
                else:
                    current += sent
            continue

        if len(current) + len(section) + 1 > chunk_size and current:
            chunks.append(current)
            current = current[-overlap:] + "\n" + section if overlap else section
        else:
            current = current + "\n" + section if current else section

    if current and current.strip():
        chunks.append(current)

    merged = []
    for chunk in chunks:
        if merged and len(chunk) < MIN_CHUNK_SIZE:
            merged[-1] += "\n" + chunk
        else:
            merged.append(chunk)

    return merged


def build_chunk_prefix(meta: dict, prefix_spec: str) -> str:
    """__chunk_prefix仕様に基づいてプレフィックス行を生成する
    
    prefix_spec: カンマ区切りのメタデータキー名
    例: "__title, tags, author" → "タイトル | タグ | 著者名"
    """
    if not prefix_spec:
        return ""
    keys = [k.strip() for k in prefix_spec.split(",")]
    parts = []
    for k in keys:
        val = meta.get(k, "")
        if val:
            parts.append(str(val))
    return " | ".join(parts) if parts else ""


def process_article(article: dict) -> list[dict]:
    """1記事分のrawデータをチャンクリストに変換する
    
    rawデータに __key, __title 等の dunder メタデータがあればそれを使う。
    なければ旧形式（key, title等）からフォールバック。
    """
    # Dunderメタデータ抽出（明示的指定 > 旧キーからのフォールバック）
    doc_key = article.get("__key") or article.get("key", "unknown")
    doc_title = article.get("__title") or article.get("title", "")
    doc_url = article.get("__url") or article.get("url", "")
    doc_date = article.get("__date") or article.get("published_at", "")
    
    # __chunk_prefix: 指定があればそれを使う、なければ __title でプレフィックス
    chunk_prefix_spec = article.get("__chunk_prefix", "__title")
    
    # ユーザー定義メタデータ（dunders + 標準フィールド以外）を収集
    skip_keys = {"id", "key", "title", "url", "published_at", "like_count",
                 "body_text", "body", "text", "content"}
    extra_meta = {}
    for k, v in article.items():
        if k.startswith("__") or k in skip_keys:
            continue
        extra_meta[k] = v
    
    # 本文テキスト取得
    body = article.get("body_text") or article.get("body") or article.get("text") or ""
    
    # チャンク分割
    chunks = chunk_text(body)
    
    # メタデータベース構築
    base_meta = {
        "__key": doc_key,
        "__title": doc_title,
        "__url": doc_url,
        "__date": doc_date,
        "__chunk_prefix": chunk_prefix_spec,
        # 旧キー互換（チャットボット等の既存消費者向け）
        "article_key": doc_key,
        "article_title": doc_title,
        "article_url": doc_url,
        "published_at": doc_date,
    }
    base_meta.update(extra_meta)
    
    result = []
    for i, chunk_body in enumerate(chunks):
        # プレフィックス生成
        prefix = build_chunk_prefix(base_meta, chunk_prefix_spec)
        if prefix:
            prefixed_text = f"【{prefix}】\n{chunk_body}"
        else:
            prefixed_text = chunk_body
        
        # チャンクメタデータ
        chunk_meta = dict(base_meta)
        chunk_meta["__index"] = i
        chunk_meta["__total"] = len(chunks)
        # 旧キー互換
        chunk_meta["chunk_index"] = i
        chunk_meta["total_chunks"] = len(chunks)
        
        result.append({
            "chunk_id": f"{doc_key}_c{i:03d}",
            "text": prefixed_text,
            "char_count": len(prefixed_text),
            "metadata": chunk_meta,
        })
    
    return result


def main():
    CHUNKS_DIR.mkdir(parents=True, exist_ok=True)

    raw_files = sorted(RAW_DIR.glob("*.json"))
    print(f"{len(raw_files)}件の記事をチャンク分割開始")

    all_chunks = []

    for f in raw_files:
        article = json.loads(f.read_text())
        chunks = process_article(article)
        all_chunks.extend(chunks)
        title = article.get("__title") or article.get("title", f.stem)
        print(f"  {title}: {len(chunks)}チャンク")

    # 全チャンクを1ファイルに保存
    out_path = CHUNKS_DIR / "all_chunks.json"
    out_path.write_text(json.dumps(all_chunks, ensure_ascii=False, indent=2))

    # 統計
    if all_chunks:
        sizes = [c["char_count"] for c in all_chunks]
        print(f"\n完了！")
        print(f"  記事数: {len(raw_files)}")
        print(f"  チャンク数: {len(all_chunks)}")
        print(f"  文字数: min={min(sizes)}, max={max(sizes)}, avg={sum(sizes)//len(sizes)}")
        print(f"  保存先: {out_path}")
    else:
        print("チャンクが生成されませんでした")


if __name__ == "__main__":
    main()
