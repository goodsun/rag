#!/usr/bin/env python3
"""noteの記事をスクレイピングしてraw JSONとして保存する"""

import json
import os
import re
import sys
import time
import requests
from html import unescape
from pathlib import Path

# 設定
NOTE_USERNAME = os.environ.get("NOTE_USERNAME", "flow_theory")
RAW_DIR = Path(__file__).parent.parent / "data" / "raw"
PER_PAGE = 6  # noteのAPIは6件固定で返す
DELAY = 1  # API呼び出し間隔（秒）

LIST_API = f"https://note.com/api/v2/creators/{NOTE_USERNAME}/contents"
NOTE_API = "https://note.com/api/v3/notes"


def strip_html(html: str) -> str:
    """HTMLタグを除去してプレーンテキストにする"""
    # <br>, <br/> → 改行
    text = re.sub(r"<br\s*/?>", "\n", html)
    # <p>, </p> → 改行
    text = re.sub(r"</?p[^>]*>", "\n", text)
    # <h1>〜<h6> → 改行+テキスト
    text = re.sub(r"<h[1-6][^>]*>", "\n## ", text)
    text = re.sub(r"</h[1-6]>", "\n", text)
    # その他のタグ除去
    text = re.sub(r"<[^>]+>", "", text)
    # HTMLエンティティ
    text = unescape(text)
    # 連続改行を整理
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def fetch_article_list() -> list[dict]:
    """全記事のメタデータを取得"""
    articles = []
    page = 1
    while True:
        print(f"  記事一覧取得中... page {page}")
        resp = requests.get(
            LIST_API,
            params={"kind": "note", "page": page, "per_page": PER_PAGE},
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        contents = data.get("contents", [])
        if not contents:
            break
        articles.extend(contents)
        if data.get("isLastPage", False) or len(contents) < PER_PAGE:
            break
        page += 1
        time.sleep(DELAY)
    return articles


def fetch_article_body(key: str) -> str:
    """記事本文（HTML）を取得"""
    resp = requests.get(f"{NOTE_API}/{key}")
    resp.raise_for_status()
    return resp.json()["data"].get("body", "")


def main():
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    print(f"note.com/{NOTE_USERNAME} の記事をスクレイピング開始")
    articles = fetch_article_list()
    print(f"  → {len(articles)}件の記事を発見")

    for i, article in enumerate(articles, 1):
        key = article["key"]
        title = article["name"]
        print(f"  [{i}/{len(articles)}] {title}")

        # 本文取得
        time.sleep(DELAY)
        body_html = fetch_article_body(key)
        body_text = strip_html(body_html)

        # 保存
        record = {
            "id": article["id"],
            "key": key,
            "title": title,
            "url": f"https://note.com/{NOTE_USERNAME}/n/{key}",
            "published_at": article.get("publishAt", ""),
            "like_count": article.get("likeCount", 0),
            "body_text": body_text,
        }
        out_path = RAW_DIR / f"{key}.json"
        out_path.write_text(json.dumps(record, ensure_ascii=False, indent=2))

    print(f"\n完了！ {len(articles)}件を {RAW_DIR} に保存しました")


if __name__ == "__main__":
    main()
