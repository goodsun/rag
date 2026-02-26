#!/usr/bin/env python3
"""議事録MarkdownをRAG用JSONに変換する"""
import json, os, re
from pathlib import Path

DISCUSSIONS_DIR = Path(os.environ.get("DISCUSSIONS_DIR", os.path.expanduser("~/documents/discussions")))
RAW_DIR = Path(os.environ.get("RAW_DIR", str(Path(__file__).parent.parent / "data" / "raw_discussions")))

def main():
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    md_files = list(DISCUSSIONS_DIR.rglob("*.md"))
    print(f"{len(md_files)}件の議事録を処理")
    
    for fp in md_files:
        rel = fp.relative_to(DISCUSSIONS_DIR)
        # doc_key: パスをそのまま使う（/ → _）
        doc_key = "disc_" + str(rel).replace("/", "_").replace(".md", "").replace(" ", "_")
        
        # 壊れたシンボリックリンクをスキップ
        if not fp.exists():
            print(f"  スキップ（リンク切れ）: {rel}")
            continue
        content = fp.read_text(encoding="utf-8")
        
        # タイトル: 1行目の# から取得、なければファイル名
        title = fp.stem
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("# "):
                title = line[2:].strip()
                break
        
        # 日付をパスから推定
        parts = fp.parts
        date_str = ""
        year = ""
        for p in parts:
            if re.match(r'^\d{4}$', p) and 2020 <= int(p) <= 2100:
                year = p
            elif re.match(r'^\d{4}$', p) and year:
                date_str = f"{year}-{p[:2]}-{p[2:]}"
        
        origin = "https://staff.bon-soleil.com/discussions/"
        
        doc = {
            "key": doc_key,
            "title": title,
            "body_text": content,
            "date": date_str,
            "origin": origin,
            "path": str(rel),
            "tags": [],
        }
        
        out = RAW_DIR / f"{doc_key}.json"
        out.write_text(json.dumps(doc, ensure_ascii=False, indent=2))
    
    print(f"完了: {RAW_DIR}")

if __name__ == "__main__":
    main()
