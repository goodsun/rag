# Academic RAG — 設計提案

## 概要

大学教授向けの論文・文書管理RAGシステム。
既存のnote記事RAGとは**完全に分離**した独立インスタンスとして構築する。

## なぜ分離するか

| 項目 | note RAG | Academic RAG |
|------|----------|--------------|
| データソース | note記事 | 論文・PDF・Word |
| 言語 | 日本語中心 | 日英混在 |
| チャンク戦略 | ブログ記事向け | 学術文書向け |
| ユーザー | bon-soleil内部 | 研究者個人 |

混在させると検索精度が落ちる。インスタンスを分けることで両者の品質を守る。

## アーキテクチャ

```
documents/          ← 監視フォルダ（PDF・Word・txt）
    └── inbox/      ← 新規ファイル投入口
    └── processed/  ← 取り込み済み（自動移動）

academic_rag/
├── ingest.py       ← PDF/Word/txt 取り込みスクリプト
├── watcher.py      ← フォルダ監視 + 自動インジェスト
├── api.py          ← 検索API（既存api.pyと同構造）
├── chroma_db/      ← 専用ベクトルDB
└── config.json     ← 設定
```

## 技術スタック

- **Embedding:** `paraphrase-multilingual-MiniLM-L12-v2`（既存と共通、コスト0）
- **ベクトルDB:** ChromaDB（既存と同様、ただし別コレクション）
- **PDFパーサー:** `pdfminer.six`（テキスト抽出精度が高い）
- **Word対応:** `python-docx`
- **フォルダ監視:** `watchdog`

## チャンク戦略（学術文書向け）

論文は構造が明確なので、ブログ記事より細かく分割する。

- チャンクサイズ: 400〜600文字（abstract/introは小さく、本文は大きめ）
- オーバーラップ: 50文字（文脈の連続性を保つ）
- メタデータ付与: ファイル名・ページ番号・取り込み日時

## フォルダ監視（自動インジェスト）

```
# watcher.py の動作
1. documents/inbox/ を監視
2. 新ファイル検出 → ingest.py を呼び出し
3. 取り込み完了 → documents/processed/ に移動
4. エラー時 → documents/error/ に移動 + ログ出力
```

手動コマンドでも実行可能:
```bash
python academic_rag/ingest.py --file path/to/paper.pdf
python academic_rag/ingest.py --dir path/to/folder/
```

## 検索API

既存 `/service/api.py` と同構造。ポートを分けて共存させる。

```
GET /search?q=量子コンピュータ&limit=5
GET /search?q=...&filter_file=paper2024.pdf  ← ファイル絞り込み
GET /files                                    ← 取り込み済みファイル一覧
DELETE /files/{filename}                      ← ファイル削除（DBからも除去）
```

## セキュリティ考慮

- APIはローカルホストのみバインド（外部公開しない）
- documents/ フォルダはコンテナ内に閉じる（ホスト直接参照なし）
- 取り込み済みファイルのハッシュ管理（重複インジェスト防止）

## 実装フェーズ

- [ ] Phase 1: `ingest.py` — PDF/Word/txt の取り込みと検索
- [ ] Phase 2: `watcher.py` — フォルダ自動監視
- [ ] Phase 3: `api.py` — 検索エンドポイント
- [ ] Phase 4: OpenClawとの連携（skill経由でRAG検索）

---

*提案者: mephi (CCO) — 2026-03-06*
*「データソースが違うなら、DBも違う。混ぜるな危険。」*
