# RAG - noteベクトル検索

noteの記事をローカルでベクトルDB化し、RAG（Retrieval-Augmented Generation）による検索・引用を可能にするプロジェクト。

## 用途

- **AIアシスタント連携** — 記事の内容を踏まえた文脈ある回答
- **チャットボット** — 外部ユーザーへの記事紹介・質問応答
- **SNS投稿** — 記事の視点を反映したコメント生成

## 技術スタック

- **Embedding:** `paraphrase-multilingual-MiniLM-L12-v2`（fastembed/ONNX / ローカル / コスト0）
- **ベクトルDB:** ChromaDB（軽量・永続化対応）
- **API:** FastAPI（`/service/api.py`）に検索エンドポイント追加
- **チャンク分割:** 500〜800文字/チャンク（セクション単位）
- **タイトル付与:** 各チャンクの先頭に `【記事タイトル】` を付与（検索精度向上）
- **タイトルフォールバック:** ベクトル検索で漏れた記事をタイトル部分一致で補完

## ディレクトリ構成

```
rag/
├── README.md
├── doc/
│   └── plan.md          # 詳細計画書
├── data/
│   ├── raw/             # スクレイピングした元記事（JSON）
│   └── chunks/          # チャンク分割済みデータ
├── chroma_db/           # ChromaDB永続化
├── scripts/
│   ├── scrape_note.py   # noteスクレイピング
│   ├── chunker.py       # チャンク分割
│   └── embed.py         # Embedding + DB格納
└── config.json          # 設定
```

## フェーズ

1. **データ準備** — スクレイピング → チャンク分割 → Embedding → DB格納
2. **テディ連携** — メインセッションからRAG検索
3. **チャットボット連携** — /service/ にRAGコンテキスト注入
4. **X連携** — 自動エンゲージメントにRAG活用

詳細は [doc/plan.md](doc/plan.md) を参照。


---

## インスタンス構成と比較（2026-03-07 実測）

bon-soleilではRAGを2つのインスタンスで運用している。詳細な設計文書は **[branch_officeのシステム設計](https://github.com/goodsun/branch_office/blob/main/documents/system_design/rag_architecture.md)** を参照。

| 項目 | EC2（アリス） | HQ Mac Mini（テディ） |
|------|------------|-------------------|
| DB | ChromaDB | PostgreSQL 17 (pgvector) |
| Embeddingモデル | paraphrase-multilingual-MiniLM-L12-v2 (384次元) | nomic-embed-text (768次元) |
| インデックス | HNSW (cosine) | HNSW (vector_cosine_ops) |
| 検索速度 | 58〜111ms | 初回600ms / 2回目以降27〜33ms |
| 精度（flow_notes検索） | dist: 0.34〜0.49 | dist: 0.24〜0.36 ✅ |

**結論**: HQ PostgreSQLが精度・速度ともに優位。メフィ（CCO）はHQのRAGを主参照として使用する。

### コレクション一覧（HQ PostgreSQL）

| collection | 内容 | チャンク数 |
|-----------|------|---------|
| flow_notes | FLOWのnote記事（マスターの思想・哲学）| 1,393 |
| plurality | Pluralityの書籍 | 1,581 |
| discussions | 社内ディスカッション | 787 |
| teddy_notes | テディのnote記事 | 347 |
| environment | テディの環境情報 | 5 |

### メフィのRAGスキル

メフィ（CCO）はSSH経由でHQ PostgreSQLを参照するスキルを持つ。
スクリプト: `workspace/skills/hq-rag-search/scripts/rag_search.js`
