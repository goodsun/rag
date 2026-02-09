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
