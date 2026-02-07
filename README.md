# RAG - goodsun's note記事ベクトル検索

goodsunさん（[@flow_theory](https://note.com/flow_theory)）のnote記事約90本をベクトルDB化し、テディおよび各サービスから検索・引用できるようにするプロジェクト。

## 用途

- **テディ（メインセッション）** — goodsunさんの思想・知見を踏まえた回答
- **/service/ チャットボット** — 外部ユーザーへの記事紹介・質問応答
- **X自動エンゲージメント** — goodsunさんの視点を反映したコメント生成

## 技術スタック

- **Embedding:** `intfloat/multilingual-e5-small`（sentence-transformers / ローカル / コスト0）
- **ベクトルDB:** ChromaDB（軽量・永続化対応）
- **API:** 既存FastAPI（`/service/api.py`）に検索エンドポイント追加
- **チャンク分割:** 500〜800文字/チャンク（セクション単位）

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
