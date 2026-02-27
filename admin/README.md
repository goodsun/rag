# ragMyAdmin

bon-soleil RAG管理ツール。PostgreSQL + pgvectorベース。

## セットアップ

### 必要条件
- PostgreSQL 17 + pgvector
- Python 3.11+
- ollama (nomic-embed-text)

### インストール
pip install -r requirements.txt

### 環境変数
| 変数 | デフォルト | 説明 |
|------|-----------|------|
| DB_DSN | dbname=bonsoleil user=teddy | PostgreSQL接続文字列 |
| OLLAMA_URL | http://localhost:11434/api/embed | ollama API URL |
| APP_ROOT | (空) | リバースプロキシのprefix |
| EMBEDDING_MODEL | nomic-embed-text | ollamaの埋め込みモデル名 |

### マイグレーション
psql -d bonsoleil -f migrations/001_initial.sql

### 起動
python3 app.py

## 初回ユーザー作成

psqlで直接挿入（bcryptハッシュ生成が必要）:

```python
import bcrypt
pw = bcrypt.hashpw(b"yourpassword", bcrypt.gensalt()).decode()
print(pw)
```

```sql
INSERT INTO shared.users (username, password_hash, role)
VALUES ('admin', '<上記のハッシュ>', 'admin');
```

## 動作確認

```bash
launchctl kickstart -k gui/$(id -u)/com.bonsoleil.ragmyadmin
sleep 2
curl -s http://127.0.0.1:8792/ -o /dev/null -w "%{http_code}"
```
