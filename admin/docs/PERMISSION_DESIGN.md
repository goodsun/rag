# ragMyAdmin Permission System Design

**Date:** 2026-02-22
**Status:** Design Draft

---

## コンセプト

Unix File Permissionモデルを ChromaDB メタデータで実現する。
ragMyAdmin のアプリケーション層でアクセス制御し、ChromaDB 本体には一切手を入れない。

---

## Dunder Metadata Fields

| Field | Example | Description |
|-------|---------|-------------|
| `__owner` | `"goodsun"` | ドキュメントの所有者 |
| `__group` | `"devteam"` | 所属グループ |
| `__permission` | `"755"` | Unix形式パーミッション |
| `__visibility` | `"public"` | 簡易フラグ（permissionから自動判定も可） |

---

## Permission Model

Unix互換の3桁数字: `owner / group / others`

各桁: `r(4) + w(2) + x(1)`

| Permission | 意味 | ユースケース |
|-----------|------|-------------|
| `777` | 誰でも閲覧・編集・削除可 | 公開教材データ |
| `755` | 誰でも閲覧可、編集はownerのみ | note記事（公開コンテンツ） |
| `750` | グループまで閲覧可、編集はownerのみ | チーム内ドキュメント |
| `700` | ownerのみ | 社内機密、個人メモ |
| `000` | アクセス不可（アーカイブ） | 削除予定データ |

### RAGコンテキストでの rwx 解釈

- **r (read)**: チャンク内容の閲覧、検索結果への表示
- **w (write)**: チャンクの編集、メタデータ変更
- **x (execute)**: RAG検索のヒット対象になる（検索可能）

x の解釈がポイント: `754` なら owner は検索+閲覧+編集、group は検索+閲覧、others は閲覧のみ（検索にはヒットしない）。
これで「見せるけど検索結果には出さない」みたいな制御が可能。

---

## デフォルト値

- `__permission`: `"700"`（安全側にデフォルト）
- `__owner`: 設定なし = admin扱い
- `__group`: 設定なし = グループなし

**公開したいものだけ明示的に `755` や `777` にする（オプトイン方式）**

---

## ユーザー管理

### `__ragmyadmin_users` コレクション

ChromaDB自体にユーザー情報を格納（phpMyAdmin が mysql.user テーブルで認証するのと同じ思想）。

```
Document ID: user_{username}
Metadata:
  username: "goodsun"
  password_hash: "bcrypt_hash_here"
  role: "admin"          # admin / editor / viewer / guest
  groups: "devteam,rag"  # カンマ区切り
```

※ chunk text にはプロフィール情報等を入れてもよい（検索可能になる）

### Role → Permission マッピング

| Role | 説明 | Permission Check |
|------|------|-----------------|
| `admin` | 全権限 | 常にフルアクセス |
| `editor` | owner or group match → rw | permission check あり |
| `viewer` | others の r bit のみ | read-only |
| `guest` | 未認証 | others の bit のみ（デフォルト） |

---

## アクセス制御フロー

```
リクエスト
  ↓
認証チェック（Cookie / Basic Auth）
  ├── 認証なし → role = guest
  ├── 認証あり → __ragmyadmin_users から role, groups 取得
  ↓
リソースアクセス
  ↓
Permission Check:
  1. role == admin → ALLOW
  2. user == __owner → owner bits で判定
  3. user の groups に __group が含まれる → group bits で判定
  4. それ以外 → others bits で判定
  ↓
r bit なし → 404 (存在自体を隠す)
w bit なし → 403 (read-only表示、編集ボタン非表示)
x bit なし → 検索結果から除外
```

---

## ChromaDB Query での実装

### ゲスト（未認証）の検索

```python
# others に r bit (4) がある = permission の3桁目が 4,5,6,7 のいずれか
col.query(
    query_texts=[q],
    where={"__permission": {"$in": ["774","775","776","777","754","755","756","757","744","745","746","747"]}}
)
```

→ 複雑すぎるので、簡易フラグ `__visibility` を併用：

```python
# 簡易版: public なら誰でも見える
col.query(query_texts=[q], where={"__visibility": "public"})
```

### Permission → Visibility 自動同期

ragMyAdmin が `__permission` 変更時に `__visibility` を自動更新:
- others の r bit あり → `__visibility: "public"`
- others の r bit なし → `__visibility: "private"`

これで検索時は `__visibility` だけ見ればよい（高速）。
`__permission` は編集・削除の判定時に使う。

---

## 段階的実装計画

### Phase 1: Guest Mode（最小実装）
- `__visibility: "public" / "private"` のみ
- 認証なし = public のみ閲覧・検索可能
- 認証あり（既存 Basic Auth）= 全アクセス
- 編集系 API は認証必須

### Phase 2: User Management
- `__ragmyadmin_users` コレクション追加
- ログイン画面、セッション管理
- role ベースの表示制御

### Phase 3: Full Permission
- `__owner`, `__group`, `__permission` 対応
- Unix 互換の rwx チェック
- x bit による検索対象制御

---

## 既存コレクションへの適用

note 記事（teddy_notes, flow_notes）は公開コンテンツなので:

```python
# 一括で public に設定
col.update(ids=all_ids, metadatas=[{"__visibility": "public"} for _ in all_ids])
```

今後追加するプライベートコレクション（discussions, whitepapers 等）はデフォルト `"private"` のまま。

---

## メフィ監査メモ

- デフォルト 700（private）= Secure by Default ✅
- 公開はオプトイン ✅
- embedding 生データはゲストに非表示 ✅
- パスワードは bcrypt ハッシュ ✅
- 存在自体を隠す（404 not 403）✅
- ChromaDB 本体に変更なし = 攻撃面増えない ✅

予想スコア: 75/100（メフィ基準）
