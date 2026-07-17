# sasuty セットアップ手順

## 1. Supabaseでスキーマを実行

Supabaseダッシュボード → **SQL Editor** で `schema.sql` の内容を全て貼り付けて実行してください。

これにより以下が作成されます：
- `users`（アカウント）
- `sessions`（ログインセッション）
- `posts`（投稿・返信、`content`は280文字制限）
- `likes` / `reposts`（`post_id + user_handle` でユニーク制約 → 二重いいね/リポストを防止）
- `impressions`（閲覧数）
- `increment_impression()` RPC関数（閲覧数を安全に1件ずつ加算）

## 2. サーバー起動

```bash
npm install
npm start
```

`SUPABASE_URL` / `SUPABASE_ANON_KEY` は環境変数で上書き可能です（未設定時はコード内のデフォルト値を使用）。

## 3. 主な変更点・修正内容

### いいね・インプレッションが反映されなかった原因と修正
1. **インプレッションの無限増殖バグ**: 旧コードは`fetchPosts()`が呼ばれるたび（いいねやリポストのたびに毎回）閲覧数を+1していました。→ **個別ポストページ(onepost.html)を開いた時に1回だけ**、サーバーのRPC関数`increment_impression`経由で安全に加算する方式に変更。
2. **いいね/リポストの二重登録**: `likes`/`reposts`テーブルに`unique(post_id, user_handle)`制約を追加し、DBレベルで二重防止。
3. **エラーが握りつぶされていた**: `toggleLike`/`toggleRepost`のSupabase操作結果を`console.error`でログ出力するよう修正（原因調査しやすく）。

### 新規ページ
- **onepost.html**: 個別投稿の詳細＋返信一覧（スレッド表示）。返信はここから投稿。
- **login.html**: ログインページ。
- **sinkitouroku.html**: 新規登録ページ。

### 認証システム
- `users`テーブルに`handle`(ユーザー名) + `password_hash`(bcrypt)を保存。
- ログイン成功時、`sessions`テーブルにランダムトークンを発行し、`httpOnly` Cookie(`sasuty_session`)にセット。
- 全ページ共通で`/api/me`を叩き、未ログインならログインページへリダイレクト（`onepost.html`は未ログインでも閲覧可、返信のみログイン必須）。
- ログアウトはサイドバーの「ログアウト」ボタンから。

### 文字数制限
- 投稿・返信ともに **280文字**。フロント側でリアルタイムカウンター表示＋サーバー側でも検証（二重チェック）。

## 4. ファイル構成

```
sasuty/
├── index.js              # Express サーバー（認証API・投稿API）
├── package.json
├── schema.sql             # Supabase用SQLスキーマ（最初に実行）
└── public/
    ├── index.html          # タイムライン（要ログイン）
    ├── onepost.html        # 個別投稿＋返信スレッド
    ├── login.html          # ログイン
    ├── sinkitouroku.html   # 新規登録
    └── common.js           # 共通JS（認証状態取得・ユーティリティ）
```

## 5. 本番運用の注意点
- `secure: true`（Cookie）はHTTPS環境でのみ有効にしてください（`index.js`内にコメントあり）。
- 現在のRLSポリシーはanonキーで全許可の簡易設定です。本番ではサーバー(service role key)経由に絞ることを推奨します。
