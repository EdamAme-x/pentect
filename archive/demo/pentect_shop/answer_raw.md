# セキュリティレビュー結果

1. **SQLインジェクション (検索エンドポイント)**
   - evidence: `GET /api/products/search?q=%27%29%20OR%201%3D1--` → `{"error":"near \")\": syntax error","sql":"SELECT * FROM products WHERE name LIKE '%') OR 1=1--%'"}`
   - severity: **critical**
   - 説明: ユーザー入力 `q` が生のSQL文字列にそのまま連結されている。エラーレスポンスに実行されたSQLクエリがそのまま返っており、ペイロード `')) --` でも同様の構文エラーが発生していることから、パラメータ化クエリが使われていないことが確認できる。任意のSQL実行・データ抽出が可能。

2. **詳細なエラー情報の漏洩 (Verbose Error Messages)**
   - evidence: `/api/products/search` および `/api/baskets/99999` のレスポンスに `"sql":"SELECT * FROM products ..."` や `"trace":["  File 'app.py', line 1, ...","  sqlite3.IntegrityError: ..."]` を含む
   - severity: **medium**
   - 説明: 実行SQL、ファイル名 (`app.py`)、内部例外 (`sqlite3.IntegrityError`)、スタックトレースをクライアントに返している。攻撃者にDBエンジン (SQLite)、コード構成、攻撃成功の判定材料を提供する。

3. **認証なしでのユーザー情報・パスワードハッシュ漏洩 (Broken Access Control / IDOR)**
   - evidence: `GET /api/users/1`, `/api/users/2`, `/api/users/3` がトークンなしで `password_hash`, `email`, `role` を含む全ユーザー情報を返している
   - severity: **critical**
   - 説明: 認可チェックがなく、IDを順番に列挙するだけで全ユーザーの機微情報が取得できる。`/api/users/4` が 404 を返すことから、IDによるユーザー列挙も成立している。

4. **管理者用ダンプエンドポイントが無認証で公開**
   - evidence: `GET /api/admin/dump` → `{"users":[{...password_hash...},...]}` 全ユーザー情報を一括返却
   - severity: **critical**
   - 説明: `/api/admin/` 配下のエンドポイントが認証/認可なしでアクセス可能。データベース全体の流出に直結する。

5. **脆弱なパスワードハッシュアルゴリズム (Unsalted MD5)**
   - evidence: `"password_hash":"5f4dcc3b5aa765d61d8327deb882cf99"` (= MD5("password")), `"098f6bcd4621d373cade4e832627b4f6"` (= MD5("test"))
   - severity: **high**
   - 説明: 32桁16進のMD5ハッシュをソルトなしで使用。レインボーテーブルで瞬時に逆引き可能で、実際にデフォルト値 `password`/`test` が即座に判明する。bcrypt/argon2 等への移行が必要。

6. **JWTペイロードへのパスワードハッシュ埋め込み**
   - evidence: `POST /api/login` のレスポンスJWTをデコードすると `{"sub":1,"email":"admin@pentect-shop.local","role":"admin","password_hash":"5f4dcc3b5aa765d61d8327deb882cf99","iat":...}`
   - severity: **high**
   - 説明: JWTは署名されているだけで暗号化されていない (Base64デコードで中身が見える)。パスワードハッシュをトークンに含めるとトークンを傍受しただけでハッシュが漏れ、オフライン解析の対象になる。

7. **JWTの脆弱な署名アルゴリズム/キー管理の疑い (HS256)**
   - evidence: JWTヘッダ `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` = `{"alg":"HS256","typ":"JWT"}`
   - severity: **low**
   - 説明: HS256自体は脆弱ではないが、対称鍵運用かつ `exp`/`nbf` クレームが見当たらない (有効期限なし) ため、トークン窃取時のリスクが高い。

8. **権限昇格を許す PATCH /api/users/{id} の可能性**
   - evidence: ログイン直後 (admin token 取得後) に `PATCH /api/users/3` が成功している記録。レスポンス本体は省略されているが、エラー応答が出ていないことから受理されたと推測される。さらに通常ユーザーでもこのエンドポイントが叩ける可能性がある (検証必要)。
   - severity: **medium**
   - 説明: ID指定で他ユーザーの属性 (role 等) を更新できる場合、IDOR/権限昇格に直結する。少なくとも管理者がユーザー3を `admin` に昇格させた形跡があり、認可境界の確認が必要。

9. **バックアップファイルの公開ディレクトリ配置**
   - evidence: `GET /backup/` および `GET /backup/db.sql.bak`
   - severity: **critical**
   - 説明: アプリのwebルート配下に `/backup/` ディレクトリが存在し、`db.sql.bak` (SQLダンプ) が無認証でダウンロード可能。ディレクトリリスティングも有効と思われ、データベース内容全件流出の致命的なリスク。

10. **HTTP (平文) 通信**
    - evidence: 全リクエストが `http://127.0.0.1:5057/...` で実施されている
    - severity: **info**
    - 説明: ローカルホスト宛なので本トレース上の影響は限定的だが、本番展開時にHTTPSが必須となる点を明記。JWTやパスワードハッシュが平文でやり取りされている。

---
**サマリ**: critical 4件 (SQLi, IDOR, admin dump公開, バックアップ漏洩) / high 2件 / medium 2件 / low 1件 / info 1件。最優先対応はパラメータ化クエリ導入、`/api/users/*` と `/api/admin/*` の認可実装、`/backup/` の公開停止、パスワードハッシュ方式の刷新です。
