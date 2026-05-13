HARトレースから特定できる脆弱性を以下に列挙します。

1. **SQLインジェクション (検索エンドポイント)**
   - evidence: `GET /api/products?...%29%20OR%201=1--` → `{"error":"near \")\": syntax error","sql":"SELECT * FROM products WHERE name LIKE '%') OR 1=1--%'"}`
   - severity: **critical**
   - explanation: `q` パラメータがエスケープされずに `LIKE` 句に直接連結されている。エラーメッセージに生のSQL (`SELECT * FROM products WHERE name LIKE '%...%'`) が露出しており、文字列連結によるクエリ構築が確定。`')) --` でカッコ数を合わせれば任意のSQLを注入可能。

2. **詳細なエラー情報・SQL文の漏洩 (Verbose Error Disclosure)**
   - evidence: `{"error":"near \")\": syntax error","sql":"SELECT * FROM products WHERE name LIKE '%') OR 1=1--%'"}` および `{"error":"basket lookup failed","trace":["  File 'app.py', line 1, in get_b...","  ...: missing basket id=..."]}`
   - severity: **high**
   - explanation: 500応答でSQL本文・ファイル名 (`app.py`)・スタックトレースをそのまま返却している。攻撃者にスキーマ・内部実装・注入ポイントを示し、上記SQLi攻撃の実装を加速させる。

3. **認証なしでのユーザー情報 (PII + パスワードハッシュ) 露出 — IDOR/Broken Access Control**
   - evidence: `GET /api/users/1`, `/api/users/2`, `/api/users/3` がいずれも `password_hash`, `email`, `role` を含むレスポンスを返す。Authorizationヘッダなしのリクエストに対しても応答している。
   - severity: **critical**
   - explanation: 連番IDを総当たりするだけで全ユーザーの認証情報・PIIが取得できる。`password_hash` をAPIで返すこと自体が設計上の重大欠陥で、オフライン総当たり攻撃の足掛かりとなる。

4. **全ユーザー一覧エンドポイントの非保護露出 (Mass Assignment / Sensitive Data Exposure)**
   - evidence: `GET .../...` (全ユーザーリスト) → `{"users":[{...,"password_hash":"..."},{...},{...}]}`
   - severity: **critical**
   - explanation: 一括ユーザー列挙エンドポイントが `password_hash` 込みで全件を返却。管理者専用であるべき機能がアクセス制御されていない。

5. **権限昇格の可能性 — 他ユーザー (admin) のPATCH**
   - evidence: `PATCH http://.../api/users/3` (id=3 は `role:"admin"` の別ユーザー)。直前の `POST /api/login` で id=1 のトークンが発行されている。
   - severity: **high**
   - explanation: 認証ユーザーが他人 (しかも admin) のレコードをPATCHできているように見える。リクエストボディ次第では `role` 等のフィールドを書き換えてのアカウント乗っ取り・権限昇格に直結する。所有者・ロールチェックの欠如が疑われる。

6. **データベースバックアップファイルの公開**
   - evidence: `GET /backup/` および `GET /backup/db.sql...` がディレクトリ参照可能
   - severity: **critical**
   - explanation: `/backup/` ディレクトリが Web から到達可能で、`db.sql` (DBダンプ) が直接ダウンロードできる状態。全ユーザーのハッシュ・商品データ・スキーマが一括で漏れる。最重要級のミスコンフィグ。

7. **JWTトークン処理時のレスポンスに `password_hash` が含まれる (Login response over-shares)**
   - evidence: `POST /api/login` のレスポンス内 `"user":{...,"password_hash":"5..."}`
   - severity: **high**
   - explanation: ログイン成功応答にパスワードハッシュを返す必要は一切ない。中間者・クライアント側ログ・XSS時に容易に窃取される。

8. **ユーザー列挙 (User Enumeration via 404)**
   - evidence: `GET /api/users/4 -> 404 NOT FOUND` に対し `/api/users/1..3` は 200。
   - severity: **low**
   - explanation: 存在するIDと存在しないIDで応答が明確に分かれ、有効ユーザーIDを総当たりで列挙可能。所見3・4と組み合わせると深刻度が上がる。

9. **エラー応答で内部ファイルパス漏洩**
   - evidence: `/api/baskets/...` の応答 `"trace":["  File 'app.py', line 1, in get_b..."]`
   - severity: **low**
   - explanation: アプリ構成 (Pythonアプリ、ファイル名 `app.py` 等) が漏洩。直接の被害は小さいが、前述SQLi/IDORと併せて攻撃計画を容易にする。

注: トレース内に `Authorization: Bearer ...` がほぼ全リクエストに付与されていないため、上記 1, 3, 4, 6 については **未認証で到達可能** な点が特に問題です。
