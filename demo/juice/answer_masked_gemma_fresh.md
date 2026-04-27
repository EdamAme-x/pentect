HARトレースから特定可能な脆弱性を以下に列挙します。

1. **タイトル: 機密情報を含む過剰なJWTペイロード (Sensitive Data Exposure in JWT)**
   - **証拠**: `POST /rest/user/login` のレスポンス:
     `{"authentication":{"token":"...eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiI...`
   - **重要度**: critical
   - **説明**: JWTのペイロード(base64デコード可能)に、ユーザーのパスワードハッシュ(`0192023a7bbd73250516f069df18b500` — MD5の `admin123` と推測される弱いハッシュ)、role、emailなどの機密情報が平文で含まれている。JWTは秘匿性を提供しないため、トークン保持者が誰でも復号可能。さらにMD5使用で更に脆弱。

2. **タイトル: SQLインジェクション試行の成功示唆 (SQL Injection in product search)**
   - **証拠**: `GET /rest/products/search?q=%27%29%29--` → 200 OK
     (デコードすると `q='))--` というSQLブレイクアウトpayload)
   - **重要度**: high
   - **説明**: 攻撃者がクエリパラメータに引用符・閉じ括弧・コメント記号を注入したリクエストに対し、サーバーが200で応答している。OWASP Juice Shopで既知のSQLi箇所と一致し、エラーレスポンスを返さず処理されたことから注入が成立している可能性が高い。

3. **タイトル: ディレクトリリスティングの公開 (`/ftp/`) (Directory Listing Exposure)**
   - **証拠**: `GET /ftp/` → 200 OK
   - **重要度**: medium
   - **説明**: `/ftp/` エンドポイントが200を返しており、サーバー上のFTPディレクトリ一覧が外部から閲覧可能。バックアップファイルや内部ドキュメントなどの機密情報リーク経路。

4. **タイトル: 不適切なアクセス制御 — 管理者APIへの未認証アクセス (Broken Access Control on /rest/admin)**
   - **証拠**: `GET /rest/admin/<<USER_ID_6d488933>>` および `GET /rest/admin/<<USER_ID_e64d06d3>>` がいずれも `Authorization` ヘッダなしで `200 OK` を返している(ログイン前のリクエスト群に出現)
   - **重要度**: high
   - **説明**: 管理者向けと推測されるエンドポイントが認証なしで200応答を返しており、認可制御が欠落している可能性が高い。

5. **タイトル: IDOR — 他ユーザー情報の列挙取得 (Insecure Direct Object Reference on /api/Users)**
   - **証拠**:
     - `GET /api/Users/<<USER_ID_6b86b273>>` → id:1 admin の情報取得
     - `GET /api/Users/<<USER_ID_d4735e3a>>` → id:2 customer の情報取得
     - `GET /api/Users/<<USER_ID_4e074085>>` → id:3 customer の情報取得
     (いずれも同じBearerトークンで成功)
   - **重要度**: high
   - **説明**: 1つのユーザートークンで連番IDを指定するだけで他ユーザーのemail等PIIを取得できている。本人以外のレコードも返却されており、リソース所有権チェックが欠如している。

6. **タイトル: 詳細なエラー情報の漏洩 (Verbose Error Responses / Possible Injection Points)**
   - **証拠**:
     - `GET /api/Baskets/<<USER_ID_6b86b273>>` → 500 Internal Server Error
     - `POST /api/BasketItems` → 500 Internal Server Error
   - **重要度**: low
   - **説明**: 通常パラメータで500エラーが発生しており、入力バリデーションが不十分。エラーメッセージ内容によってはスタックトレースやSQL文がリークし、SQLi/NoSQLi等の攻撃糸口になり得る。

7. **タイトル: 弱いパスワードハッシュアルゴリズム (Weak Password Hashing — MD5)**
   - **証拠**: JWT内 `"password":"0192023a7bbd73250516f069df18b500"` (32桁hex = MD5 / saltなし)
   - **重要度**: high
   - **説明**: パスワードがMD5(無salt)で保存されている。これはレインボーテーブル攻撃に脆弱で、現代の標準(bcrypt/argon2等)を満たさない。`admin123` のMD5値と一致。

8. **タイトル: HTTPによる平文通信 (Cleartext Transmission of Credentials)**
   - **証拠**: 全てのリクエストが `http://` スキーム(例: `POST http://<<INTERNAL_URL_HOST>>/rest/user/login`)
   - **重要度**: high
   - **説明**: ログイン時の認証情報および発行されたBearerトークンがTLSなしで送受信されている。中間者攻撃でトークン奪取が可能。

9. **タイトル: Score Board の存在露出 (Information Disclosure)**
   - **証拠**: `GET /api/Challenges/?name=Score%20Board` → 200 OK
   - **重要度**: info
   - **説明**: 隠しスコアボードのエンドポイントが200を返しており、クライアントが未公開機能を列挙できることを示している(Juice Shopの既知の挑戦課題)。
