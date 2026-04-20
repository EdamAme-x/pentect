HARサマリを分析し、脆弱性を特定します。

1. **管理者向けエンドポイントの無認証アクセス (Broken Access Control)**
   - evidence: `GET http://juice-shop.local/rest/admin/application-version -> 200 OK` および `GET http://juice-shop.local/rest/admin/application-configuration`
   - severity: high
   - 説明: `/rest/admin/` 配下の管理エンドポイントに認証ヘッダなしでアクセスでき、200応答が返っている。管理機能が無認証で露出している典型的なBroken Access Control。

2. **ユーザー列挙 / IDOR (Users APIの直接参照)**
   - evidence: `GET /api/Users/1`, `/api/Users/2`, `/api/Users/3` が順次成功し、`admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op` が返却されている
   - severity: high
   - 説明: 数値IDを総当たりで他ユーザーのメール・ロール・作成日時を取得可能。Insecure Direct Object Reference かつユーザー列挙。

3. **機微情報を含むJWTの漏洩 (Sensitive Data Exposure)**
   - evidence: `Authorization: Bearer eyJ...` のペイロードをデコードすると `"password":"0192023a7bbd7325..."`, `"role":"admin"`, `"email":"admin@juice-sh.op"` が含まれる
   - severity: critical
   - 説明: JWTのクレームに管理者のパスワードハッシュ(MD5相当の32桁hex)が埋め込まれている。トークンを傍受すれば即座にハッシュクラック対象になる。

4. **SQLインジェクション試行の痕跡 (検知 or 成功の可能性)**
   - evidence: `GET /rest/products/search?q=%27%29%29--` (デコード: `'))--`)
   - severity: high
   - 説明: 検索パラメータに典型的なSQLi終端ペイロードが投入されている。トレース上はレスポンスコードが記録されていないが、Juice ShopのこのエンドポイントはUNION SQLiの既知脆弱箇所。

5. **例外情報の漏洩につながる500エラー (Error Handling)**
   - evidence: `GET /api/Baskets/1 -> 500 Internal Server Error`
   - severity: medium
   - 説明: 認証済みユーザーが他者のBasket IDにアクセスし500を返している。認可失敗を例外として処理しており、IDOR+情報漏洩の兆候。

6. **FTPディレクトリの露出 (Directory Listing / Sensitive File Exposure)**
   - evidence: `GET /ftp/` および `GET /ftp/package.json.bak -> 403 Forbidden`
   - severity: medium
   - 説明: `/ftp/` が外部からブラウズ可能で、バックアップファイル (`.bak`) の存在がパス経由で確認できる。403で直接取得は防がれているが、既知のNull byte等でバイパスされる脆弱箇所。

7. **Mass Assignment / 過剰なフィールド返却の兆候**
   - evidence: `GET /rest/user/whoami?fields=id,email` でクライアント指定のフィールドクエリを受け付けている
   - severity: low
   - 説明: `fields` パラメータで返却フィールドを制御できる設計は、サーバ側でホワイトリスト化されていなければ内部属性の露出(`password`, `role`等)を招く可能性がある。
