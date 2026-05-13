セキュリティレビューを開始します。

# セキュリティレビュー結果

トレースから特定可能な脆弱性を以下に列挙します。

## 1. SQL Injection の試行(検証可能な攻撃ベクトル)
- **title**: 商品検索エンドポイントに対する SQL Injection 試行
- **evidence**: `GET http://<<INTERNAL_URL_HOST_f4703816>>/rest/products/search?q=%27%29%29--`
- **severity**: high
- **explanation**: `q` パラメータに URL エンコードされた `'))--` が送信されています。これは典型的な SQLi クロージャ + コメント化ペイロードであり、攻撃者が SQL インジェクションを試みている明確な証拠です。レスポンスコードはトレースに記載がないため成否は不明ですが、エンドポイントが SQLi 試験対象となっていることが明らかです。OWASP Juice Shop でも既知の脆弱な箇所です。

## 2. IDOR(Insecure Direct Object Reference) / 権限昇格
- **title**: `/api/Users/{id}` で他ユーザーの管理者情報を取得可能
- **evidence**:
  - `GET /api/Users/<<USER_ID_6b86b273>>` → `"id":1,...,"role":"admin",...`
  - `GET /api/Users/<<USER_ID_d4735e3a>>` → `"id":2,...`
  - `GET /api/Users/<<USER_ID_4e074085>>` → `"id":3,...`
- **severity**: high
- **explanation**: 任意のユーザー ID を指定するだけで他ユーザーのプロフィール情報(email、role、deluxeToken フィールド、lastLoginIp 等)を順次取得できています。特に `id:1` の `role:"admin"` が露出しており、認可チェックが欠落した IDOR が成立しています。

## 3. 機微情報の API レスポンス露出
- **title**: ユーザー API が `deluxeToken` / `lastLoginIp` などをレスポンスに含めている
- **evidence**: `/api/Users/...` の各レスポンス内 `"deluxeToken":"","lastLoginIp":"",...`
- **severity**: medium
- **explanation**: `deluxeToken`(課金/権限ステータスに関わるトークン)や `lastLoginIp` といった、本来クライアントへ返すべきでないフィールドが API スキーマで露出しています。マスク済みで値は空に見えますが、フィールド自体が返却される設計は情報漏洩の温床です。

## 4. 機密ディレクトリ `/ftp/` の露出
- **title**: `/ftp/` ディレクトリリスティングへのアクセス可能性
- **evidence**:
  - `GET /ftp/`
  - `GET /ftp/package.json.bak` → `403 Forbidden`
- **explanation**: `/ftp/` 配下のリスティングへ攻撃者がアクセスを試みています。`package.json.bak` への直接アクセスは 403 ですが、ディレクトリ自体(`/ftp/`)のレスポンスコードがトレース上明示されておらず、Juice Shop 既定では一覧が露出します。バックアップファイルがホスティングされている時点で Sensitive Data Exposure の典型例です。
- **severity**: medium

## 5. Score Board(管理用エンドポイント)の露出
- **title**: 隠しスコアボードチャレンジエンドポイントの探索
- **evidence**: `GET /api/Challenges/?name=Score%20Board`
- **severity**: low
- **explanation**: 通常のユーザー UI から見えない管理/デバッグ用の "Score Board" を列挙する試行が成立しています。本番環境で同種のデバッグエンドポイントが残存していれば Information Disclosure です。

## 6. Bearer トークンの平文 HTTP 送信
- **title**: `Authorization: Bearer` ヘッダが HTTP(非 TLS)で送信されている
- **evidence**: `GET http://.../rest/user/whoami` に `Authorization: Bearer <<CREDENTIAL_99ed0ee3>>`
- **severity**: high
- **explanation**: すべてのリクエストが `http://`(平文)です。Bearer トークンや Cookie が中間者によって盗聴可能な状態で送信されています。HTTPS 必須化が行われていません。

## 7. 500 Internal Server Error によるエラーハンドリング不備
- **title**: `/api/Baskets/{id}` が 500 を返却
- **evidence**: `GET /api/Baskets/<<USER_ID_6b86b273>> -> 500 Internal Server Error`
- **severity**: low
- **explanation**: 想定外の入力やアクセス権の問題に対し 500 を返しており、適切な 4xx ハンドリングおよびエラーメッセージのサニタイズができていない可能性があります。スタックトレースが返るタイプの構成では Information Disclosure に発展します。

## 8. Mass Assignment / フィールド指定の脆弱性候補
- **title**: `whoami?fields=id,email` のフィールドセレクタ
- **evidence**: `GET /rest/user/whoami?fields=id,email`
- **severity**: low
- **explanation**: クライアントから任意のフィールド名を指定できるパラメータが存在します。サーバ側でホワイトリスト制限がない場合、内部フィールド(password ハッシュ、トークン等)を `fields=` で要求して引き出される Mass Assignment / Excessive Data Exposure に発展しうる設計です。トレースだけでは悪用の成否は確認できませんが、設計上の指摘事項です。

---

**注意**: トレースはマスク済みで、レスポンスボディの多くと一部のステータスコードが省略されています。SQLi(#1)、IDOR(#2)については成功/失敗の最終確認には生のレスポンス本文が必要です。トレースから「試行が確実に存在する」「設計上の欠陥が見える」ものに限って列挙しました。
