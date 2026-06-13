# Pentect positioning

## One-line definition

Pentect is a local, reversible masking layer that lets AI agents work with
sensitive technical values without seeing the original data.

日本語では、次の定義に固定する。

> Pentect は、AI エージェントに機密値を見せずに、技術データを読ませ・使わせるためのローカル可逆マスキングエンジン。

短い対外説明では **AI 時代のローカル可逆 DLP kernel** と言ってよい。
ただし、企業向け DLP 製品全体ではなく、AI agent と tool-use の手前に置く
core/kernel だと必ず補足する。

## Primary user

最初の主ユーザーは **AI を使う技術者**。

具体的には、個人開発者、セキュリティ寄り技術者、AI coding agent を使う人、ログ・設定・コード・API key を AI に渡したい人を想定する。

企業の情シス・セキュリティ管理者や、非技術職向けのブラウザ DLP は将来候補だが、最初の主対象にはしない。

## Core pain

解く痛みは **AI に秘密を見せたくないが、AI の能力は使いたい** こと。

クラウド LLM や AI agent は便利だが、`.env`、API key、cookie、DB URL、顧客情報、内部 endpoint、HTTP trace をそのまま渡せない。手作業で消すのは漏れやすく、消しすぎると AI が推論できない。

Pentect はこの間に入り、機密値をローカルで可逆 placeholder に置き換える。AI は placeholder を見て作業し、必要な実行時だけローカル側で値を戻す。

## Scope

主戦場は、値・構造・checksum・文脈で判定できる技術データ。

- API key, token, credential, private key
- `.env`, config, logs, stack traces, code snippets
- HAR, curl, headers, cookies, query parameters
- local filesystem paths that reveal account names
- email, phone, card, IBAN, national ID などの構造化 PII

自由文 PII は捨てないが、core の主戦場にしない。

- 人名、住所、組織名、自由文の地名は optional NER sidecar / audit / policy pack の責務にする。
- 判例・契約書・社内文書の完全匿名化は v1 の主目的にしない。

詳細な境界は [PII boundary](pii_boundary.md) に固定する。

## Non-goals for now

- ペンテスト専用アプリにすること
- 一般的な PII 匿名化 SaaS にすること
- 企業向け管理 DLP を最初から作ること
- 画像/OCR/Office/PDF 対応を最初の核にすること
- 自由文 PII の 100% recall を core が保証すること

## Differentiation

検出 breadth だけでは勝たない。既存の secret scanner や PII recognizer は多数あり、自由文 PII は Presidio や NER 系の土俵になる。

Pentect の差別化は次の体験に置く。

1. ローカルで機密値を可逆マスクする。
2. AI には placeholder だけを見せる。
3. AI が生成した command や tool input を実行直前にローカルで resolve する。
4. tool output に秘密が再出現したら remask して AI 側へ戻す。

この `mask -> AI -> resolve-at-exec -> remask` が Pentect の核。

## How to describe Pentect

短く説明するときは、次の順で話す。

1. AI に秘密を貼れないので、便利な AI agent を使い切れない。
2. Pentect はローカルで機密値を placeholder に置き換える。
3. placeholder は可逆なので、必要な実行時だけローカルで元の値に戻せる。
4. だから AI には秘密を見せずに、ログ解析・設定相談・API 操作・ペンテスト補助ができる。

避ける説明。

- 「PII 匿名化ツール」
- 「ペンテスト専用ツール」
- 「正規表現で秘密を消すだけの CLI」
- 「企業 DLP」
