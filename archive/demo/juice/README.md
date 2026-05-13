# Juice Shop デモ環境

OWASP Juice Shop を `juice-shop.local` というドメインで立てて、Pentect が内部ドメインとして検出できるか示す。

## 1. /etc/hosts に追加

```
127.0.0.1  juice-shop.local
```

Windows 側で動かす場合は `C:\Windows\System32\drivers\etc\hosts`

## 2. 起動

```bash
cd demo/juice
docker compose up -d
```

起動後、http://juice-shop.local:3000 でアクセスできる。

## 3. HAR 取得

`capture.py`(Playwright) を実行すると `captured.har` が生成される。

```bash
pip install playwright
playwright install chromium
python demo/juice/capture.py
```

## 4. Pentect で検査

```bash
python -m engine.cli demo/juice/captured.har --llm > demo/juice/masked.json
```

## 5. 停止

```bash
docker compose down
```
