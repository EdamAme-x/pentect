# Runpod で FT を回す

ローカル GPU が足りない時 / 比較実験で別 GPU を試したい時に使う。
GPU pod を On-Demand で立てて学習し、checkpoint を持ち帰って自動で pod を落とす。

## 必要なもの

- Runpod API key (`RUNPOD_API_KEY`) — https://runpod.io/console/user/settings
- HF token (`HF_TOKEN`) — Gemma 3 が gated なため (opf 単独なら不要)
- ssh 公開鍵 (`~/.ssh/id_ed25519.pub` など) — pod に登録される

## インストール

```bash
pip install -e '.[runpod]'
```

## 例: Privacy Filter FT (opf)

```bash
export RUNPOD_API_KEY=rpa_xxx
python scripts/runpod_train.py --backend opf --epochs 3 --batch-size 8
```

- A100 80GB PCIe で約 1〜2 分 + データ転送
- 終わると `training/runs/opf_pentect_runpod_<ts>/` にチェックポイントが落ちる
- pod は自動 terminate (失敗時も)

## 例: Gemma 3 4B + LoRA FT

```bash
export RUNPOD_API_KEY=rpa_xxx
export HF_TOKEN=hf_xxx
python scripts/runpod_train.py --backend gemma --epochs 3 --gpu "NVIDIA A100 80GB PCIe"
```

## オプション

- `--cloud COMMUNITY` で community 価格 (~$1.19/h)、`--cloud SECURE` で確実性 (~$1.39/h)
- `--gpu "NVIDIA RTX A6000"` で 48GB に節約
- `--keep` で pod を残す (デバッグ用、課金が続くので注意)

## 価格目安 (2026-04 時点)

| GPU | community | secure |
|---|---|---|
| A100 80GB PCIe | $1.19/h | $1.39/h |
| A100 80GB SXM | $1.50/h 前後 | $1.89/h 前後 |
| RTX A6000 48GB | $0.50/h 前後 | $0.79/h 前後 |
| RTX 4090 24GB | $0.34/h 前後 | $0.69/h 前後 |

500 円 (~$3.3) なら A100 80GB を 2 時間以上回せる。

## 中で何が起きてるか

```
1. runpod.create_pod() で On-Demand pod 起動 (image: pytorch + cuda)
2. PUBLIC_KEY を pod に渡す → root の authorized_keys に登録
3. ssh 経由で /workspace/pentect に rsync push (.git や training/runs 等は除外)
4. pod 内で:
   - pip install -e .  +  opf or transformers extras
   - opf train ... または python -m training.train_lora ...
5. training/runs/<run_name> を rsync pull で持ち帰り
6. runpod.terminate_pod() で確実に課金を止める
```

失敗時も `finally` で terminate するので、課金が暴走することは無い。
