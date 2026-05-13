# archive/ — 採択までの過程

このディレクトリは、 未踏ジュニア採択 (2026-05) までに書いた Pentect
prototype の凍結。 突貫工事のまま残してある — 思考の痕跡として読み
返すためのもので、 動かしたり改修したりする想定はない。

## ここにあるもの

- `engine/` — マスキングエンジン本体 (rule / entropy / base64-unwrap /
  seed-phrase / crypto-address / encoding-peel / opf_pf 等の検出器、
  granularity、 merger、 mask_har オーケストレーション)
- `tests/` — 440 件のテスト
- `ui/` + `server/` — Vite + FastAPI のデモ
- `demo/` — Juice Shop / WebGoat / pentect_shop の HAR キャプチャ + マスク結果
- `eval/`, `testcases/`, `training/` — 評価とデータ生成の足場
- `scripts/` — bench_scaling.py 等
- `ref*.md` — 採択提案 / メンタリング向けの思考ログ (ref から ref11 まで)
- `README.md` — 元のプロダクト README (採択前時点の説明)

## なぜ archive にしたか

採択後、 「**思想を再定義してゼロから本番リポを切る**」 と決めた。 ここは
そのための材料 / 後で見返すための歴史。 本番コードはリポルートで新しく
作り直す。

## 移動経緯

採択直後の整理: 2026-05-13。 `.git` 以外を全部このディレクトリへ。

要点メモ: `ref11.md` (移動前の最後のメモ — 混合行列、 比較ベンチの方針)
