"""Qwen-based Verifier: a second-opinion LLM that re-reads masked text.

Design intent:
  - Use a *different model family* from the primary FT detector (Gemma) so
    systematic blind spots are not shared.
  - No fine-tuning. The Verifier is a classification-style prompt task
    ("does any sensitive value still appear here?"), which Qwen 2.5 Instruct
    handles zero-shot. Adding FT would defeat the diversity goal.

Env vars:
  PENTECT_VERIFIER_MODEL    HF model id (default: Qwen/Qwen2.5-3B-Instruct)
  PENTECT_VERIFIER_4BIT     "1" to load in 4-bit (default: 1)
  PENTECT_VERIFIER_MAX_TOK  max_new_tokens (default: 200)
"""
from __future__ import annotations

import json as _json
import os
import re
from dataclasses import dataclass


_PROMPT_TEMPLATE = """You are a security reviewer. The text below has already been passed
through a masking engine, which replaces sensitive values with placeholders of
the form <<CATEGORY_hash>>. Your job is to look at the *remaining* text and
decide whether any sensitive value slipped through.

Sensitive = credentials/tokens, internal hostnames, private IPs, emails,
personal names, customer/user IDs.

Ignore placeholders like <<PII_NAME_a1b2>> -- those are correctly masked.
Only flag raw values that escaped masking.

Respond with a JSON object on a single line:
{{"ok": true}}  if nothing leaked
{{"ok": false, "leaks": ["value1", "value2"]}}  if something still appears

Masked text:
---
{masked}
---

Response:
"""


@dataclass
class VerifierReport:
    ok: bool
    leaks: list[str]
    raw: str


def _parse(raw: str) -> VerifierReport:
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return VerifierReport(ok=True, leaks=[], raw=raw)
    try:
        obj = _json.loads(m.group(0))
    except Exception:  # noqa: BLE001
        return VerifierReport(ok=True, leaks=[], raw=raw)
    ok = bool(obj.get("ok", True))
    leaks_raw = obj.get("leaks") or []
    leaks = [str(x) for x in leaks_raw if isinstance(x, (str, int))]
    return VerifierReport(ok=ok, leaks=leaks, raw=raw)


class QwenVerifier:
    name = "qwen-verifier"

    def __init__(self) -> None:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
            import torch
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "transformers not installed. Install with: pip install 'pentect[llm]'"
            ) from e

        model_id = os.environ.get("PENTECT_VERIFIER_MODEL", "Qwen/Qwen2.5-3B-Instruct")
        use_4bit = os.environ.get("PENTECT_VERIFIER_4BIT", "0").lower() in {"1", "true"}
        self._max_new_tokens = int(os.environ.get("PENTECT_VERIFIER_MAX_TOK", "32"))
        self._max_input_chars = int(os.environ.get("PENTECT_VERIFIER_MAX_CHARS", "1500"))

        self._tok = AutoTokenizer.from_pretrained(model_id)
        if self._tok.pad_token is None:
            self._tok.pad_token = self._tok.eos_token
        self._tok.padding_side = "left"

        kwargs: dict = {"device_map": "auto"}
        if use_4bit:
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
            )
        else:
            kwargs["dtype"] = torch.bfloat16

        self._model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
        self._model.eval()

    def _generate(self, prompts: list[str]) -> list[str]:
        import torch

        tok, model = self._tok, self._model
        enc = tok(prompts, return_tensors="pt", padding=True, truncation=True, max_length=1024).to(model.device)
        with torch.inference_mode():
            out = model.generate(
                **enc,
                max_new_tokens=self._max_new_tokens,
                do_sample=False,
                pad_token_id=tok.pad_token_id,
                use_cache=True,
            )
        prompt_len = enc["input_ids"].shape[1]
        gen_only = out[:, prompt_len:]
        return tok.batch_decode(gen_only, skip_special_tokens=True)

    def verify(self, masked_text: str) -> VerifierReport:
        raw = self._generate([_PROMPT_TEMPLATE.format(masked=masked_text[:self._max_input_chars])])[0]
        return _parse(raw)

    def verify_batch(self, masked_texts: list[str]) -> list[VerifierReport]:
        prompts = [_PROMPT_TEMPLATE.format(masked=t[:self._max_input_chars]) for t in masked_texts]
        raws = self._generate(prompts)
        return [_parse(r) for r in raws]
