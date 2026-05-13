"""LLM detector (loads a fine-tuned Gemma 3 4B).

Env vars:
  PENTECT_LLM_MODEL    base model id (default: google/gemma-3-4b-it)
  PENTECT_LLM_ADAPTER  path to a LoRA adapter (optional)
  PENTECT_LLM_4BIT     "1" to load base in 4-bit (faster, smaller VRAM)
  PENTECT_LLM_MAX_TOK  max_new_tokens per sample (default: 160)

Post-processing (placeholder generation, hashing, grouping) is done in Python.
"""
from __future__ import annotations

import json as _json
import os
import re

from engine.categories import Category
from engine.detectors.base import Span


_PROMPT = """### Instruction:
Detect sensitive spans in the following text and output a JSON array of objects with
fields 'span' (the exact substring) and 'category' (one of CREDENTIAL, INTERNAL_URL,
INTERNAL_IP, PII_EMAIL, PII_NAME, USER_ID).

### Input:
{input}

### Output:
"""


_OBJ_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


def _parse_output(raw: str) -> list[tuple[str, str]]:
    # Cut at hallucinated continuation markers so we only consider the first block.
    for marker in ("### Instruction", "### Input", "\n### "):
        idx = raw.find(marker, 1)
        if idx > 0:
            raw = raw[:idx]
            break

    # Prefer the first balanced [...] block starting at the first '['.
    start = raw.find("[")
    candidate: str | None = None
    if start >= 0:
        depth = 0
        for i in range(start, len(raw)):
            c = raw[i]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    candidate = raw[start:i + 1]
                    break
        if candidate is None:
            # truncated mid-array: salvage by harvesting any complete {...} objects
            candidate = raw[start:] + "]"

    items: list[dict] = []
    if candidate:
        try:
            arr = _json.loads(candidate)
            if isinstance(arr, list):
                items = [x for x in arr if isinstance(x, dict)]
        except Exception:  # noqa: BLE001
            # Fall back to extracting any complete {"span":..., "category":...} objects
            for m in _OBJ_RE.finditer(candidate):
                try:
                    obj = _json.loads(m.group(0))
                except Exception:  # noqa: BLE001
                    continue
                if isinstance(obj, dict):
                    items.append(obj)

    out: list[tuple[str, str]] = []
    for item in items:
        span = item.get("span")
        cat = item.get("category")
        if isinstance(span, str) and isinstance(cat, str):
            out.append((span, cat))
    return out


class LLMDetector:
    name = "llm"

    def __init__(self) -> None:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
            import torch
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "transformers is not installed. Install with: pip install 'pentect[llm]'"
            ) from e

        model_id = os.environ.get("PENTECT_LLM_MODEL", "google/gemma-3-4b-it")
        adapter = os.environ.get("PENTECT_LLM_ADAPTER")
        use_4bit = os.environ.get("PENTECT_LLM_4BIT", "").lower() in {"1", "true"}
        self._max_new_tokens = int(os.environ.get("PENTECT_LLM_MAX_TOK", "384"))
        self._micro_batch = int(os.environ.get("PENTECT_LLM_MICROBATCH", "4"))

        self._tok = AutoTokenizer.from_pretrained(model_id)
        if self._tok.pad_token is None:
            self._tok.pad_token = self._tok.eos_token
        self._tok.padding_side = "left"  # required for batched generation with decoder-only

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
        if adapter:
            from peft import PeftModel

            self._model = PeftModel.from_pretrained(self._model, adapter)
        self._model.eval()

    def _generate(self, prompts: list[str]) -> list[str]:
        """Generate with automatic micro-batching.

        Large HARs produce dozens of prompts; running them as one padded
        tensor OOMs 16GB cards. Split into PENTECT_LLM_MICROBATCH chunks.
        If a single-prompt chunk still OOMs, raise — silently skipping would
        let sensitive spans through as a masking fallback, which is exactly
        the failure mode we refuse to have.
        """
        import torch

        tok, model = self._tok, self._model
        results: list[str] = []
        size = max(1, self._micro_batch)
        i = 0
        while i < len(prompts):
            chunk = prompts[i : i + size]
            try:
                enc = tok(chunk, return_tensors="pt", padding=True,
                          truncation=True, max_length=1024).to(model.device)
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
                results.extend(tok.batch_decode(gen_only, skip_special_tokens=True))
                del enc, out, gen_only
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                i += size
            except torch.cuda.OutOfMemoryError:
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                if size == 1:
                    raise
                size = max(1, size // 2)
        return results

    def _to_spans(self, text: str, raw: str) -> list[Span]:
        spans: list[Span] = []
        for span_str, cat_str in _parse_output(raw):
            try:
                cat = Category(cat_str)
            except ValueError:
                continue
            idx = text.find(span_str)
            if idx < 0:
                continue
            spans.append(
                Span(start=idx, end=idx + len(span_str), category=cat, source=self.name)
            )
        return spans

    def detect(self, text: str) -> list[Span]:
        raw = self._generate([_PROMPT.format(input=text[:3000])])[0]
        return self._to_spans(text, raw)

    def detect_batch(self, texts: list[str]) -> list[list[Span]]:
        prompts = [_PROMPT.format(input=t[:3000]) for t in texts]
        raws = self._generate(prompts)
        return [self._to_spans(t, r) for t, r in zip(texts, raws)]
