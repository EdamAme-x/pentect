"""Gemma-as-second-opinion auditor.

Used in hybrid mode: a primary detector (Privacy Filter FT) runs first; this
auditor is asked **only** "did the primary miss anything?" -- a short, cheap
generation task vs. the full span enumeration the LLMDetector does.

Output format the model is asked to produce:

    []                                      # nothing missed
    [{"span": "...", "category": "..."}]    # one or more missed spans

Hard-capped at ~64 new tokens so this stays cheap even on weak GPUs. If the
primary already covers the entry well, this collapses to two-token "[]" outputs.
"""
from __future__ import annotations

import json as _json
import os
import re

from engine.categories import Category
from engine.detectors.base import Span


_PROMPT = """### Instruction:
Below is a text and a list of sensitive substrings already detected in it.
Your job: list ONLY substrings that were MISSED. If nothing is missed, output [].
Each item must be {{"span": "exact substring", "category": one of CREDENTIAL, INTERNAL_URL, INTERNAL_IP, PII_EMAIL, PII_NAME, USER_ID}}.
Do not repeat already-detected substrings. Do not invent. Output a JSON array only.

### Text:
{text}

### Already detected:
{detected}

### Missed:
"""


_OBJ_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


def _parse_audit(raw: str) -> list[tuple[str, str]]:
    for marker in ("### Instruction", "### Text", "### Already", "### Missed", "\n### "):
        idx = raw.find(marker, 1)
        if idx > 0:
            raw = raw[:idx]
            break

    start = raw.find("[")
    if start < 0:
        return []
    depth = 0
    candidate: str | None = None
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
        candidate = raw[start:] + "]"

    items: list[dict] = []
    try:
        arr = _json.loads(candidate)
        if isinstance(arr, list):
            items = [x for x in arr if isinstance(x, dict)]
    except Exception:  # noqa: BLE001
        for m in _OBJ_RE.finditer(candidate):
            try:
                obj = _json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(obj, dict):
                items.append(obj)

    out: list[tuple[str, str]] = []
    for it in items:
        span = it.get("span")
        cat = it.get("category")
        if isinstance(span, str) and isinstance(cat, str):
            out.append((span, cat))
    return out


class LLMAuditor:
    """Wraps a fine-tuned Gemma to act as a 'second opinion' on missed spans.

    NOT a Detector -- used only inside HybridDetector. Call audit_batch() with
    (text, detected_spans) pairs and get back the missed spans the primary
    detector should add.
    """

    name = "llm_audit"

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
        self._max_new_tokens = int(os.environ.get("PENTECT_AUDIT_MAX_TOK", "64"))
        self._micro_batch = int(os.environ.get("PENTECT_AUDIT_MICROBATCH", "8"))

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
        if adapter:
            from peft import PeftModel

            self._model = PeftModel.from_pretrained(self._model, adapter)
        self._model.eval()

    def _generate(self, prompts: list[str]) -> list[str]:
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

    @staticmethod
    def _format_detected(text: str, spans: list[Span]) -> str:
        if not spans:
            return "(none)"
        parts = []
        seen = set()
        for sp in spans:
            val = text[sp.start:sp.end]
            key = (val, sp.category.value)
            if key in seen:
                continue
            seen.add(key)
            parts.append(f"- {sp.category.value}: {val}")
        return "\n".join(parts) if parts else "(none)"

    def _to_spans(self, text: str, raw: str, already: set[str]) -> list[Span]:
        out: list[Span] = []
        for span_str, cat_str in _parse_audit(raw):
            if span_str in already:
                continue
            try:
                cat = Category(cat_str)
            except ValueError:
                continue
            idx = text.find(span_str)
            if idx < 0:
                continue
            out.append(Span(start=idx, end=idx + len(span_str), category=cat, source=self.name))
        return out

    def audit_batch(self, texts: list[str], detected_per_text: list[list[Span]]) -> list[list[Span]]:
        prompts = []
        already_per: list[set[str]] = []
        for t, spans in zip(texts, detected_per_text):
            already = {t[sp.start:sp.end] for sp in spans}
            already_per.append(already)
            prompts.append(_PROMPT.format(text=t[:3000], detected=self._format_detected(t, spans)))
        raws = self._generate(prompts)
        return [
            self._to_spans(t, r, a)
            for t, r, a in zip(texts, raws, already_per)
        ]
