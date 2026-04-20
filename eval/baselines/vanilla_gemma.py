"""Vanilla Gemma 3 4B baseline (no fine-tuning, prompt-only).

Env vars:
  PENTECT_VANILLA_MODEL  base model id (default: google/gemma-3-4b-it)
  PENTECT_VANILLA_4BIT   "1" to load in 4-bit (default: 1)
  PENTECT_VANILLA_MAX_TOK  max_new_tokens (default: 512)
"""
from __future__ import annotations

import os

_PROMPT = """You are a data masking tool. Replace sensitive values (tokens, credentials,
internal hostnames, internal IPs, emails, personal names, user IDs) with the literal
string <MASKED>. Preserve non-sensitive text exactly. Output the masked text only.

Input:
{input}

Masked:
"""


def _load_model():
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        import torch
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("transformers not installed") from e

    model_id = os.environ.get("PENTECT_VANILLA_MODEL", "google/gemma-3-4b-it")
    use_4bit = os.environ.get("PENTECT_VANILLA_4BIT", "1").lower() in {"1", "true"}

    tok = AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "left"

    kwargs: dict = {"device_map": "auto"}
    if use_4bit:
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
    else:
        kwargs["dtype"] = torch.bfloat16

    model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
    model.eval()
    return tok, model


_cache: dict = {}


def mask_with_vanilla_gemma(text: str) -> str:
    import torch

    if "tok" not in _cache:
        _cache["tok"], _cache["model"] = _load_model()
    tok, model = _cache["tok"], _cache["model"]
    max_new = int(os.environ.get("PENTECT_VANILLA_MAX_TOK", "512"))

    prompt = _PROMPT.format(input=text[:4000])
    inputs = tok(prompt, return_tensors="pt", truncation=True, max_length=2048).to(model.device)
    with torch.inference_mode():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new,
            do_sample=False,
            pad_token_id=tok.pad_token_id,
            use_cache=True,
        )
    prompt_len = inputs["input_ids"].shape[1]
    generated = tok.decode(out[0][prompt_len:], skip_special_tokens=True)
    return generated.strip()
