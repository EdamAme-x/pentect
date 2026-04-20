"""Gemma 3 4B + QLoRA fine-tuning script (minimal).

Requires a GPU environment. Only the script is committed to the PoC repo.

Usage:
    python -m training.train_lora --config training/configs/gemma3_4b_lora.yaml
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


PROMPT_TEMPLATE = """### Instruction:
{instruction}

### Input:
{input}

### Output:
{output}"""


def _format(sample: dict) -> str:
    return PROMPT_TEMPLATE.format(
        instruction=sample["instruction"],
        input=sample["input"],
        output=sample["output"],
    )


def run(config_path: Path) -> None:
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    # training libraries are optional dependencies
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        Trainer,
        TrainingArguments,
        DataCollatorForLanguageModeling,
    )
    import torch

    samples: list[dict] = []
    with Path(cfg["dataset_path"]).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            s = json.loads(line)
            s["text"] = _format(s)
            samples.append(s)
    ds = Dataset.from_list(samples)

    tok = AutoTokenizer.from_pretrained(cfg["base_model"])
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    def _tokenize(batch):
        enc = tok(
            batch["text"],
            truncation=True,
            max_length=int(cfg["max_seq_length"]),
            padding="max_length",
        )
        # Gemma 3 expects token_type_ids during training (multimodal carry-over).
        # We only feed text here, so set them to zeros.
        enc["token_type_ids"] = [[0] * len(ids) for ids in enc["input_ids"]]
        return enc

    ds = ds.map(_tokenize, batched=True, remove_columns=ds.column_names)

    quant = None
    if cfg.get("load_in_4bit"):
        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )

    model = AutoModelForCausalLM.from_pretrained(
        cfg["base_model"],
        quantization_config=quant,
        device_map="auto",
    )
    model = prepare_model_for_kbit_training(model)

    lora = LoraConfig(
        r=cfg["lora_r"],
        lora_alpha=cfg["lora_alpha"],
        lora_dropout=cfg["lora_dropout"],
        target_modules=cfg["target_modules"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora)

    args = TrainingArguments(
        output_dir=cfg["output_dir"],
        num_train_epochs=int(cfg["epochs"]),
        per_device_train_batch_size=int(cfg["batch_size"]),
        gradient_accumulation_steps=int(cfg["grad_accum"]),
        learning_rate=float(cfg["learning_rate"]),
        seed=int(cfg["seed"]),
        logging_steps=20,
        save_strategy="epoch",
        bf16=True,
        report_to=[],
    )

    collator = DataCollatorForLanguageModeling(tok, mlm=False)
    trainer = Trainer(model=model, args=args, train_dataset=ds, data_collator=collator)
    trainer.train()
    trainer.save_model(cfg["output_dir"])
    tok.save_pretrained(cfg["output_dir"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, required=True)
    args = ap.parse_args()
    run(args.config)


if __name__ == "__main__":
    main()
