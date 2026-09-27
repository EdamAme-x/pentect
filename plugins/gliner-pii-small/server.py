"""Offline GLiNER PII inspection over Pentect's native JSONL protocol."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys
import subprocess

SCHEMA = "pentect.plugin.v1"
MODEL = "knowledgator/gliner-pii-small-v1.0"
REVISION = "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e"
LABELS = {"name": ("PERSON", "pii"), "email address": ("EMAIL", "pii"),
          "phone number": ("PHONE", "pii"), "location address": ("ADDRESS", "pii"),
          "account number": ("ACCOUNT", "pii"), "password": ("SECRET", "secret"),
          "api key": ("SECRET", "secret")}
MAX_LINE = 1048576


def convert(text, entities):
    spans = []
    for entity in entities:
        start, end = entity["start"], entity["end"]
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
            raise ValueError("invalid model span")
        if text[start:end] != entity["text"]:
            raise ValueError("model span does not match source")
        label, category = LABELS[entity["label"]]
        spans.append({"start": len(text[:start].encode("utf-8")),
                      "end": len(text[:end].encode("utf-8")),
                      "label": label, "category": category, "confidence": "medium"})
    return spans


class Detector:
    def __init__(self, model, device="cpu", offline=True, threshold=0.3, revision=None):
        # Pentect strips user-name environment variables. PyTorch's default
        # Windows cache lookup otherwise calls the unavailable Unix pwd module.
        os.environ.setdefault("TORCHINDUCTOR_CACHE_DIR",
                              str(Path.home() / ".pentect" / "gliner-pii-small" / "torch-cache"))
        import torch
        from gliner import GLiNER
        torch.set_num_threads(4)
        self.model = GLiNER.from_pretrained(model, revision=revision,
            local_files_only=offline, load_tokenizer=True, trust_remote_code=False)
        self.model.to(device)
        self.model.eval()
        self.threshold = threshold

    def inspect(self, text):
        # Bound windows below the model's word limit, with overlap for boundaries.
        unique = {}
        for start in range(0, len(text), 750):
            window = text[start:start + 1000]
            offset = len(text[:start].encode("utf-8"))
            entities = self.model.predict_entities(window, list(LABELS), threshold=self.threshold)
            for span in convert(window, entities):
                span = dict(span, start=span["start"] + offset, end=span["end"] + offset)
                unique[(span["start"], span["end"], span["label"])] = span
            if len(unique) > 4096:
                raise ValueError("span limit exceeded")
        return [unique[key] for key in sorted(unique)]


def handle(detector, request):
    if not isinstance(request, dict) or request.get("schema") != SCHEMA or request.get("hook") != "inspect":
        raise ValueError("invalid request")
    if type(request.get("id")) is not int or not isinstance(request.get("payload"), dict):
        raise ValueError("invalid request")
    text = request["payload"].get("text")
    if not isinstance(text, str):
        raise ValueError("invalid text")
    return {"schema": SCHEMA, "id": request["id"], "type": "result", "action": "next",
            "spans": detector.inspect(text)}


def serve(detector):
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE + 1)
        if not line:
            return
        request_id = None
        try:
            if len(line) > MAX_LINE:
                raise ValueError("oversized request")
            request = json.loads(line)
            if isinstance(request, dict) and type(request.get("id")) is int:
                request_id = request["id"]
            with contextlib.redirect_stdout(sys.stderr):
                result = handle(detector, request)
        except Exception:
            result = {"schema": SCHEMA, "id": request_id, "type": "result", "action": "next",
                      "error": {"code": "inference_failed"}}
        print(json.dumps(result, ensure_ascii=False), flush=True)
        if len(line) > MAX_LINE:
            return


def main():
    root = Path.home() / ".pentect" / "gliner-pii-small"
    python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if python.is_file() and Path(sys.prefix).resolve() != python.parent.parent.resolve():
        if os.name == "nt":
            # Windows execv does not replace the process as on POSIX. Keep the
            # protocol parent's pipe lifetime tied to the managed interpreter.
            result = subprocess.run([str(python), str(Path(__file__).resolve()), *sys.argv[1:]],
                                    stdin=sys.stdin.buffer, stdout=sys.stdout.buffer,
                                    stderr=sys.stderr.buffer, creationflags=subprocess.CREATE_NO_WINDOW)
            raise SystemExit(result.returncode)
        os.execv(str(python), [str(python), str(Path(__file__).resolve()), *sys.argv[1:]])
    try:
        state = json.loads((root / "setup.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", default=state.get("checkpoint", str(root / "checkpoint")))
    parser.add_argument("--device", choices=["cpu", "cuda"], default=state.get("device", "cpu"))
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    try:
        with contextlib.redirect_stdout(sys.stderr):
            detector = Detector(args.checkpoint, device=args.device)
        serve(detector)
    except Exception:
        print("GLiNER initialization failed; run approved plugin setup.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
