"""FastAPI server exposing /api/mask"""
from __future__ import annotations

import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from engine.core import PentectEngine


app = FastAPI(title="Pentect PoC")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


_VALID_BACKENDS = ("rule", "gemma", "opf_pf", "hybrid")


def _default_backend() -> str:
    env = os.environ.get("PENTECT_DETECTOR_BACKEND")
    if env in _VALID_BACKENDS:
        return env
    if os.environ.get("PENTECT_USE_LLM", "").lower() in {"1", "true"}:
        return "gemma"
    return "rule"


_use_verifier = os.environ.get("PENTECT_USE_VERIFIER", "").lower() in {"1", "true"}

# Lazy engine cache: each backend loads its own (potentially heavy) model only
# the first time it's asked for. Multiple requests share the cached instance.
_engine_cache: dict[str, PentectEngine] = {}
_engine_lock = threading.Lock()


def _get_engine(backend: str) -> PentectEngine:
    with _engine_lock:
        eng = _engine_cache.get(backend)
        if eng is None:
            eng = PentectEngine(use_verifier=_use_verifier, backend=backend)
            _engine_cache[backend] = eng
        return eng


# Pre-warm the default backend so the first /api/mask isn't slow.
_get_engine(_default_backend())


class MaskRequest(BaseModel):
    text: str
    is_har: bool = True
    backend: str | None = None  # one of _VALID_BACKENDS; defaults to env


class MaskResponse(BaseModel):
    masked_text: str
    map: dict
    summary: dict
    verifier: dict | None = None
    backend: str


def _looks_like_har(text: str) -> bool:
    """Heuristic: does this body look like a HAR JSON?

    The lenient HAR loader will happily turn any input into an empty
    {"log": {"entries": []}}, which silently produces masked=0 for plain
    text inputs. Detect HAR-ish shapes here so plain text falls through
    to mask_text instead.
    """
    head = text.lstrip()[:1024]
    if not head.startswith("{"):
        return False
    return '"log"' in head or '"entries"' in head or '"version"' in head


@app.post("/api/mask", response_model=MaskResponse)
def mask(req: MaskRequest) -> MaskResponse:
    backend = req.backend or _default_backend()
    if backend not in _VALID_BACKENDS:
        raise HTTPException(400, f"unknown backend {backend!r}; valid: {_VALID_BACKENDS}")
    engine = _get_engine(backend)
    # Auto-route by content shape, not by an `is_har` flag the UI never sets.
    if req.is_har and _looks_like_har(req.text):
        try:
            result = engine.mask_har(req.text)
        except Exception:  # noqa: BLE001
            result = engine.mask_text(req.text)
    else:
        result = engine.mask_text(req.text)
    return MaskResponse(
        masked_text=result.masked_text,
        map=result.map,
        summary=result.summary,
        verifier=result.verifier,
        backend=backend,
    )


@app.get("/api/health")
def health() -> dict:
    default = _default_backend()
    eng = _engine_cache.get(default)
    return {
        "status": "ok",
        "default_backend": default,
        "loaded_backends": sorted(_engine_cache.keys()),
        "available_backends": list(_VALID_BACKENDS),
        "detectors": [d.name for d in eng.detectors] if eng else [],
    }
