"""FastAPI server exposing /api/mask"""
from __future__ import annotations

import os

from fastapi import FastAPI
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

_use_llm = os.environ.get("PENTECT_USE_LLM", "").lower() in {"1", "true"}
_use_verifier = os.environ.get("PENTECT_USE_VERIFIER", "").lower() in {"1", "true"}
_engine = PentectEngine(use_llm=_use_llm, use_verifier=_use_verifier)


class MaskRequest(BaseModel):
    text: str
    is_har: bool = True


class MaskResponse(BaseModel):
    masked_text: str
    map: dict
    summary: dict
    verifier: dict | None = None


@app.post("/api/mask", response_model=MaskResponse)
def mask(req: MaskRequest) -> MaskResponse:
    if req.is_har:
        try:
            result = _engine.mask_har(req.text)
        except Exception:  # noqa: BLE001
            result = _engine.mask_text(req.text)
    else:
        result = _engine.mask_text(req.text)
    return MaskResponse(
        masked_text=result.masked_text,
        map=result.map,
        summary=result.summary,
        verifier=result.verifier,
    )


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "detectors": [d.name for d in _engine.detectors]}
