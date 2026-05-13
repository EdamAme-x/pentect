"""Presidio-only baseline: replace all detected entities with <PRESIDIO_MASKED>."""
from __future__ import annotations


def _get_analyzer():
    from presidio_analyzer import AnalyzerEngine

    return AnalyzerEngine()


def mask_with_presidio(text: str) -> str:
    try:
        from presidio_anonymizer import AnonymizerEngine
        from presidio_anonymizer.entities import OperatorConfig
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("presidio-anonymizer not installed") from e

    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language="en")
    anonymizer = AnonymizerEngine()
    anon = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<PRESIDIO_MASKED>"})},
    )
    return anon.text
