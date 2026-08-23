"""Input parsers for agent output (SARIF, JSON, CSV)."""

from __future__ import annotations

import logging
from pathlib import Path

from sastbench.models import Finding
from sastbench.parsers.base import BaseParser
from sastbench.parsers.csv_parser import CsvParser
from sastbench.parsers.json_parser import JsonParser
from sastbench.parsers.sarif_parser import SarifParser

__all__ = [
    "BaseParser",
    "CsvParser",
    "JsonParser",
    "SarifParser",
    "detect_and_parse",
]

logger = logging.getLogger(__name__)

_PARSERS: list[BaseParser] = [
    SarifParser(),
    JsonParser(),
    CsvParser(),
]


def detect_and_parse(path: Path | str) -> list[Finding]:
    """Auto-detect file format and parse into findings.

    Tries each registered parser in order; returns results from the first
    parser that reports it can handle the file.

    Raises ``ValueError`` if no parser matches.
    """
    path = Path(path)
    for parser in _PARSERS:
        if parser.can_parse(path):
            logger.info("Using %s for %s", type(parser).__name__, path)
            return parser.parse(path)
    raise ValueError(f"No parser found for {path}")
