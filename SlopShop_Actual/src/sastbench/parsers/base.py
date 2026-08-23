"""Abstract base class for agent output parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sastbench.models import Finding


class BaseParser(ABC):
    """Base class that all format-specific parsers must implement."""

    @abstractmethod
    def parse(self, path: Path) -> list[Finding]:
        """Parse agent output file and return normalized findings."""

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        """Check if this parser can handle the given file."""
