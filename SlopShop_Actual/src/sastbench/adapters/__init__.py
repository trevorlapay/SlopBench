"""Ground truth adapters for benchmark datasets."""

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.adapters.bigvul import BigVulAdapter
from sastbench.adapters.castle import CastleAdapter
from sastbench.adapters.custom import CustomAdapter
from sastbench.adapters.cvefixes import CVEFixesAdapter
from sastbench.adapters.humaneval import HumanEvalAdapter
from sastbench.adapters.juliet import JulietAdapter
from sastbench.adapters.primevul import PrimeVulAdapter
from sastbench.adapters.sard import SardAdapter

ADAPTERS: dict[str, type[BenchmarkAdapter]] = {
    "juliet": JulietAdapter,
    "sard": SardAdapter,
    "primevul": PrimeVulAdapter,
    "bigvul": BigVulAdapter,
    "cvefixes": CVEFixesAdapter,
    "castle": CastleAdapter,
    "humaneval": HumanEvalAdapter,
    "custom": CustomAdapter,
}


def get_adapter(name: str) -> BenchmarkAdapter:
    """Get an adapter instance by benchmark name."""
    cls = ADAPTERS.get(name.lower())
    if cls is None:
        available = ", ".join(sorted(ADAPTERS.keys()))
        raise ValueError(f"Unknown benchmark '{name}'. Available: {available}")
    return cls()


def list_benchmarks() -> list[dict]:
    """List all available benchmarks with metadata."""
    return [cls().info() for cls in ADAPTERS.values()]


__all__ = [
    "ADAPTERS",
    "BenchmarkAdapter",
    "BigVulAdapter",
    "CastleAdapter",
    "CustomAdapter",
    "CVEFixesAdapter",
    "HumanEvalAdapter",
    "JulietAdapter",
    "PrimeVulAdapter",
    "SardAdapter",
    "get_adapter",
    "list_benchmarks",
]
