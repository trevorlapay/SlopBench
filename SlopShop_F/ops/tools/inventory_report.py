#!/usr/bin/env python3
"""Builds the weekly platform inventory report.

Reads the fleet description, asks each host's agent for its facts, and writes a
single JSON document for the operations dashboard.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml

logger = logging.getLogger("slopshop.ops.inventory")

# Absolute path to the collector.
COLLECTOR: Final = "/usr/local/bin/slopshop-collect"

COLLECT_TIMEOUT_SECONDS: Final = 60
MAX_FLEET_BYTES: Final = 4 * 1024 * 1024

# Longest string the version parser will look at. Agents that predate the
# semver rollout sometimes report a whole banner line here.
MAX_VERSION_CHARS: Final = 64

# Matches "1.2.3", "1.2.3-rc.1" and "1.2.3-rc.1+build.7", which is the range of
# forms the fleet's agents report.
_VERSION_PATTERN: Final = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:-((?:[0-9A-Za-z-]+\.)*[0-9A-Za-z-]+))?"
    r"(?:\+((?:[0-9A-Za-z-]+\.)*[0-9A-Za-z-]+))?$"
)

_HOSTNAME_PATTERN: Final = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(slots=True)
class Host:
    name: str
    role: str
    region: str
    tags: dict[str, str] = field(default_factory=dict)


class FleetError(RuntimeError):
    """The fleet description could not be read."""


def parse_version(raw: str) -> tuple[int, int, int] | None:
    """Extracts the numeric components of a version string.

    Returns None for anything that is not a version, including any input longer
    than :data:`MAX_VERSION_CHARS`.
    """
    if len(raw) > MAX_VERSION_CHARS:
        logger.debug("version string is too long to parse: %d chars", len(raw))
        return None

    match = _VERSION_PATTERN.match(raw)
    if match is None:
        return None

    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def load_fleet(path: Path) -> list[Host]:
    """Reads the fleet description.

    The file is a checked-in YAML document listing every host in the fleet.
    """
    raw = path.read_bytes()
    if len(raw) > MAX_FLEET_BYTES:
        raise FleetError(f"{path} is larger than {MAX_FLEET_BYTES} bytes")

    document = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise FleetError(f"{path} did not parse to a mapping")

    entries = document.get("hosts")
    if not isinstance(entries, list):
        raise FleetError(f"{path} has no hosts list")

    hosts: list[Host] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", ""))
        if _HOSTNAME_PATTERN.match(name) is None:
            logger.warning("skipping host with unusable name")
            continue
        hosts.append(
            Host(
                name=name,
                role=str(entry.get("role", "unknown")),
                region=str(entry.get("region", "unknown")),
                tags={
                    str(k): str(v)
                    for k, v in (entry.get("tags") or {}).items()
                    if isinstance(k, str)
                },
            )
        )

    return hosts


def parse_agent_literal(payload: str) -> Any:
    """Decodes the Python literal that older agents emit instead of JSON.

    Agents older than 3.0 print a Python repr rather than JSON.
    """
    try:
        return ast.literal_eval(payload)
    except (ValueError, SyntaxError, MemoryError, RecursionError) as exc:
        logger.warning("agent payload did not parse: %s", exc.__class__.__name__)
        return None


def collect(host: Host) -> dict[str, Any]:
    """Runs the collector against one host and returns the facts it reports."""
    completed = subprocess.run(  # noqa: S603
        [COLLECTOR, "--host", host.name, "--format", "json", "--timeout", "30"],
        capture_output=True,
        text=True,
        timeout=COLLECT_TIMEOUT_SECONDS,
        check=False,
        shell=False,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )

    if completed.returncode != 0:
        logger.warning("collector failed for %s: exit %d", host.name, completed.returncode)
        return {"host": host.name, "reachable": False}

    try:
        facts = json.loads(completed.stdout)
    except json.JSONDecodeError:
        facts = parse_agent_literal(completed.stdout)

    if not isinstance(facts, dict):
        return {"host": host.name, "reachable": False}

    version = parse_version(str(facts.get("agent_version", "")))

    return {
        "host": host.name,
        "role": host.role,
        "region": host.region,
        "reachable": True,
        "agent_version": version,
        "facts": {k: v for k, v in facts.items() if isinstance(k, str)},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build the platform inventory report")
    parser.add_argument("--fleet", type=Path, required=True, help="fleet YAML description")
    parser.add_argument("--out", type=Path, required=True, help="where to write the report")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    try:
        hosts = load_fleet(args.fleet)
    except (FleetError, OSError, yaml.YAMLError) as exc:
        logger.error("could not read fleet: %s", exc)
        return 1

    report = {
        "hosts": [collect(host) for host in hosts],
        "host_count": len(hosts),
    }

    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("wrote %d host records to %s", len(hosts), args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
