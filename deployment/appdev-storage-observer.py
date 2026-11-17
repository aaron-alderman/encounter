#!/usr/bin/env python3
"""Publish allocated bytes for fixed AppDev storage areas without reading file contents."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile


def measure(directory, *, children=False):
    if not directory.is_dir():
        return {}, True
    depth = "--max-depth=1" if children else "--summarize"
    result = subprocess.run(
        ["/usr/bin/du", "--one-file-system", "--block-size=1", depth, "--", directory],
        text=True, capture_output=True, check=False, timeout=60,
    )
    totals = {}
    for line in result.stdout.splitlines():
        size, separator, path = line.partition("\t")
        if separator and size.isdecimal():
            totals[Path(path)] = int(size)
    return totals, result.returncode != 0


def main():
    workspace = Path(os.environ["APPDEV_OBSERVED_WORKSPACE"])
    state = Path(os.environ["STATE_DIRECTORY"])
    targets = {
        "builds": [workspace / "builds"],
        "state": [workspace / "state"],
        "evidence": [workspace / name for name in ("receipts", "logs", "jobs")],
        "environment": [workspace / "env"],
        "copies": [workspace.parent.parent / "copies"],
        "releases": [Path("/srv/encounter-apps")],
        "hosted": [Path("/srv/sourcery")],
        "logs": [Path("/var/log")],
    }

    def record(key, sizes, partial):
        areas[key] = {"bytes": sum(sizes) if sizes else None, "partial": partial}

    areas = {}
    projects = workspace / "projects"
    project_groups = {
        "rollouts": ["release-rollouts"],
        "apps": ["applications"],
        "platform": ["encounter-core", "encounter-platform"],
        "os": ["sourcery-os", "sourcery-os-quickbasic"],
        "media": ["media", "game-migration"],
        "research": ["research"],
    }
    project_sizes, partial = measure(projects, children=True)
    allocated = 0
    for key, names in project_groups.items():
        sizes = [project_sizes[projects / name] for name in names if projects / name in project_sizes]
        record(key, sizes, partial or len(sizes) != len(names))
        allocated += sum(sizes)
    remaining = [max(0, project_sizes[projects] - allocated)] if projects in project_sizes else []
    record("projects", remaining, partial)
    for key, directories in targets.items():
        sizes = []
        partial = False
        for directory in directories:
            result, incomplete = measure(directory)
            partial |= incomplete or directory not in result
            if directory in result:
                sizes.append(result[directory])
        record(key, sizes, partial)

    observation = {"sampledAt": datetime.now(timezone.utc).isoformat(), "areas": areas}
    with tempfile.NamedTemporaryFile(mode="w", dir=state, delete=False) as pending:
        temporary = Path(pending.name)
        try:
            json.dump(observation, pending)
            pending.flush()
            os.fchmod(pending.fileno(), 0o644)
            temporary.replace(state / "storage.json")
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
