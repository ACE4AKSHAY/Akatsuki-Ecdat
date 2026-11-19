"""Validate the standards registry policy data.

Exits non-zero when the registry contains structural defects so that a broken
policy file can never reach a release. Run directly or from CI:

    python scripts/validate_registry.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.engine.standards import (  # noqa: E402
    get_registry,
    validate_registry,
)


def main() -> int:
    problems = validate_registry()
    registry = get_registry()
    entries = registry.get("entries", [])
    print(
        f"registry version {registry.get('registryVersion')} "
        f"(reviewed {registry.get('reviewedOn')}), {len(entries)} entries"
    )
    if not problems:
        print("standards registry is valid")
        return 0
    print(f"standards registry has {len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
