"""Validate a CycloneDX CBOM file against the official 1.6 schema.

    python scripts/validate_cbom.py work/ecdat-ci-results/cbom.json

Exit 0 when the document is schema-valid; exit 1 with the problem list
otherwise. Used by CI and available locally.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.engine.cbom_validator import validate_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cbom_file", type=Path, help="Path to the CBOM JSON document")
    args = parser.parse_args()

    if not args.cbom_file.is_file():
        print(f"error: file not found: {args.cbom_file}", file=sys.stderr)
        return 1

    problems = validate_file(args.cbom_file)
    if not problems:
        print(f"{args.cbom_file}: valid CycloneDX 1.6 CBOM")
        return 0

    print(f"{args.cbom_file}: {len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
