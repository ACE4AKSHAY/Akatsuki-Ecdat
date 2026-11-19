"""Guards the shape of the standards registry policy data."""
from __future__ import annotations

import pytest

from backend.engine.standards import (
    candidate_view,
    candidates_for_path,
    get_registry,
    iter_entries,
    registry_summary,
    resolve_entry,
    validate_registry,
)


def test_registry_has_no_structural_defects():
    assert validate_registry() == []


def test_registry_declares_version_and_review_date():
    registry = get_registry()
    assert registry["registryVersion"]
    assert registry["reviewedOn"]


def test_every_entry_resolves_by_alias():
    for entry in iter_entries():
        resolved = resolve_entry(entry["id"])
        assert resolved is not None, entry["id"]
        assert resolved["id"] == entry["id"]
        for alias in entry.get("aliases", []):
            by_alias = resolve_entry(alias)
            assert by_alias is not None, alias
            assert by_alias["id"] == entry["id"], alias


def test_registry_summary_counts_match_entries():
    summary = registry_summary()
    assert summary["entryCount"] == len(list(iter_entries()))


def test_candidate_view_exposes_action_and_standard():
    for entry in iter_entries():
        view = candidate_view(entry["id"])
        assert view is not None, entry["id"]
        assert view["action"], entry["id"]
        assert view["standard"], entry["id"]


@pytest.mark.parametrize(
    "path_id",
    ["password-storage", "legacy-symmetric", "key-establishment", "certificate"],
)
def test_known_migration_paths_resolve(path_id):
    candidates = candidates_for_path(path_id)
    assert candidates
    assert all(candidate["id"] for candidate in candidates)


def test_every_migration_path_candidate_is_ranked():
    registry = get_registry()
    for path in registry["migrationPaths"]:
        candidates = candidates_for_path(path["id"])
        assert len(candidates) == len(path["candidates"]), path["id"]
