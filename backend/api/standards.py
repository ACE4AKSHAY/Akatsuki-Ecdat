"""Read-only access to the versioned standards and policy registry."""
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from backend.engine.standards import (
    candidates_for_path,
    get_entry,
    get_registry,
    registry_summary,
)

router = APIRouter(prefix="/standards", tags=["Standards"])


@router.get("")
def list_standards(
    path: Optional[str] = Query(None, description="Return candidates for a migration path"),
    family: Optional[str] = Query(None, description="Filter entries by family"),
    status: Optional[str] = Query(None, description="Filter entries by standards maturity"),
    q: Optional[str] = Query(None, description="Free-text search over names, aliases and standards"),
    complianceTarget: str = Query("NIST-general", description="NIST-general or CNSA2.0"),
):
    registry = get_registry()
    if path:
        candidates = candidates_for_path(path, complianceTarget)
        if not candidates:
            raise HTTPException(status_code=404, detail=f"Migration path '{path}' not found")
        return {"path": path, "complianceTarget": complianceTarget, "candidates": candidates}

    summary = registry_summary()
    entries = summary["entries"]
    if family:
        entries = [entry for entry in entries if entry["family"] == family]
    if status:
        entries = [entry for entry in entries if entry["status"] == status]
    if q:
        needle = q.lower()
        full = {entry["id"]: entry for entry in registry["entries"]}
        entries = [
            entry for entry in entries
            if needle in entry["displayName"].lower()
            or needle in entry["standard"].lower()
            or any(needle in alias.lower() for alias in full[entry["id"]].get("aliases", []))
        ]

    return {
        "registryVersion": summary["registryVersion"],
        "reviewedOn": summary["reviewedOn"],
        "complianceTarget": complianceTarget,
        "entries": entries,
        "migrationPaths": [
            {"id": item["id"], "label": item.get("label", item["id"]), "roles": item.get("roles", [])}
            for item in registry.get("migrationPaths", [])
        ],
    }


@router.get("/{entry_id}")
def get_standard(entry_id: str):
    entry = get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Standard entry '{entry_id}' not found")
    return entry
