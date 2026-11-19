"""Harvest Now, Decrypt Later (HNDL) assessment.

HNDL is a confidentiality-specific complement to Mosca's timing model. It is
never calculated for signature-only findings, and an unknown data lifetime
produces ``Unknown`` rather than a speculative Critical result.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from backend.engine.context import confidentiality_relevant

_QUANTUM_FACTOR = {"vulnerable": 1.0, "weakened": 0.5}
_EXPOSURE_FACTOR = {"external-facing": 1.0, "internal-only": 0.5}


def _tier(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 1.5:
        return "Critical"
    if score >= 1.0:
        return "High"
    if score >= 0.5:
        return "Medium"
    return "Low"


def assess_hndl(
    *,
    quantum_status: str,
    usage_context: str,
    exposure: str,
    shelf_life_years: Optional[float],
    z_years: float,
    is_confidentiality_role: Optional[bool] = None,
) -> Dict[str, Any]:
    """Return a transparent HNDL score with its factors and assumptions."""
    confidentiality_relevant_role = (
        confidentiality_relevant(usage_context)
        if is_confidentiality_role is None
        else is_confidentiality_role
    )

    if not confidentiality_relevant_role:
        return {
            "applicable": False,
            "tier": "NotApplicable",
            "score": None,
            "factors": {},
            "explanation": "HNDL does not apply to integrity or signature-only assets.",
            "assumptions": [],
        }

    if quantum_status not in _QUANTUM_FACTOR:
        return {
            "applicable": False,
            "tier": "NotApplicable",
            "score": None,
            "factors": {"quantumStatus": quantum_status},
            "explanation": "The asset is not quantum-vulnerable for confidentiality purposes.",
            "assumptions": [],
        }

    if not shelf_life_years or shelf_life_years <= 0 or not z_years or z_years <= 0:
        return {
            "applicable": True,
            "tier": "Unknown",
            "score": None,
            "factors": {"quantumStatus": quantum_status, "exposure": exposure},
            "explanation": "Confidentiality lifetime or threat timeline is unknown, so HNDL cannot be scored.",
            "assumptions": ["Supply the data confidentiality lifetime to score HNDL."],
        }

    quantum_factor = _QUANTUM_FACTOR[quantum_status]
    exposure_factor = _EXPOSURE_FACTOR.get(exposure, 0.75)
    lifetime_factor = min(shelf_life_years / z_years, 2.0)
    score = round(quantum_factor * exposure_factor * lifetime_factor, 3)

    assumptions = [
        f"Quantum factor {quantum_factor} for a {quantum_status} algorithm.",
        f"Exposure factor {exposure_factor} for {exposure or 'unknown exposure'}.",
        f"Lifetime factor capped at 2.0 from {shelf_life_years:g} years of confidentiality over a {z_years:g}-year threat timeline.",
    ]
    if exposure not in _EXPOSURE_FACTOR:
        assumptions.append("Exposure was not explicit; a neutral factor of 0.75 was used.")

    return {
        "applicable": True,
        "tier": _tier(score),
        "score": score,
        "factors": {
            "quantum": quantum_factor,
            "exposure": exposure_factor,
            "lifetimeRatio": round(lifetime_factor, 3),
        },
        "explanation": "Encrypted traffic or stored data can be captured now and decrypted after a relevant quantum computer exists.",
        "assumptions": assumptions,
    }
