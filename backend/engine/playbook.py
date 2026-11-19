"""Migration playbook templates (M6).

Playbooks describe a staged, reversible migration. They are guidance for a
human operator: ECDAT never executes these steps.
"""
from __future__ import annotations

from typing import Any, Dict, List

_Step = Dict[str, Any]


def _step(
    order: int,
    phase: str,
    action: str,
    owner_role: str,
    evidence: str,
    rollback: str,
    blocking: bool = False,
) -> _Step:
    return {
        "order": order,
        "phase": phase,
        "action": action,
        "ownerRole": owner_role,
        "evidence": evidence,
        "rollback": rollback,
        "blocking": blocking,
    }


def _password_storage(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", f"Inventory every place the legacy password hash is written or verified, including reset flows.", "Application security", "Complete call-graph of hash creation and verification.", "No production change yet; inventory is read-only.", True),
        _step(2, "prepare", f"Select {target} and record memory, iteration and salt parameters in configuration.", "Backend engineer", "Approved parameter set and library version.", "Keep the legacy verifier enabled for old hashes."),
        _step(3, "transition", "Add a versioned hash prefix and write new hashes with the new KDF.", "Backend engineer", "New hashes carry the new identifier; login succeeds.", "Route writes back to the legacy path by configuration flag."),
        _step(4, "transition", "Rehash on successful login; do not force a mass reset unless required.", "Backend engineer", "Rehash-on-login counter increases.", "Legacy verification remains available for unrehashed rows."),
        _step(5, "validate", "Run authentication, lockout and reset-flow regression tests.", "QA engineer", "Authentication test suite and staging login evidence.", "Feature flag returns the previous hashing implementation.", True),
        _step(6, "complete", "Remove the legacy hash verifier after the migration window closes.", "Platform engineer", "No legacy-prefix hashes remain in the store.", "Retain a read-only archive of the verifier for the agreed retention period."),
    ]


def _legacy_hash(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", "Confirm every use of the legacy digest and separate integrity, signature and password uses.", "Security engineer", "Usage inventory with file and call evidence.", "No change; the legacy digest remains for verification.", True),
        _step(2, "transition", f"Write new digests with {target}; dual-read old and new values during rollout.", "Backend engineer", "Dual-read comparisons match expected values.", "Keep a read-only legacy verification path."),
        _step(3, "transition", "Regenerate stored digests where the data permits, starting with the highest-sensitivity records.", "Data engineer", "Backfill report with success and failure counts.", "Pause the backfill; old values remain untouched."),
        _step(4, "validate", "Test signature or integrity verification against known-good vectors.", "QA engineer", "Test vectors pass for both legacy and new values.", "Re-enable the legacy-only path per service."),
        _step(5, "complete", "Remove legacy verification and document the retirement date.", "Platform engineer", "No remaining legacy-only consumers.", "Retain the previous release artifact for rollback."),
    ]


def _legacy_symmetric(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", "Inventory encrypted fields, data volumes, key custody and every writer and reader.", "Security engineer", "Complete encryption map with owners.", "No change; retain existing ciphertext.", True),
        _step(2, "prepare", f"Provision key-management support for {target} and confirm nonce handling.", "Platform engineer", "Key policy and AEAD nonce rules reviewed.", "Keep the legacy key active for decryption."),
        _step(3, "transition", "Enable dual-read: decrypt legacy ciphertext and write new ciphertext in the target format.", "Backend engineer", "Mixed-read staging test passes.", "Configuration flag restores legacy writes."),
        _step(4, "transition", "Re-encrypt stored data in batches with progress checkpoints.", "Data engineer", "Batch job report with counts and failures.", "Resume from the last checkpoint; legacy copies remain."),
        _step(5, "validate", "Verify integrity checks, large payloads and failure handling.", "QA engineer", "Integration tests cover tampering and truncation.", "Roll back the writer flag and keep both keys."),
        _step(6, "complete", "Retire the legacy key and cipher after the retention window.", "Platform engineer", "No legacy ciphertext remains.", "Archive the retired key under the key-retention policy."),
    ]


def _key_establishment(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", "Map every TLS endpoint, client population, gateway and library version that performs key establishment.", "Platform engineer", "Endpoint and client inventory with versions.", "No production change.", True),
        _step(2, "prepare", f"Confirm library support for {target} and enable it in a staging environment.", "Platform engineer", "Staging handshake negotiates the target group.", "Disable the new group; the classical group remains enabled."),
        _step(3, "transition", "Enable the hybrid or PQ group alongside the classical group and canary a small traffic slice.", "SRE", "Canary success rate and handshake latency within threshold.", "Remove the new group from the preference list.", True),
        _step(4, "transition", "Expand the rollout by service tier while monitoring handshake failures and record sizes.", "SRE", "Dashboards show stable error rate and latency.", "Roll back per service with the previous configuration."),
        _step(5, "validate", "Test legacy clients, constrained devices and middleboxes explicitly.", "QA engineer", "Compatibility matrix with pass and fail evidence.", "Keep the classical fallback during the compatibility window.", True),
        _step(6, "complete", "Make the target group mandatory and remove the vulnerable-only configuration.", "Security engineer", "Policy check confirms the target group is required.", "Restore the previous configuration from version control."),
    ]


def _signature(target: str, firmware: bool = False) -> List[_Step]:
    owner = "Firmware engineer" if firmware else "Security engineer"
    return [
        _step(1, "prepare", "Inventory signing keys, verifiers, trust stores, artifact formats and rotation ownership.", owner, "Signing and verification map with key owners.", "No change; existing signatures remain valid.", True),
        _step(2, "prepare", f"Confirm {target} support in the signing library and in every verifier, including size limits.", "Platform engineer", "Staging signature verifies on all supported platforms.", "Keep the existing signer available."),
        _step(3, "transition", "Introduce dual signing or a new key identifier so old and new artifacts can be verified.", owner, "Verifiers accept both formats during the transition.", "Disable the new signer and continue with the legacy key."),
        _step(4, "transition", "Rotate to the new signing key and publish the updated trust material.", "Security engineer", "Trust-store update is distributed and verified.", "Restore the previous trust material from backup.", True),
        _step(5, "validate", "Verify artifacts on every target platform and record signature size impact.", "QA engineer", "Cross-platform verification evidence.", "Keep dual verification enabled."),
        _step(6, "complete", "Retire the vulnerable signing key after the artifact retention window.", "Security engineer", "No artifacts require the legacy verifier.", "Retain archived verification material for audit."),
    ]


def _certificate(target: str, facts: Dict[str, Any] | None = None) -> List[_Step]:
    facts = facts or {}
    renewal = facts.get("notAfter")
    renewal_text = f" Plan the change for the renewal window ending {renewal}." if renewal else ""
    return [
        _step(1, "prepare", "Identify the certificate role, issuer, chain, trust stores and every service that loads it.", "PKI engineer", "Certificate inventory with dependent configuration evidence.", "No change to the current certificate.", True),
        _step(2, "prepare", f"Confirm certificate-authority support for {target} and client/chain size limits.{renewal_text}", "PKI engineer", "CA and client compatibility statement.", "Continue with the existing certificate."),
        _step(3, "transition", "Request a parallel certificate and install it on a canary service.", "PKI engineer", "Canary serves the new chain successfully.", "Restore the previous certificate and key."),
        _step(4, "transition", "Update trust stores and configuration references, then expand the rollout.", "Platform engineer", "All referencing services use the new certificate.", "Revert configuration and trust-store change.", True),
        _step(5, "validate", "Test client compatibility, chain validation and expiry monitoring.", "QA engineer", "Client matrix and expiry alarm evidence.", "Keep the old certificate valid until validation completes."),
        _step(6, "complete", "Revoke or retire the old certificate at the planned expiry boundary.", "PKI engineer", "Old certificate is no longer referenced.", "Restore from the PKI backup if a dependency is missed."),
    ]


def _protocol(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", "Inventory protocol versions, cipher suites and clients per endpoint.", "Platform engineer", "Configuration inventory with versions.", "No change.", True),
        _step(2, "prepare", f"Stage {target} with a modern cipher policy and verify certificate compatibility.", "Platform engineer", "Staging negotiation test passes.", "Restore the previous configuration."),
        _step(3, "transition", "Disable deprecated protocol versions for the canary endpoint.", "SRE", "No deprecated-version handshakes in canary logs.", "Re-enable the previous protocol list.", True),
        _step(4, "validate", "Test legacy clients and document accepted exceptions with an owner and end date.", "Security engineer", "Exception register with expiry dates.", "Re-enable the exception endpoint configuration."),
        _step(5, "complete", "Apply the policy to all endpoints and add a configuration regression check.", "Security engineer", "Policy check passes in CI.", "Revert the policy commit."),
    ]


def _review(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", "Confirm the algorithm, its role, and the owning service before planning a change.", "Security engineer", "Reviewed finding with a named owner and use case.", "No change until the review completes.", True),
        _step(2, "prepare", "Verify library/provider version and whether the proposed target is supported.", "Platform engineer", "Version and capability evidence.", "No change; record the blocker."),
        _step(3, "validate", "Run a small compatibility test if the use case is confirmed.", "QA engineer", "Test result recorded against the finding.", "Abandon the candidate and revisit at the next review."),
        _step(4, "complete", "Record the decision (retain, replace or defer) with its rationale and review date.", "Security engineer", "Decision note linked to the asset.", "Reopen the finding if the context changes."),
    ]


def _retain(target: str) -> List[_Step]:
    return [
        _step(1, "prepare", "Confirm the algorithm, key size and mode match the approved configuration.", "Security engineer", "Configuration evidence reviewed.", "No change required.", False),
        _step(2, "validate", "Schedule a periodic review and monitor library advisories.", "Platform engineer", "Review date and advisory subscription recorded.", "Reopen the finding if an advisory changes the posture.", False),
    ]


def build_playbook(
    template_id: str,
    target_label: str,
    blockers: List[str] | None = None,
    certificate_facts: Dict[str, Any] | None = None,
) -> List[_Step]:
    """Return ordered playbook steps for a migration template."""
    obstacles = list(blockers or [])

    if template_id == "password-storage":
        steps = _password_storage(target_label)
    elif template_id == "legacy-hash":
        steps = _legacy_hash(target_label)
    elif template_id == "legacy-symmetric":
        steps = _legacy_symmetric(target_label)
    elif template_id == "key-establishment":
        steps = _key_establishment(target_label)
    elif template_id == "firmware-signature":
        steps = _signature(target_label, firmware=True)
    elif template_id == "signature":
        steps = _signature(target_label)
    elif template_id == "certificate":
        steps = _certificate(target_label, certificate_facts)
    elif template_id == "protocol":
        steps = _protocol(target_label)
    elif template_id == "retain":
        steps = _retain(target_label)
    else:
        steps = _review(target_label)

    for step in steps:
        if obstacles and step["blocking"]:
            step["blockers"] = obstacles
    return steps
