# ECDAT migration playbook

How to read an ECDAT result and turn it into migration work. Written for the
engineer who owns the change and the reviewer who signs it off.

## 1. How to read an asset

Every asset in the inventory carries the same structure. The four fields that
drive the plan are the assessment, the strategy, the risk breakdown and the
evidence.

| Field | Meaning |
| --- | --- |
| `classicalStatus` | strong / acceptable / deprecated / broken today |
| `quantumStatus` | vulnerable / weakened / resistant against a quantum attacker |
| `standardsMaturity` | maturity of the governing standard |
| `usageContext` | what the artefact is actually used for |
| `readiness.tier` | how ready the artefact is to migrate |
| `hndl.tier` | harvest-now-decrypt-later exposure |
| `strategy.action` | the change to make |
| `strategy.phase` | when to make it |
| `strategy.candidates` | ranked options with fit, cost and constraints |
| `strategy.blockers` | what must be cleared first |
| `strategy.playbook` | ordered steps for the engineer |
| `moscaBreakdown` | X, Y, Z, r, tier and composite score |
| `evidence` | the raw signal, detection tier and source module |

The four assessment axes are independent on purpose. `AES-256-GCM` is
classically strong and quantum vulnerable; `SHA-256` is quantum resistant but
unusable for signature; `TLS 1.2` is acceptable but dated. A single
"is it safe" label would hide that.

## 2. Phases

`GET /roadmap/{scan_id}` groups the assets of a scan into four phases.

| Phase | Meaning |
| --- | --- |
| `immediate` | Broken or expiring today. Fix first, regardless of everything else. |
| `transition` | Quantum vulnerable or deprecated. Start planning and staging now. |
| `target` | The committed end state of the migration. |
| `monitor` | Retain with periodic review, or resolve an unknown. |

Within a phase, assets are ordered by risk tier, so the roadmap is already a
work queue.

## 3. Actions

| Action | When it applies | What it means in practice |
| --- | --- | --- |
| `replace` | The algorithm itself is the problem | Swap the primitive and its parameters |
| `reconfigure` | The mode, protocol or configuration is the problem | Keep the primitive, change how it is used (ECB → AEAD, TLS 1.0 → 1.3) |
| `hybridize` | The quantum transition needs a bridge | Run classical and post-quantum side by side during the transition |
| `reissue-certificate` | The certificate is expired, weak or mis-issued | Re-issue with a stronger key and profile, then re-deploy the chain |
| `deprecate` | The primitive has no defensible use | Remove the dependency, not just the call |
| `rotate` | A key or credential must be replaced | Replace the material and the consumers |
| `retain` | Already at the target state | Record the decision and review periodically |
| `monitor` | Unknown, or future-tracked | Set a review date and a trigger |
| `manual-review` | The assessment is not confident enough to recommend | A human decides |

## 4. The migration loop

1. **Scan.** Run ECDAT against the bounded snapshot of the target: source
   tree, repository, archive or container inventory.
2. **Triage the roadmap.** Read the `immediate` phase first. Broken
   configurations (ECB, MD5 for signatures, TLS 1.0/1.1) outrank everything
   else because they are exploitable now.
3. **Correct the context.** The usage context is inferred from the call site.
   When the inference is wrong, confirm it with
   `PATCH /assets/{id}/context`. The override re-plans the asset and writes
   an audit event, so the change is traceable.
4. **Clear the blockers.** Each strategy lists what has to be settled first:
   interoperability, data format, library support, certificate chain,
   client fleet.
5. **Execute the playbook.** The numbered steps in `strategy.playbook` are
   ordered for one engineer working through the change.
6. **Re-scan and compare.** The same scan id history and the exported CBOM
   give you a before/after comparison of asset counts and tiers.
7. **Record the decision.** Export the report; keep the audit trail with the
   change record.

## 5. Context overrides

An override is for one asset and always audited.

```http
PATCH /assets/{id}/context
Content-Type: application/json
X-Operator: alice@example.com

{
  "usageContext": "password-storage",
  "artifactType": "algorithm",
  "complianceTarget": "NIST-general",
  "protocol": "TLSv1.3",
  "operator": "alice@example.com"
}
```

Effects: the usage context is set to confirmed confidence `1.0`, the
readiness score and tier are recomputed, the migration action, phase,
candidates, blockers, assumptions and playbook are rebuilt, and an
`asset-context-override` audit event is written with the before and after
state. The actor comes from the `operator` field, falling back to the
`X-Operator` header.

Use overrides sparingly and with a reason. A confirmed context that
contradicts the code is a code defect.

## 6. Reading the risk numbers

Mosca's inequality is `r = (X + Y) / Z`.

- `X` — the estimated shelf life of the data protected by the artefact.
- `Y` — the estimated effort to migrate away from it.
- `Z` — the time until a cryptographically relevant quantum computer
  exists.

`r ≥ 1` means the migration cannot finish before the threat arrives. The
dashboard's timeline slider changes `Z` and re-scores the whole inventory
live, which is how you test "what if the threat lands sooner".

The composite risk score adds business criticality, exposure and key size on
top of the ratio, so a Critical-tier PII asset in an external-facing service
ranks above a Critical-tier internal asset with the same ratio.

## 7. Common situations

**Password storage.** Assets are routed to KDF candidates (Argon2id
preferred, bcrypt and scrypt acceptable alternatives). The playbook covers
parameter selection and a rehash-on-login migration path rather than a
straight algorithm swap.

**Legacy symmetric ciphers.** 3DES and DES are deprecated, not merely
quantum-vulnerable. The plan is to move to AES-GCM or ChaCha20-Poly1305 and
to re-encrypt data at rest.

**ECB mode.** ECB is treated as a reconfiguration, not an algorithm swap.
Leaking plaintext structure has nothing to do with key length, so the target
is an AEAD mode first.

**Certificates.** The asset carries the certificate facts: subject, issuer,
validity window, signature algorithm, key size and whether it is self-signed.
A self-signed certificate in an external-facing service is flagged for
issuance against a managed CA.

**TLS versions.** TLS 1.0 and 1.1 are deprecated and are `immediate` work.
TLS 1.2 is acceptable; TLS 1.3 is the target.

**Quantum-vulnerable asymmetric primitives.** RSA and ECDSA key establishment
is bridged with a hybrid construction during the transition window, and the
roadmap marks the committed end state separately from the bridge.

## 8. What ECDAT does not decide

ECDAT does not execute your code, does not measure your real data lifetime,
and cannot see a primitive used through a wrapper library it does not
recognise. Every finding, tier and recommendation is evidence for a human
decision, not the decision itself. The operator override exists precisely
because the automated context is sometimes wrong.
