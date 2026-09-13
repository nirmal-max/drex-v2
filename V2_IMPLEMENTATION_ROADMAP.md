# DREX v2 — Implementation Roadmap

## Mission

Evolve DREX from a working 25-method prototype into a defensible, measurable unified platform for secure sanitization and digital forensic recovery.

## Engineering principle

> Prefer truthful capability reporting, independently verifiable outcomes, and measured performance over a larger list of claimed methods.

## Baseline

The current repository contains 25 methods across drive erasure, file/folder erasure, and recovery. The authoritative machine-readable status currently records 11 real-execution passes, 5 decision-engine passes, 2 synthetic passes, 2 partial methods, 4 unsupported methods, and 1 backend-unavailable method. It also records 81/81 regression tests passing. Do not describe decision, synthetic, partial, unsupported, or unavailable methods as physically executed.

## Phase 0 — Baseline integrity

- Reconcile README test count with the authoritative validation artifacts.
- Establish one machine-readable capability/status schema.
- Separate execution, verification, evidence, and audit status.
- Preserve existing working behavior with regression tests before major changes.
- Record backend versions, hashes, licenses, and installation locations.

## Phase 1 — Capability Truth Engine

Every method receives a machine-readable contract:

- method_id and version
- target type
- supported OS/filesystem/media/bus
- required privileges
- required backend
- hardware qualification requirements
- execution status
- verification status
- evidence status
- audit status
- safety constraints
- explicit limitations

Device qualification should capture model, serial, firmware when available, bus/interface, media type, capacity, sector sizes, partitioning, filesystem, mounted/boot state, read-only state, passthrough capability, and relevant ATA/NVMe/sanitize capabilities.

Lifecycle:

`DISCOVER → QUALIFY → PLAN → CONFIRM → EXECUTE → VERIFY → EVIDENCE → AUDIT → REPORT`

## Phase 2 — Sanitization hardening

- Harden drive/file/folder target validation.
- Add stronger hardware-aware method selection.
- Implement safe native ATA/NVMe pathways only when the hardware capability is positively qualified.
- Improve verification depth and failure handling.
- Never claim controller-level sanitization through an interface that cannot expose it.
- Add repeatable test-media validation for destructive operations.

## Phase 3 — Advanced recovery

- Integrate filesystem-aware recovery with raw carving.
- Add a native DREX carver for supported signatures.
- Add fragment detection and reconstruction.
- Add candidate deduplication and multi-engine result fusion.
- Add confidence scoring based on signature, structure, parser/open success, completeness, corruption, and provenance.
- Add folder/tree reconstruction.
- Add disk-image workflows.
- Add damaged-media acquisition through a qualified ddrescue backend.
- Add RAID/storage reconstruction through explicit backend capability detection.

## Phase 4 — Evidence and independent verification

Evidence package target:

- operation.json
- device.json
- method.json
- execution.json
- verification.json
- hashes.json
- audit.json
- certificate.json

Add an independent verifier capable of returning:

`VALID | TAMPERED | INCOMPLETE | UNSIGNED`

The verifier must not depend on the operational database or UI.

## Phase 5 — Validation laboratory

Use controlled ground-truth datasets:

`CREATE TEST DATA → RECORD GROUND TRUTH → DELETE/IMAGE → RECOVER → MEASURE → SANITIZE → RECOVER AGAIN → MEASURE → COMPARE → REPORT`

Track:

- precision
- recall
- recovery completeness
- fragment reconstruction success
- corruption rate
- false positives
- throughput
- latency
- verification success
- filesystem coverage
- hardware compatibility

## Phase 6 — Investigation-time optimization

Measure and optimize:

- device discovery
- filesystem metadata indexing
- bitmap/free-space acceleration
- carving throughput
- parallel recovery
- duplicate elimination
- candidate ranking
- evidence generation

Every performance improvement must be benchmarked against a baseline.

## Phase 7 — Operator dashboard

The UI should expose the truth of the backend rather than hiding limitations.

Primary workspaces:

1. Dashboard
2. Devices
3. Sanitization
4. Recovery
5. Evidence Vault
6. Validation Lab
7. Reports
8. System/Backend Health

Each operation should show target qualification, selected method, reason for selection, execution progress, verification result, evidence state, and limitations.

## Phase 8 — Compliance and documentation

Maintain versioned:

- technical architecture
- threat model
- user manual
- validation methodology
- performance report
- limitations register
- third-party notices
- compliance mapping
- hardware qualification guide
- evidence/certificate specification

## Definition of done

A feature is not considered complete merely because code exists. It is complete only when its behavior is:

1. source-implemented,
2. safely executable in its supported environment,
3. independently verifiable where applicable,
4. covered by automated tests,
5. documented with limitations,
6. represented accurately in the capability/status registry, and
7. measurable in the validation lab when the feature affects recovery or sanitization performance.

## Immediate priority order

**P0:** baseline/status consistency → capability contracts → backend manager → independent verifier

**P1:** advanced carver → fragment reconstruction → recovery fusion → damaged-media backend

**P2:** verification depth → validation lab → performance instrumentation → compliance mapping

**P3:** dashboard redesign → packaging → final demonstration workflows
