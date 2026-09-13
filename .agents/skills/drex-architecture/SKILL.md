---
name: drex-architecture
description: Architecture overview, component boundaries, and state lifecycle for DREX-V2.
---

# DREX Architecture Skill

## When to Use
Use when designing, extending, or refactoring DREX-V2 core modules, dispatchers, backend adapters, or threading models.

## Core Modules
- `drex_app.py`: Main UI controller, page renderers, and background thread manager.
- `backend_adapters.py`: CLI command construction and output parsing for TSK, PhotoRec, ddrescue.
- `recovery_adapter.py`: Candidate normalization, safety checks, and dispatch orchestration.
- `recovery_backends.py`: Authoritative backend discovery and discovery status.

## Key Contracts
- Always return typed `OperationResult` records.
- Enforce strict separation between GUI main thread and background worker threads.
