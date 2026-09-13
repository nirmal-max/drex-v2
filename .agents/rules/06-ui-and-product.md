# UI and Product Design Rule

## Directives
1. **Design Theme**: Blue forensic workstation styling (`#007AFF`, `#111827`, `#F5F5F7`, `#FFFFFF`) with crisp light technical grids and white evidence cards.
2. **Navigation**: 25 dedicated pages organized logically: Overview, Cases, Forensic Recovery, Carving, Fragment Recovery, Damaged Media, Hex Inspector, Device Intelligence, Sanitization Planner, Drive Eraser, File Eraser, Residue Analyzer, Verification, Audit Chain, Evidence Vault, Independent Verifier, Certificates, Reports, Validation Lab, Performance Lab, Backend Manager, Device Manager, Settings, Diagnostics, Judge Demo Flow.
3. **Responsive Async Threading**: Heavy I/O, device discovery, and recovery scans run on dedicated worker threads; UI remains non-blocking with live progress events (`EV_PROGRESS`, `EV_OP_COMPLETED`).
