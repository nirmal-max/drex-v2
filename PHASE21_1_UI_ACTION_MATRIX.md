# DREX V2 — Phase 21.1 UI Action Matrix

| Screen / View | UI Element / Button | Action Triggered | Target API / Backend Route | Actual Execution Result | UI State Transition | Verified |
|:---|:---|:---|:---|:---|:---|:---:|
| **System Validation** | `[Filter Pills]` | Category filter | Client-side reactive filter | Filters 977 tests by category ($\sum = 977$) | Table rows update dynamically | `[x]` |
| **System Validation** | `[Search Input]` | Test name/marker search | Client-side search | Filters tests in real-time | Dynamic matching count & pagination | `[x]` |
| **System Validation** | `[Test Row Click]` | Open Drawer | Client-side test ledger lookup | Retrieves exact docstring, category, status | Drawer slides in with test metadata | `[x]` |
| **File/Folder Eraser** | `[📁 Browse File]` | Open Native Picker | `POST /api/dialog/pick-file` | Opens native Windows file selection dialog | Updates input value to real path | `[x]` |
| **File/Folder Eraser** | `[📁 Browse Folder]` | Open Native Picker | `POST /api/dialog/pick-folder` | Opens native Windows folder selection dialog | Updates input value to real path | `[x]` |
| **File/Folder Eraser** | `[Target Input Change]` | Debounced Inspect | `POST /api/dialog/inspect-target` | Validates path, size, preflight hash, tripwire | Displays Preflight Target Identity Card | `[x]` |
| **File/Folder Eraser** | `[⚡ Execute Secure Overwrite]` | Run Overwrite | `POST /api/sanitization/execute` | Anti-TOCTOU hash check + CSPRNG overwrite | Green verified badge + certificate button | `[x]` |
| **Forensic Recovery** | `[📁 Browse Image]` | Open File Dialog | `POST /api/dialog/pick-file` | Selects forensic disk image (`.img`, `.raw`, `.dd`) | Updates source path & preflight status | `[x]` |
| **Forensic Recovery** | `[⚡ Execute Forensic Scan]` | Start Recovery | `POST /api/recovery/scan` + Polling | Multi-stage polling state machine | Multi-step progress bar → Candidates table | `[x]` |
| **Fragment Recovery** | `[⚡ Execute Fragment Reconstruction]` | Reassemble | `POST /api/recovery/reconstruct` | Structural CRC + seam continuity + SHA-256 | Displays confidence, size, SHA-256 | `[x]` |
| **Hex Inspector** | `[Preset Dropdown]` | Load Preset | Client-side byte stream loader | Loads sample byte patterns & calculates $H$ | Updates hex decode table & entropy display | `[x]` |
| **Judge Demo** | `[✦ Execute Synthetic Proof (<60s)]` | Run Mode A | `POST /api/demo/flow` | Executes 6-step in-memory evaluation loop | Green checkmarks + verdict in console | `[x]` |
| **Judge Demo** | `[⚡ Execute Operational Demo]` | Run Mode B | `POST /api/demo/operational-flow` | Real disk fixture + carve + wipe + PDF cert | Telemetry stream + PDF download link | `[x]` |
| **Certificates** | `[📜 Download Forensic Certificate (PDF)]` | Download PDF | `GET /api/certificates/{id}/pdf` | Generates & streams valid PDF binary | Browser downloads genuine PDF cert | `[x]` |
| **Certificates** | `[🔍 Verify Certificate]` | Independent Verify | `POST /api/certificates/verify` | Validates hash chain, PDF hash, case binding | Tamper-evident verdict badge | `[x]` |
