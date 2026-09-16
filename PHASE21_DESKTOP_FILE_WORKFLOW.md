# DREX V2 — PHASE 21 REAL DESKTOP WORKFLOW & ANTI-TOCTOU ARCHITECTURE
**Authoritative Baseline:** `fbad09d`  
**Execution Environment:** Windows 11 (AMD64)  
**Date:** September 16, 2026  

---

## 1. Zero-Dependency Native Desktop Dialogs

Standard browser file input elements (`<input type="file">`) are restricted by web security sandboxes to returning only synthetic relative filenames (e.g. `document.docx`), stripping real Windows drive roots and folder paths (`D:\ForensicData\...`).

To provide genuine forensic desktop capability without introducing heavy third-party dependencies, DREX V2 utilizes Python's built-in `tkinter.filedialog` executed in a background thread via `asyncio.to_thread`:

```python
def _ask_open_file_dialog_sync(title="Select Target File", initial_dir=None, file_types=None) -> str:
    """Execute native Tkinter file picker dialog in background thread."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            kwargs = {"title": title}
            if initial_dir and os.path.exists(initial_dir):
                kwargs["initialdir"] = initial_dir
            if file_types:
                kwargs["filetypes"] = file_types
            path = filedialog.askopenfilename(**kwargs)
            return path or ""
        finally:
            root.destroy()
    except Exception:
        return ""
```

---

## 2. Live Target Metadata & Preflight Inspection

When a target is selected via native dialog or typed into the path input, DREX instantly executes `POST /api/dialog/inspect-target`, inspecting:

| Metadata Field | Extraction Technique | Forensic Purpose |
| :--- | :--- | :--- |
| **`path`** | Absolute Windows Path | Exact disk target identity (`D:\...`) |
| **`type`** | `FILE` / `FOLDER` / `DEVICE` | Determines overwrite strategy |
| **`file_count`** | Recursive Directory Walk | Quantifies scope of recursive erasure |
| **`total_size`** | `os.path.getsize()` / Sum | Verifies exact byte coverage |
| **`readable`** | `os.access(R_OK)` | Verifies process read permissions |
| **`protected`** | `DeviceIntelligenceEngine.is_system_drive()` | OS boot tripwire enforcement |
| **`filesystem`** | Volume extent probe (`NTFS`, `FAT32`) | Cluster alignment detection |
| **`preflight_hash`** | Initial 64KB SHA-256 Digest | **Anti-TOCTOU baseline hash** |

---

## 3. Anti-TOCTOU (Time-of-Check to Time-of-Use) Security Guard

### 3.1 The Vulnerability
In high-security forensic environments, an attacker or concurrent process could substitute or modify a file between the moment the investigator reviews the preflight metadata and the moment the destructive overwrite is executed.

### 3.2 The Enforcement
When the user clicks `[Execute Secure Overwrite]`, the frontend transmits the recorded `preflight_identity` hash. The server re-inspects the file on disk immediately before taking the destructive lock:

```python
if req.preflight_identity:
    target_meta = inspect_target_metadata(req.target_path)
    if target_meta.get("exists") and target_meta.get("preflight_hash"):
        if target_meta["preflight_hash"] != req.preflight_identity:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"TOCTOU VIOLATION: Target file '{req.target_path}' was modified after preflight inspection. Operation aborted.",
            )
```

If the file was tampered with, modified, or swapped, the operation is **immediately aborted with HTTP 409 Conflict**, preventing accidental or malicious evidence corruption.
