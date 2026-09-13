# Security and Safety Policy

## Scope
Governs physical storage safety, OS disk protection, path sanitization, and administrative boundary enforcement.

## Mandatory Controls
1. **Physical Drive Protection**: Boot drives (`C:`, `/`, `/boot`), EFI system partitions, and swap files are locked from destructive overwrite.
2. **Read-Only Recovery Isolation**: Recovery scans must never write to the target evidence device. Destination directories must not reside within source trees.
3. **Path Traversal & Symlink Defense**: All file paths must be strictly canonicalized using `Path.resolve()` before opening handles.
4. **Elevation Management**: Require explicit administrative privilege checks before issuing low-level Win32 `DeviceIoControl` / `CreateFile` calls.
5. **Confirmation Phrases**: Destructive volume/drive wipes require exact phrase input in confirmation modals.
