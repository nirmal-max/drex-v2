# Forensic Recovery Engineering Rule

## Directives
1. **Multi-Engine Pipeline**: Recovery flows must leverage TSK (`fls`, `icat`, `tsk_recover`) for structured filesystems and PhotoRec / pure-Python chunk carvers for unallocated blocks.
2. **5-Factor Confidence Scoring**:
   $$\text{Confidence} = 0.35 \times \text{SigMatch} + 0.25 \times \text{Structure} + 0.20 \times \text{Continuity} + 0.15 \times \text{Metadata} + 0.05 \times \text{Size}$$
3. **Fragment Reconstruction**: Handle out-of-order and non-contiguous file blocks using JPEG entropy-stream/MCU boundary decoding and ZIP central directory mapping.
4. **Read-Only Enclosure**: Source evidence files and disks are accessed strictly with `FILE_SHARE_READ` and write-blocker assertions.
