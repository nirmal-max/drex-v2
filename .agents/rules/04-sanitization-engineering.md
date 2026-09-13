# Sanitization Engineering Rule

## Directives
1. **Standards Compliance**: All drive sanitization routines must explicitly declare compliance level (NIST SP 800-88 Rev. 2 Clear/Purge, DoD 5220.22-M, IEEE 2883).
2. **Media Awareness**: Differentiate magnetic rotational media (requiring multi-pass overwrite) from NVMe/SSD media (requiring cryptographic purge, block erase, and FTL awareness).
3. **Residue Elimination**: Target cluster slack, NTFS MFT residual filenames, VSS shadow copies (`kill_vss_shadows`), and temporary swap artifacts.
4. **Readback Verification**: Complete byte verification or pseudo-random entropy verification must run after every wipe pass.
