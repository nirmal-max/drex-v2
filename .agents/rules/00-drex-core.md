# DREX Core Engineering Rule

## Purpose
Establishes the supreme architectural and operational principles for the DREX-V2 platform.

## Principles
1. **Never Fabricate**: Never fabricate implementation, test results, benchmarks, device capabilities, or forensic evidence. If unverified, mark as `UNVERIFIED`.
2. **Real != Simulated**: Real execution against physical media/filesystems must never be confused with synthetic testbeds or decision engine simulations.
3. **Fail Closed**: In any ambiguous state, missing hardware capability, or destination collision, fail closed with an explicit error code.
4. **Execution != Verification**: Completing an I/O operation does not imply verification; explicit readback hash verification is required.
5. **No Blind Deletion**: Files may only be deleted if classified and approved in a formal manifest.
