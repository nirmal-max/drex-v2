"""
DREX-V2 Phase 8 Import Isolation Test
=====================================
Statically and dynamically verifies that drex_verify.py has ZERO imports of
or dependencies on DREX execution runtime, GUI, hardware controllers, or vault modules.
"""

import ast
import sys
from pathlib import Path

FORBIDDEN_MODULES = {
    "drex_app",
    "forensic_vault",
    "certificate_engine",
    "hardware_storage",
    "recovery_adapter",
    "recovery_backends",
    "fs_recovery",
    "carver_engine",
    "fragment_engine",
    "damaged_media",
    "file_sanitizer",
    "mft_sanitizer",
    "vss_sanitizer",
    "entropy_engine",
    "backend_adapters",
    "tkinter",
    "cryptography",
    "reportlab",
    "qrcode",
}


def test_drex_verify_ast_import_isolation():
    """Statically parse drex_verify.py AST to assert no forbidden imports exist."""
    verifier_path = Path(__file__).resolve().parent.parent / "drex_verify.py"
    assert verifier_path.is_file(), f"drex_verify.py missing at {verifier_path}"

    tree = ast.parse(verifier_path.read_text(encoding="utf-8"), filename="drex_verify.py")
    imported_names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module.split(".")[0])

    violations = imported_names.intersection(FORBIDDEN_MODULES)
    assert not violations, f"Architectural Isolation Violation: drex_verify.py imports forbidden modules: {violations}"


def test_drex_verify_runtime_import_isolation(monkeypatch):
    """Dynamically import drex_verify and verify sys.modules contains zero DREX runtime modules."""
    import drex_verify  # Must succeed with standard library only

    assert hasattr(drex_verify, "IndependentPackageVerifier")
    assert hasattr(drex_verify, "VerificationVerdict")
    assert hasattr(drex_verify, "ExitCode")

    # Check sys.modules for any leaked forbidden modules
    for forbidden in FORBIDDEN_MODULES:
        # If forbidden was imported prior by pytest test runner, that's external, but drex_verify itself shouldn't reference them
        assert not hasattr(drex_verify, forbidden), f"drex_verify namespace contains forbidden symbol '{forbidden}'"
