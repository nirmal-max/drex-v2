"""
DREX-V2 Role-Based Access Control (RBAC) & Authentication Engine
================================================================
Provides strict role hierarchy, JWT issuance and verification,
and destructive-action permission gates.

Roles:
1. ADMIN: Full system administration, diagnostics, configuration.
2. FORENSIC_ANALYST: Evidence handling, deep carving, verification, notes.
3. INVESTIGATOR: Case overview, timeline queries, report generation.
4. OPERATOR: Sanitization execution, file shredding, device qualification.
5. AUDITOR: Read-only audit chain inspection, certificate verification.
6. JUDGE_DEMO: Deterministic safe sandbox evaluation and quick-action proof loop.

Zero unapproved dependencies (uses pyjwt, hashlib, time, uuid).
License: Apache 2.0.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import time
import uuid
from typing import Any, Dict, List, Optional, Set
import jwt

from drex_api_models import UserRole


import os

# ─── Configuration ────────────────────────────────────────────────────────────

_DEFAULT_DEV_SECRET = "DREX_FORENSIC_SECURE_TOKEN_KEY_9A7B3C1D8E2F"
JWT_SECRET = os.environ.get("DREX_JWT_SECRET", _DEFAULT_DEV_SECRET)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours for workstation convenience


def validate_jwt_secret_for_environment() -> None:
    """Enforce that production mode (DREX_ENV=production) refuses weak or default secrets."""
    is_prod = os.environ.get("DREX_ENV", "development").strip().lower() == "production"
    if is_prod:
        current_secret = os.environ.get("DREX_JWT_SECRET", "")
        if not current_secret or current_secret == _DEFAULT_DEV_SECRET or len(current_secret) < 32:
            raise RuntimeError(
                "FATAL: Insecure or default JWT_SECRET configured in production mode. "
                "Set environment variable DREX_JWT_SECRET to a cryptographically random string (min 32 chars)."
            )


# ─── Permissions Matrix ───────────────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[UserRole, Set[str]] = {
    UserRole.ADMIN: {
        "cases:read", "cases:write", "cases:delete",
        "evidence:read", "evidence:write", "evidence:hash",
        "timeline:read",
        "devices:read", "devices:qualify",
        "recovery:scan", "recovery:read", "recovery:reconstruct", "recovery:extract",
        "jobs:read", "jobs:cancel",
        "sanitization:plan", "sanitization:execute",
        "residue:analyze",
        "verification:verify", "verification:entropy",
        "audit:read", "audit:verify",
        "vault:read", "vault:export",
        "certificates:read", "certificates:issue", "certificates:verify",
        "reports:generate",
        "workstations:read", "diagnostics:read",
        "validation:run", "performance:run",
        "demo:run",
    },
    UserRole.FORENSIC_ANALYST: {
        "cases:read", "cases:write",
        "evidence:read", "evidence:write", "evidence:hash",
        "timeline:read",
        "devices:read", "devices:qualify",
        "recovery:scan", "recovery:read", "recovery:reconstruct", "recovery:extract",
        "jobs:read", "jobs:cancel",
        "sanitization:plan",
        "residue:analyze",
        "verification:verify", "verification:entropy",
        "audit:read",
        "vault:read", "vault:export",
        "certificates:read", "certificates:issue", "certificates:verify",
        "reports:generate",
        "diagnostics:read",
        "validation:run",
        "demo:run",
    },
    UserRole.INVESTIGATOR: {
        "cases:read", "cases:write",
        "evidence:read",
        "timeline:read",
        "devices:read",
        "recovery:read",
        "jobs:read",
        "verification:verify",
        "audit:read",
        "vault:read",
        "certificates:read", "certificates:verify",
        "reports:generate",
        "demo:run",
    },
    UserRole.OPERATOR: {
        "cases:read",
        "evidence:read",
        "devices:read", "devices:qualify",
        "jobs:read", "jobs:cancel",
        "sanitization:plan", "sanitization:execute",
        "residue:analyze",
        "verification:verify", "verification:entropy",
        "certificates:read",
        "reports:generate",
        "demo:run",
    },
    UserRole.AUDITOR: {
        "cases:read",
        "evidence:read",
        "timeline:read",
        "jobs:read",
        "verification:verify",
        "audit:read", "audit:verify",
        "vault:read",
        "certificates:read", "certificates:verify",
        "reports:generate",
        "demo:run",
    },
    UserRole.JUDGE_DEMO: {
        "cases:read", "cases:write",
        "evidence:read", "evidence:write",
        "timeline:read",
        "devices:read", "devices:qualify",
        "recovery:scan", "recovery:extract",
        "jobs:read", "jobs:cancel",
        "sanitization:plan", "sanitization:execute",  # Simulation only
        "residue:analyze",
        "verification:verify", "verification:entropy",
        "audit:read", "audit:verify",
        "vault:read", "vault:export",
        "certificates:read", "certificates:issue", "certificates:verify",
        "reports:generate",
        "diagnostics:read",
        "validation:run", "performance:run",
        "demo:run",
    },
}


# ─── Built-in Personas ────────────────────────────────────────────────────────

PERSONA_PROFILES: Dict[UserRole, Dict[str, Any]] = {
    UserRole.ADMIN: {
        "username": "admin",
        "display_name": "Chief Forensic Director (Admin)",
        "organization": "National Forensic Laboratory",
    },
    UserRole.FORENSIC_ANALYST: {
        "username": "analyst",
        "display_name": "Senior Digital Forensic Analyst",
        "organization": "DFIR Investigation Unit",
    },
    UserRole.INVESTIGATOR: {
        "username": "investigator",
        "display_name": "Lead Case Investigator",
        "organization": "Cyber Crime Division",
    },
    UserRole.OPERATOR: {
        "username": "operator",
        "display_name": "Hardware Sanitization Technician",
        "organization": "Secure Storage Clearing Center",
    },
    UserRole.AUDITOR: {
        "username": "auditor",
        "display_name": "Independent Forensic Compliance Auditor",
        "organization": "Assurance & Oversight Board",
    },
    UserRole.JUDGE_DEMO: {
        "username": "judge_demo",
        "display_name": "SIH 2026 Evaluation Committee Judge",
        "organization": "NTRO Evaluation Bench",
    },
}


# ─── Token Generation & Validation ────────────────────────────────────────────

def create_access_token(role: UserRole, username: Optional[str] = None) -> str:
    """Issue a signed JWT access token for the given user role."""
    profile = PERSONA_PROFILES.get(role, PERSONA_PROFILES[UserRole.JUDGE_DEMO])
    now = datetime.datetime.now(datetime.timezone.utc)
    expire = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": username or profile["username"],
        "display_name": profile["display_name"],
        "role": role.value,
        "permissions": sorted(list(ROLE_PERMISSIONS.get(role, set()))),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a signed JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.PyJWTError, ValueError):
        return None


def verify_permission(user_payload: Dict[str, Any], required_permission: str) -> bool:
    """Check if the authenticated user has the specified permission."""
    role_str = user_payload.get("role", "")
    try:
        role = UserRole(role_str)
    except ValueError:
        return False

    perms = ROLE_PERMISSIONS.get(role, set())
    return required_permission in perms
