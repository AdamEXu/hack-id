"""SAML key/certificate loading helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from config import (
    SAML_IDP_CERT_ACTIVE_PATH,
    SAML_IDP_CERT_NEXT_PATH,
    SAML_IDP_KEY_ACTIVE_PATH,
    SAML_IDP_KEY_NEXT_PATH,
)


def _read_text(path_value: str) -> Optional[str]:
    if not path_value:
        return None
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip()


def _pem_body(pem_text: str) -> str:
    lines = []
    for line in pem_text.splitlines():
        line = line.strip()
        if not line or line.startswith("-----BEGIN") or line.startswith("-----END"):
            continue
        lines.append(line)
    return "".join(lines)


def get_active_key_path() -> str:
    return SAML_IDP_KEY_ACTIVE_PATH


def get_active_cert_path() -> str:
    return SAML_IDP_CERT_ACTIVE_PATH


def get_next_key_path() -> Optional[str]:
    return SAML_IDP_KEY_NEXT_PATH or None


def get_next_cert_path() -> Optional[str]:
    return SAML_IDP_CERT_NEXT_PATH or None


def get_idp_certificates_for_metadata() -> List[str]:
    """Return active + next certs as base64 bodies for metadata publication."""
    certs: List[str] = []
    active = _read_text(SAML_IDP_CERT_ACTIVE_PATH)
    if active:
        certs.append(_pem_body(active))

    nxt = _read_text(SAML_IDP_CERT_NEXT_PATH)
    if nxt:
        body = _pem_body(nxt)
        if body and body not in certs:
            certs.append(body)
    return certs


def key_material_health() -> Dict[str, bool]:
    """Simple key/cert readability status used by health checks/admin."""
    return {
        "active_key": bool(_read_text(SAML_IDP_KEY_ACTIVE_PATH)),
        "active_cert": bool(_read_text(SAML_IDP_CERT_ACTIVE_PATH)),
        "next_key": bool(_read_text(SAML_IDP_KEY_NEXT_PATH)) if SAML_IDP_KEY_NEXT_PATH else False,
        "next_cert": bool(_read_text(SAML_IDP_CERT_NEXT_PATH)) if SAML_IDP_CERT_NEXT_PATH else False,
    }
