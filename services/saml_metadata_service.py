"""SAML metadata fetch, validation, parsing, and diff helpers."""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

import requests

from config import (
    SAML_METADATA_SYNC_MAX_BYTES,
    SAML_METADATA_SYNC_TIMEOUT_SEC,
    SAML_METADATA_SYNC_USER_AGENT,
)
from models.app import (
    APP_TYPE_SAML,
    SAML_DEFAULT_ACS_BINDING,
    SAML_DEFAULT_NAMEID_FORMAT,
    get_app_by_id,
    update_app,
)

NS_MD = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
NS_DS = {"ds": "http://www.w3.org/2000/09/xmldsig#"}

ALLOWED_MAPPING_SOURCE_FIELDS = {
    "email",
    "legal_name",
    "preferred_name",
    "pronouns",
    "dob",
    "discord_id",
    "events",
    "display_name",
}

DEFAULT_ATTRIBUTE_MAPPING = [
    {
        "source_field": "email",
        "saml_name": "email",
        "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "required": True,
        "multi_valued": False,
        "transform": "identity",
    },
    {
        "source_field": "display_name",
        "saml_name": "displayName",
        "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "required": False,
        "multi_valued": False,
        "transform": "identity",
    },
]

MATERIAL_DIFF_FIELDS = {
    "saml_entity_id",
    "saml_acs_url",
    "saml_acs_binding",
    "saml_slo_url",
    "saml_sp_signing_certs_json",
    "saml_require_signed_authn_request",
}


class SamlMetadataError(RuntimeError):
    """Metadata fetch/parse/validation error."""


def _is_public_ip(ip_value: str) -> bool:
    addr = ipaddress.ip_address(ip_value)
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    return True


def _resolve_public_ips(hostname: str) -> List[str]:
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SamlMetadataError(f"Unable to resolve metadata host: {exc}") from exc

    ips: List[str] = []
    for info in addr_infos:
        ip_value = info[4][0]
        if not _is_public_ip(ip_value):
            raise SamlMetadataError("Metadata host resolves to non-public IP; request blocked")
        ips.append(ip_value)

    if not ips:
        raise SamlMetadataError("No valid public IPs resolved for metadata host")
    return sorted(set(ips))


def _validate_https_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise SamlMetadataError("Metadata URL must use https")
    if not parsed.hostname:
        raise SamlMetadataError("Metadata URL host is missing")


def _requests_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": SAML_METADATA_SYNC_USER_AGENT})
    return session


def fetch_metadata_xml(
    metadata_url: str,
    *,
    timeout_sec: int = SAML_METADATA_SYNC_TIMEOUT_SEC,
    max_bytes: int = SAML_METADATA_SYNC_MAX_BYTES,
    max_redirects: int = 3,
) -> Tuple[str, Optional[str], str]:
    """
    Fetch metadata XML with SSRF protections.

    Returns tuple(xml_text, etag, final_url).
    """
    _validate_https_url(metadata_url)
    parsed_initial = urlparse(metadata_url)
    pinned_host = parsed_initial.hostname or ""

    session = _requests_session()
    current_url = metadata_url
    visited: set[str] = set()

    for _ in range(max_redirects + 1):
        if current_url in visited:
            raise SamlMetadataError("Redirect loop detected while fetching metadata")
        visited.add(current_url)

        parsed = urlparse(current_url)
        _validate_https_url(current_url)
        if (parsed.hostname or "") != pinned_host:
            raise SamlMetadataError("Metadata redirects must stay on the same host")
        _resolve_public_ips(parsed.hostname or "")

        try:
            response = session.get(
                current_url,
                timeout=timeout_sec,
                stream=True,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise SamlMetadataError(f"Metadata fetch failed: {exc}") from exc

        if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("Location")
            if not location:
                raise SamlMetadataError("Redirect response missing Location header")
            current_url = urljoin(current_url, location)
            continue

        if response.status_code != 200:
            raise SamlMetadataError(
                f"Metadata fetch failed with status={response.status_code}"
            )

        received = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            received.extend(chunk)
            if len(received) > max_bytes:
                raise SamlMetadataError("Metadata response exceeded max byte limit")

        etag = response.headers.get("ETag")
        return received.decode("utf-8", errors="replace"), etag, current_url

    raise SamlMetadataError("Too many redirects while fetching metadata")


def _text_or_empty(value: Optional[str]) -> str:
    return (value or "").strip()


def parse_metadata_xml(xml_text: str) -> Dict[str, Any]:
    """Parse SAML SP metadata XML into normalized app fields."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SamlMetadataError(f"Invalid metadata XML: {exc}") from exc

    entity_id = _text_or_empty(root.attrib.get("entityID"))
    if not entity_id:
        raise SamlMetadataError("Metadata missing EntityDescriptor entityID")

    sp_descriptor = root.find("md:SPSSODescriptor", NS_MD)
    if sp_descriptor is None:
        raise SamlMetadataError("Metadata missing SPSSODescriptor")

    acs_nodes = sp_descriptor.findall("md:AssertionConsumerService", NS_MD)
    if not acs_nodes:
        raise SamlMetadataError("Metadata missing AssertionConsumerService")

    acs_selected = None
    for node in acs_nodes:
        binding = _text_or_empty(node.attrib.get("Binding"))
        if binding == SAML_DEFAULT_ACS_BINDING:
            acs_selected = node
            break
    if acs_selected is None:
        acs_selected = acs_nodes[0]

    acs_url = _text_or_empty(acs_selected.attrib.get("Location"))
    acs_binding = _text_or_empty(acs_selected.attrib.get("Binding")) or SAML_DEFAULT_ACS_BINDING
    if not acs_url:
        raise SamlMetadataError("Metadata ACS entry missing Location")

    slo_node = sp_descriptor.find("md:SingleLogoutService", NS_MD)
    slo_url = _text_or_empty(slo_node.attrib.get("Location")) if slo_node is not None else ""

    signing_certs: List[str] = []
    for key_descriptor in sp_descriptor.findall("md:KeyDescriptor", NS_MD):
        use_attr = _text_or_empty(key_descriptor.attrib.get("use"))
        if use_attr and use_attr != "signing":
            continue
        cert_nodes = key_descriptor.findall(".//ds:X509Certificate", NS_DS)
        for cert_node in cert_nodes:
            cert_text = "".join((cert_node.text or "").split())
            if cert_text:
                signing_certs.append(cert_text)

    require_signed_authn_request = (
        _text_or_empty(sp_descriptor.attrib.get("AuthnRequestsSigned")).lower() == "true"
    )

    return {
        "saml_entity_id": entity_id,
        "saml_acs_url": acs_url,
        "saml_acs_binding": acs_binding,
        "saml_slo_url": slo_url,
        "saml_sp_signing_certs_json": json.dumps(sorted(set(signing_certs))),
        "saml_require_signed_authn_request": require_signed_authn_request,
        "saml_nameid_format": SAML_DEFAULT_NAMEID_FORMAT,
        "saml_enabled": True,
    }


def fetch_and_parse_metadata(metadata_url: str) -> Dict[str, Any]:
    """Fetch metadata URL and return normalized values plus fetch metadata."""
    xml_text, etag, final_url = fetch_metadata_xml(metadata_url)
    parsed = parse_metadata_xml(xml_text)
    parsed["saml_metadata_url"] = final_url
    parsed["saml_metadata_etag"] = etag or ""
    parsed["saml_metadata_last_fetched_at"] = datetime.now(timezone.utc).isoformat()
    return parsed


def validate_attribute_mapping(mapping: Any) -> Tuple[bool, Optional[str]]:
    """Validate per-app SAML attribute mapping schema."""
    if isinstance(mapping, str):
        try:
            mapping = json.loads(mapping)
        except json.JSONDecodeError as exc:
            return False, f"Invalid JSON for saml_attribute_mapping: {exc}"

    if not isinstance(mapping, list):
        return False, "saml_attribute_mapping must be a JSON array"

    seen_names: set[str] = set()
    for idx, item in enumerate(mapping):
        if not isinstance(item, dict):
            return False, f"saml_attribute_mapping[{idx}] must be an object"

        source_field = item.get("source_field")
        saml_name = item.get("saml_name")
        if source_field not in ALLOWED_MAPPING_SOURCE_FIELDS:
            return False, f"Unsupported source_field '{source_field}' in mapping entry {idx}"
        if not saml_name or not isinstance(saml_name, str):
            return False, f"Mapping entry {idx} is missing valid saml_name"
        if saml_name in seen_names:
            return False, f"Duplicate saml_name '{saml_name}' in mapping"
        seen_names.add(saml_name)

        for bool_field in ("required", "multi_valued"):
            if bool_field in item and not isinstance(item[bool_field], bool):
                return False, f"{bool_field} must be boolean in mapping entry {idx}"

        transform = item.get("transform", "identity")
        if transform not in {"identity", "lowercase", "uppercase", "first_word", "last_word", "rest_words"}:
            return False, f"Unsupported transform '{transform}' in mapping entry {idx}"

    return True, None


def get_default_attribute_mapping_json() -> str:
    return json.dumps(DEFAULT_ATTRIBUTE_MAPPING)


def compute_material_diff(current_app: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Compute material metadata differences used for approval flow."""
    before: Dict[str, Any] = {}
    after: Dict[str, Any] = {}
    for field in MATERIAL_DIFF_FIELDS:
        current_value = current_app.get(field, "")
        next_value = incoming.get(field, "")
        if current_value != next_value:
            before[field] = current_value
            after[field] = next_value
    return {"before": before, "after": after, "has_material_change": bool(before)}


def stage_app_metadata_update(app_id: str, incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Stage metadata updates for admin approval."""
    app = get_app_by_id(app_id)
    if not app:
        return {"success": False, "error": "App not found"}
    if app.get("app_type") != APP_TYPE_SAML:
        return {"success": False, "error": "Metadata sync is only supported for SAML apps"}

    diff = compute_material_diff(app, incoming)
    pending_payload = {
        "incoming": incoming,
        "diff": diff,
        "staged_at": datetime.now(timezone.utc).isoformat(),
    }

    result = update_app(
        app_id,
        saml_metadata_pending_diff_json=json.dumps(pending_payload),
        saml_metadata_sync_error="",
        saml_metadata_last_fetched_at=incoming.get("saml_metadata_last_fetched_at"),
        saml_metadata_etag=incoming.get("saml_metadata_etag"),
    )
    if not result.get("success"):
        return result
    return {"success": True, "pending": pending_payload}


def apply_staged_metadata_update(app_id: str) -> Dict[str, Any]:
    """Apply staged metadata diff to active SAML app configuration."""
    app = get_app_by_id(app_id)
    if not app:
        return {"success": False, "error": "App not found"}
    if app.get("app_type") != APP_TYPE_SAML:
        return {"success": False, "error": "Only SAML apps support metadata apply"}

    pending_json = app.get("saml_metadata_pending_diff_json") or "{}"
    pending = _parse_json_or_empty_obj(pending_json)
    incoming = pending.get("incoming")
    if not isinstance(incoming, dict):
        return {"success": False, "error": "No staged metadata updates to apply"}

    update_result = update_app(
        app_id,
        saml_metadata_url=incoming.get("saml_metadata_url"),
        saml_entity_id=incoming.get("saml_entity_id"),
        saml_acs_url=incoming.get("saml_acs_url"),
        saml_acs_binding=incoming.get("saml_acs_binding"),
        saml_slo_url=incoming.get("saml_slo_url"),
        saml_sp_signing_certs_json=incoming.get("saml_sp_signing_certs_json"),
        saml_require_signed_authn_request=incoming.get("saml_require_signed_authn_request"),
        saml_nameid_format=incoming.get("saml_nameid_format", SAML_DEFAULT_NAMEID_FORMAT),
        saml_enabled=True,
        saml_metadata_etag=incoming.get("saml_metadata_etag", ""),
        saml_metadata_last_fetched_at=incoming.get("saml_metadata_last_fetched_at", ""),
        saml_metadata_last_applied_at=datetime.now(timezone.utc).isoformat(),
        saml_metadata_pending_diff_json=json.dumps({}),
        saml_metadata_sync_error="",
    )
    return update_result


def reject_staged_metadata_update(app_id: str) -> Dict[str, Any]:
    """Reject staged metadata diff and clear pending state."""
    app = get_app_by_id(app_id)
    if not app:
        return {"success": False, "error": "App not found"}
    if app.get("app_type") != APP_TYPE_SAML:
        return {"success": False, "error": "Only SAML apps support metadata approval"}

    return update_app(
        app_id,
        saml_metadata_pending_diff_json=json.dumps({}),
        saml_metadata_sync_error="",
    )


def _parse_json_or_empty_obj(value: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
        if isinstance(parsed, dict):
            return parsed
    except (TypeError, ValueError):
        pass
    return {}


def check_metadata_url_health(metadata_url: str) -> Dict[str, Any]:
    """Validate and fetch metadata URL, returning parsed result/error details."""
    try:
        incoming = fetch_and_parse_metadata(metadata_url)
        return {"success": True, "incoming": incoming}
    except SamlMetadataError as exc:
        return {"success": False, "error": str(exc)}
