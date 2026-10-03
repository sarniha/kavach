"""
sentinelai/threat_intel/normalization.py
────────────────────────────────────────
Mandatory IOC normalization and validation functions (Section 8.2 B).
Handles:
- IP validation via ipaddress (IPv4 and IPv6)
- Defanging reversal (hxxp -> http, [.] -> ., [:] -> :)
- Domain canonicalization (lowercase, strip trailing dots, clean protocols/paths)
- URL canonicalization
- Cryptographic hash type detection by hex length (MD5: 32, SHA1: 40, SHA256: 64)
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from sentinelai.threat_intel.schemas import IOCType


def refang(value: str) -> str:
    """
    Remove defensive defanging obfuscations:
    - hxxp://, hxxps:// -> http://, https://
    - [.] or (.), [dot] -> .
    - [:] or (:) -> :
    - [@] -> @
    """
    val = value.strip()
    # Protocols
    val = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0) else "http://", val, flags=re.IGNORECASE)
    val = re.sub(r"^fxps?://", lambda m: "ftps://" if "s" in m.group(0) else "ftp://", val, flags=re.IGNORECASE)
    # Dots and colons
    val = val.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    val = re.sub(r"\[dot\]", ".", val, flags=re.IGNORECASE)
    val = val.replace("[:]", ":").replace("(:)", ":")
    val = val.replace("[@]", "@")
    return val.strip()


def normalize_ip(value: str) -> str:
    """Validate and normalize IPv4/IPv6 address. Raises ValueError on invalid IP."""
    clean = refang(value)
    # Validate via ipaddress module
    ip_obj = ipaddress.ip_address(clean)
    return str(ip_obj)


def normalize_domain(value: str) -> str:
    """Normalize a domain: lowercase, refang, remove protocol/path if included, strip trailing dot."""
    clean = refang(value)
    if "://" in clean:
        clean = urlparse(clean).netloc or clean
    clean = clean.split("/")[0].split(":")[0]  # Strip paths and port numbers
    clean = clean.lower().rstrip(".")
    if not clean or "." not in clean:
        raise ValueError(f"Invalid domain name: '{value}'")
    return clean


def normalize_url(value: str) -> str:
    """Canonicalize URL: refang, ensure valid scheme, strip fragments."""
    clean = refang(value)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean):
        clean = "http://" + clean
    parsed = urlparse(clean)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def detect_hash_type(value: str) -> IOCType:
    """Detect hash type by hexadecimal character count. Raises ValueError if unrecognized."""
    clean = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", clean):
        raise ValueError(f"Value '{value}' contains non-hexadecimal characters.")

    length = len(clean)
    if length == 32:
        return IOCType.HASH_MD5
    elif length == 40:
        return IOCType.HASH_SHA1
    elif length == 64:
        return IOCType.HASH_SHA256
    raise ValueError(f"Unrecognized hash length {length} (expected 32, 40, or 64 hex chars).")


def normalize_ioc(kind: IOCType | str, value: str) -> tuple[IOCType, str]:
    """
    Validate and normalize any IOC value according to its declared kind.
    Returns (normalized_kind, normalized_value).
    """
    k_str = kind.value if isinstance(kind, IOCType) else str(kind).lower().strip()

    if k_str == "ip":
        return IOCType.IP, normalize_ip(value)
    elif k_str == "domain":
        return IOCType.DOMAIN, normalize_domain(value)
    elif k_str == "url":
        return IOCType.URL, normalize_url(value)
    elif k_str in ("hash", "hash_md5", "hash_sha1", "hash_sha256"):
        detected = detect_hash_type(value)
        return detected, value.strip().lower()
    else:
        # Default pass-through
        return IOCType.DOMAIN, value.strip()
