"""CWE hierarchy and normalization utilities."""

from __future__ import annotations

import re

# Partial CWE hierarchy: child → parent mapping for common vulnerability classes.
# Used for partial-credit matching (agent reports parent when ground truth is child).
CWE_PARENT_MAP: dict[str, str] = {
    # Injection family (CWE-74)
    "CWE-77": "CWE-74",   # Command Injection
    "CWE-78": "CWE-74",   # OS Command Injection
    "CWE-79": "CWE-74",   # XSS
    "CWE-89": "CWE-74",   # SQL Injection
    "CWE-90": "CWE-74",   # LDAP Injection
    "CWE-91": "CWE-74",   # XML Injection
    "CWE-94": "CWE-74",   # Code Injection
    "CWE-917": "CWE-74",  # Expression Language Injection
    # Buffer errors (CWE-119)
    "CWE-120": "CWE-119",  # Buffer Copy without Checking Size
    "CWE-121": "CWE-119",  # Stack-based Buffer Overflow
    "CWE-122": "CWE-119",  # Heap-based Buffer Overflow
    "CWE-124": "CWE-119",  # Buffer Underwrite
    "CWE-125": "CWE-119",  # Out-of-bounds Read
    "CWE-126": "CWE-119",  # Buffer Over-read
    "CWE-127": "CWE-119",  # Buffer Under-read
    "CWE-787": "CWE-119",  # Out-of-bounds Write
    "CWE-788": "CWE-119",  # Access of Memory Location After End of Buffer
    # Input validation (CWE-20)
    "CWE-22": "CWE-20",   # Path Traversal
    "CWE-23": "CWE-22",   # Relative Path Traversal
    "CWE-36": "CWE-22",   # Absolute Path Traversal
    "CWE-129": "CWE-20",  # Improper Validation of Array Index
    "CWE-1284": "CWE-20", # Improper Validation of Specified Quantity in Input
    # Numeric errors (CWE-189)
    "CWE-190": "CWE-189",  # Integer Overflow
    "CWE-191": "CWE-189",  # Integer Underflow
    "CWE-193": "CWE-189",  # Off-by-one Error
    "CWE-195": "CWE-189",  # Signed to Unsigned Conversion Error
    "CWE-197": "CWE-189",  # Numeric Truncation Error
    "CWE-369": "CWE-189",  # Divide By Zero
    # Auth (CWE-287)
    "CWE-288": "CWE-287",  # Auth Bypass Using Alternate Path
    "CWE-290": "CWE-287",  # Auth Bypass by Spoofing
    "CWE-306": "CWE-287",  # Missing Auth for Critical Function
    # Access control (CWE-264)
    "CWE-269": "CWE-264",  # Improper Privilege Management
    "CWE-284": "CWE-264",  # Improper Access Control
    "CWE-732": "CWE-264",  # Incorrect Permission Assignment
    "CWE-862": "CWE-264",  # Missing Authorization
    "CWE-863": "CWE-264",  # Incorrect Authorization
    # Crypto (CWE-310)
    "CWE-326": "CWE-310",  # Inadequate Encryption Strength
    "CWE-327": "CWE-310",  # Use of Broken Crypto Algorithm
    "CWE-328": "CWE-310",  # Reversible One-Way Hash
    # Information exposure (CWE-200)
    "CWE-201": "CWE-200",  # Insertion of Sensitive Information Into Sent Data
    "CWE-209": "CWE-200",  # Generation of Error Message Containing Sensitive Info
    "CWE-312": "CWE-200",  # Cleartext Storage of Sensitive Information
    "CWE-319": "CWE-200",  # Cleartext Transmission of Sensitive Information
    "CWE-532": "CWE-200",  # Insertion of Sensitive Information into Log File
    # Resource management (CWE-399)
    "CWE-400": "CWE-399",  # Uncontrolled Resource Consumption
    "CWE-401": "CWE-399",  # Memory Leak
    "CWE-404": "CWE-399",  # Improper Resource Shutdown or Release
    "CWE-415": "CWE-399",  # Double Free
    "CWE-416": "CWE-399",  # Use After Free
    "CWE-476": "CWE-399",  # NULL Pointer Dereference
    "CWE-772": "CWE-399",  # Missing Release of Resource after Effective Lifetime
    "CWE-835": "CWE-399",  # Loop with Unreachable Exit Condition (Infinite Loop)
    # Concurrency (CWE-362)
    "CWE-366": "CWE-362",  # Race Condition within a Thread
    "CWE-367": "CWE-362",  # TOCTOU Race Condition
    # Security features (CWE-254)
    "CWE-311": "CWE-254",  # Missing Encryption of Sensitive Data
    "CWE-345": "CWE-254",  # Insufficient Verification of Data Authenticity
    # Error handling (CWE-388 / CWE-755)
    "CWE-755": "CWE-388",  # Improper Handling of Exceptional Conditions
    "CWE-754": "CWE-388",  # Improper Check for Unusual or Exceptional Conditions
    "CWE-252": "CWE-388",  # Unchecked Return Value
    # Deprecated/broad categories (CWE-17 "Code Quality", CWE-19 "Data Processing")
    # These are top-level pillars — many CWEs map here loosely
    "CWE-170": "CWE-17",   # Improper Null Termination
    "CWE-457": "CWE-17",   # Use of Uninitialized Variable
    "CWE-908": "CWE-17",   # Use of Uninitialized Resource
    "CWE-134": "CWE-20",   # Use of Externally-Controlled Format String
    "CWE-617": "CWE-20",   # Reachable Assertion
    # File/link handling
    "CWE-59": "CWE-20",    # Improper Link Resolution Before File Access
    "CWE-73": "CWE-20",    # External Control of File Name or Path
    # Deserialization
    "CWE-502": "CWE-20",   # Deserialization of Untrusted Data
    # SSRF
    "CWE-918": "CWE-20",   # Server-Side Request Forgery
}

_CWE_PATTERN = re.compile(r"(?:CWE[-_]?)?(\d+)", re.IGNORECASE)


def normalize_cwe(raw: str) -> str | None:
    """Normalize CWE identifiers to 'CWE-NNN' form.

    Accepts: 'CWE-79', 'CWE79', 'cwe_79', '79', 'CWE-0079'
    Returns: 'CWE-79' or None if unparseable.
    """
    if not raw:
        return None
    m = _CWE_PATTERN.search(raw.strip())
    if not m:
        return None
    num = int(m.group(1))
    if num == 0:
        return None
    return f"CWE-{num}"


def cwe_matches(reported: str, expected: str, *, allow_parent: bool = False) -> bool:
    """Check if reported CWE matches expected, optionally allowing parent matches."""
    r = normalize_cwe(reported)
    e = normalize_cwe(expected)
    if r is None or e is None:
        return False
    if r == e:
        return True
    if allow_parent:
        # Check if expected is a child of reported (agent reported parent)
        parent = CWE_PARENT_MAP.get(e)
        if parent == r:
            return True
        # Check if reported is a child of expected (agent reported child)
        parent = CWE_PARENT_MAP.get(r)
        if parent == e:
            return True
    return False


def get_cwe_parent(cwe_id: str) -> str | None:
    """Get the parent CWE for a given CWE ID, or None if not in hierarchy."""
    normalized = normalize_cwe(cwe_id)
    if normalized is None:
        return None
    return CWE_PARENT_MAP.get(normalized)


def get_cwe_family(cwe_id: str) -> str:
    """Get the top-level family CWE by walking up the hierarchy."""
    normalized = normalize_cwe(cwe_id)
    if normalized is None:
        return cwe_id
    seen: set[str] = set()
    current = normalized
    while current in CWE_PARENT_MAP and current not in seen:
        seen.add(current)
        current = CWE_PARENT_MAP[current]
    return current
