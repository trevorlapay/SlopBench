"""Input validation helpers. These are deliberately correct and safe."""
import re

# Linear-time, anchored patterns (no catastrophic backtracking).
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SKU_RE = re.compile(r"^[A-Z]{2,4}-[0-9]{4,8}$")
_POSTAL_US_RE = re.compile(r"^[0-9]{5}(?:-[0-9]{4})?$")


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value or ""))


def is_slug(value: str) -> bool:
    return bool(_SLUG_RE.match(value or ""))


def is_sku(value: str) -> bool:
    return bool(_SKU_RE.match(value or ""))


def is_us_postal(value: str) -> bool:
    return bool(_POSTAL_US_RE.match(value or ""))


def clamp_quantity(value, lo: int = 1, hi: int = 99) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return lo
    return max(lo, min(hi, n))


def normalize_username(raw: str) -> str:
    """Allow only a conservative identifier charset; reject everything else."""
    cleaned = (raw or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{3,32}", cleaned):
        raise ValueError("invalid username")
    return cleaned


def require_fields(payload: dict, fields) -> None:
    missing = [f for f in fields if f not in payload or payload[f] in (None, "")]
    if missing:
        raise ValueError("missing fields: %s" % ", ".join(missing))
_PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")
_TRACKING_RE = re.compile(r"^[A-Z0-9]{8,30}$")
_COUPON_RE = re.compile(r"^[A-Z0-9]{4,16}$")


def is_phone(value: str) -> bool:
    return bool(_PHONE_RE.match((value or "").replace(" ", "")))


def is_tracking_number(value: str) -> bool:
    return bool(_TRACKING_RE.match((value or "").strip().upper()))


def is_coupon_code(value: str) -> bool:
    return bool(_COUPON_RE.match((value or "").strip().upper()))


def clamp_page_size(value, lo: int = 1, hi: int = 100) -> int:
    """Bound a requested page size to something the service will serve."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return lo
    return max(lo, min(hi, n))


def normalize_email(raw: str) -> str:
    """Lowercase and trim an address after confirming it parses."""
    cleaned = (raw or "").strip().lower()
    if not is_email(cleaned):
        raise ValueError("invalid email")
    return cleaned


def reject_control_characters(value: str) -> str:
    """Refuse values carrying control characters, which no field needs."""
    if any(ord(ch) < 32 for ch in (value or "")):
        raise ValueError("control characters are not permitted")
    return value
