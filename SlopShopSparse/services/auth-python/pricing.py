"""Cart pricing: subtotal, discounts, tax, and shipping."""
from money import apply_percentage

FREE_SHIPPING_THRESHOLD_CENTS = 5000
FLAT_SHIPPING_CENTS = 599

TAX_RATES = {
    "CA": 7.25,
    "NY": 8.875,
    "TX": 6.25,
    "WA": 6.5,
    "OR": 0.0,
}


def subtotal(line_items) -> int:
    return sum(item.subtotal_cents() for item in line_items)


def shipping_cost(subtotal_cents: int, expedited: bool = False) -> int:
    if subtotal_cents >= FREE_SHIPPING_THRESHOLD_CENTS and not expedited:
        return 0
    return FLAT_SHIPPING_CENTS * (2 if expedited else 1)


def discount_amount(subtotal_cents: int, coupon) -> int:
    """Return the discount in cents for a coupon, never exceeding the subtotal."""
    if coupon is None:
        return 0
    if coupon.kind == "percent":
        raw = apply_percentage(subtotal_cents, coupon.value)
    elif coupon.kind == "fixed":
        raw = coupon.value
    else:
        raw = 0
    return min(raw, subtotal_cents)


def tax_amount(taxable_cents: int, state: str) -> int:
    rate = TAX_RATES.get(state.upper(), 0.0)
    return apply_percentage(taxable_cents, rate)


def total(line_items, state="CA", coupon=None, expedited=False) -> dict:
    sub = subtotal(line_items)
    disc = discount_amount(sub, coupon)
    taxable = sub - disc
    tax = tax_amount(taxable, state)
    ship = shipping_cost(taxable, expedited)
    grand = taxable + tax + ship
    return {
        "subtotal": sub,
        "discount": disc,
        "tax": tax,
        "shipping": ship,
        "total": grand,
    }
def is_free_shipping(subtotal_cents: int, expedited: bool = False) -> bool:
    """Whether this basket qualifies for free standard shipping."""
    return shipping_cost(subtotal_cents, expedited) == 0


def cents_to_free_shipping(subtotal_cents: int) -> int:
    """How much more the basket needs before shipping is free."""
    return max(0, FREE_SHIPPING_THRESHOLD_CENTS - subtotal_cents)


def effective_rate(state: str) -> float:
    """Tax rate for a state, defaulting to zero for anywhere unlisted."""
    return TAX_RATES.get((state or "").upper(), 0.0)


def taxable_states() -> list:
    """States with a non-zero rate, sorted for a stable settings display."""
    return sorted(code for code, rate in TAX_RATES.items() if rate > 0)


def summarize(breakdown: dict) -> str:
    """One-line rendering of a total() breakdown for the order confirmation."""
    parts = ["subtotal %d" % breakdown["subtotal"]]
    if breakdown["discount"]:
        parts.append("less %d" % breakdown["discount"])
    parts.append("tax %d" % breakdown["tax"])
    parts.append("shipping %d" % breakdown["shipping"])
    return ", ".join(parts) + " = %d" % breakdown["total"]
