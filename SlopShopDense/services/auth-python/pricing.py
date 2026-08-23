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
